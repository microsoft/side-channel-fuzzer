"""
File: Unicorn-based backend to the contract model.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Set, TYPE_CHECKING, Final, Dict, Type

import numpy as np

import unicorn as uc
import unicorn.x86_const as x86ucc  # type: ignore # no type hints for unicorn.x86_const
import unicorn.arm64_const as armucc  # type: ignore # no type hints for unicorn.arm_const
from unicorn import Uc, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, \
    UC_HOOK_MEM_UNMAPPED, UcError, UC_MEM_WRITE, UC_PROT_NONE, UC_PROT_READ

from ..model import Model
from ..sandbox import SandboxLayout, DataArea
from ..config import CONF
from ..logs import ModelLogger, BLUE, COL_RESET, error
from ..traces import CTraceEntry

from .taint_tracker import UnicornTaintTracker
from .coverage import InstructionCoverage
from .execution_context import ModelExecutionState

if TYPE_CHECKING:
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_data import InputTaint
    from ..tc_components.test_case_code import TestCaseProgram
    from ..traces import CTrace
    from .tracer import UnicornTracer
    from .speculator_abc import UnicornSpeculator
    from .interpreter import ExtraInterpreter
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..sandbox import BaseAddrTuple


_UC_FAULT_MAPPING: Final[Dict[str, List[int]]] = {  # map fault names to Unicorn fault IDs
    "DE": [21],
    "DB": [10],
    "BP": [21],
    "BR": [13],
    "UD": [10],
    "PF": [12, 13],
    "GP": [6, 7],
    "assist": [12, 13],
}


# ==================================================================================================
# Private classes and functions
# ==================================================================================================
class _Dispatcher:
    """
    Class responsible for invoking callback functions in service classes upon events in Unicorn
    """
    coverage: InstructionCoverage
    _taint_tracker: UnicornTaintTracker
    _tracer: UnicornTracer
    _speculator: UnicornSpeculator
    _interpreter: ExtraInterpreter

    def __init__(self, taint_tracker: UnicornTaintTracker, speculator: UnicornSpeculator,
                 tracer: UnicornTracer, interpreter: ExtraInterpreter,
                 coverage: InstructionCoverage) -> None:
        self._taint_tracker = taint_tracker
        self._tracer = tracer
        self._speculator = speculator
        self._interpreter = interpreter
        self.coverage = coverage

    def test_case_load_dispatch(self, test_case: TestCaseProgram) -> None:
        """ Call callbacks in service classes that need to be called when a test case is loaded """
        self._interpreter.load_test_case(test_case)
        self._tracer.load_test_case(test_case)
        self.coverage.finish_test_case()
        self.coverage.start_test_case()

    def execution_start_dispatch(self, input_: InputData) -> None:
        """ Call callbacks in service classes that need to be called before model execution """
        self._tracer.reset(input_)
        self._speculator.reset()
        self._taint_tracker.reset()
        self._interpreter.load_input(input_)

    def instruction_dispatch(self, address: int, size: int, _: UnicornModel,
                             state: ModelExecutionState) -> None:
        """ Call instruction-related callbacks in service classes """

        if state.current_instruction.is_macro_placeholder:
            # Skip macro placeholders as they are not real instructions
            return

        # NOTE: the order of the following calls is important
        self._taint_tracker.track_instruction(state.current_instruction)
        self._tracer.observe_instruction(address, size)
        self._speculator.handle_instruction(address, size)
        self._interpreter.interpret_instruction(address, state)
        self.coverage.add_instruction(state.current_instruction)

    def mem_access_dispatch(self, access: int, address: int, size: int, value: int,
                            state: ModelExecutionState) -> None:
        """ Call memory access-related callbacks in service classes """

        if state.current_instruction.is_macro_placeholder:
            # Skip macro placeholders as they are not real instructions
            return

        # NOTE: the order of the following calls is important
        self._taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        self._speculator.handle_mem_access(access, address, size, value)
        self._tracer.observe_mem_access(access, address, size, value)
        self._interpreter.interpret_mem_access(access, address, size, value)


def _instruction_hook(_: Uc, address: int, size: int, model: UnicornModel) -> None:
    """ Dispatch the Unicorn instruction hook to the model. """
    model.instruction_callback(address, size)


def _mem_access_hook(_: Uc, access: int, address: int, size: int, value: int,
                     model: UnicornModel) -> None:
    """ Dispatch the Unicorn memory access hook to the model. """
    model.mem_access_callback(access, address, size, value)


def _mem_unmapped_hook(_: Uc, access: int, address: int, size: int, value: int,
                       model: UnicornModel) -> None:
    """ Dispatch the Unicorn memory unmapped hook to the model. """
    model.mem_access_callback(access, address, size, value)


_ERR_DECODE = {
    uc.UC_ERR_OK: "OK (UC_ERR_OK)",
    uc.UC_ERR_NOMEM: "No memory available or memory not present (UC_ERR_NOMEM)",
    uc.UC_ERR_ARCH: "Invalid/unsupported architecture (UC_ERR_ARCH)",
    uc.UC_ERR_HANDLE: "Invalid handle (UC_ERR_HANDLE)",
    uc.UC_ERR_MODE: "Invalid mode (UC_ERR_MODE)",
    uc.UC_ERR_VERSION: "Different API version between core & binding (UC_ERR_VERSION)",
    uc.UC_ERR_READ_UNMAPPED: "Invalid memory read (UC_ERR_READ_UNMAPPED)",
    uc.UC_ERR_WRITE_UNMAPPED: "Invalid memory write (UC_ERR_WRITE_UNMAPPED)",
    uc.UC_ERR_FETCH_UNMAPPED: "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)",
    uc.UC_ERR_HOOK: "Invalid hook type (UC_ERR_HOOK)",
    uc.UC_ERR_INSN_INVALID: "Invalid instruction (UC_ERR_INSN_INVALID)",
    uc.UC_ERR_MAP: "Invalid memory mapping (UC_ERR_MAP)",
    uc.UC_ERR_WRITE_PROT: "Write to write-protected memory (UC_ERR_WRITE_PROT)",
    uc.UC_ERR_READ_PROT: "Read from non-readable memory (UC_ERR_READ_PROT)",
    uc.UC_ERR_FETCH_PROT: "Fetch from non-executable memory (UC_ERR_FETCH_PROT)",
    uc.UC_ERR_ARG: "Invalid argument (UC_ERR_ARG)",
    uc.UC_ERR_READ_UNALIGNED: "Read from unaligned memory (UC_ERR_READ_UNALIGNED)",
    uc.UC_ERR_WRITE_UNALIGNED: "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)",
    uc.UC_ERR_FETCH_UNALIGNED: "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)",
    uc.UC_ERR_RESOURCE: "Insufficient resource (UC_ERR_RESOURCE)",
    uc.UC_ERR_EXCEPTION: "Misc. CPU exception (UC_ERR_EXCEPTION)",
}


def _err_to_str(errno: int) -> str:
    if errno in _ERR_DECODE:
        return _ERR_DECODE[errno]
    return "Unknown error code"


# ==================================================================================================
# Public Interface: Architecture-independent Model
# ==================================================================================================
class UnicornModel(Model, ABC):
    """
    Basic architecture-independent implementation of a Unicorn-based model.
    This implementation does not support speculative execution; see UnicornSpec for that.
    """

    # pylint: disable=too-many-instance-attributes
    # justification: This is a management class that connects many services together, so having
    # many attributes is a necessary evil

    # Service objects
    emulator: Uc
    tracer: Final[UnicornTracer]
    speculator: Final[UnicornSpeculator]
    _taint_tracker: UnicornTaintTracker
    _log: Final[ModelLogger]
    _dispatcher: Final[_Dispatcher]

    # Model state
    state: ModelExecutionState
    layout: SandboxLayout

    # Descriptors
    _bases: BaseAddrTuple
    _target_desc: Final[TargetDesc]
    _uc_target_desc: Final[UnicornTargetDesc]
    _architecture: Optional[Tuple[int, int]] = None  # (UC_ARCH, UC_MODE)
    _handled_faults: Set[int]  # The set of fault types that do NOT terminate execution

    # ----------------------------------------------------------------------------------------------
    # Constructor and Service Module Initialization
    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:

        assert self._architecture is not None, \
            "Subclasses must define the `architecture` attribute before calling super().__init__"

        # Service modules
        self.emulator = Uc(*self._architecture)
        self._taint_tracker = UnicornTaintTracker(bases, target_desc)
        self.tracer = tracer_cls(target_desc, self, self._taint_tracker)
        self.speculator = speculator_cls(target_desc, self, self._taint_tracker)
        self._dispatcher = _Dispatcher(self._taint_tracker, self.speculator, self.tracer,
                                       interpreter_cls(target_desc, self), InstructionCoverage())
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc
        self._log = ModelLogger()

        # Set the base addresses and the mismatch check mode
        self._bases = bases
        self._enable_mismatch_check_mode = enable_mismatch_check_mode
        self.is_speculative = not self.speculator.is_sequential

        # Set the list of handled faults
        self._handled_faults = set()
        for fault in CONF.get_handled_faults():
            if fault in _UC_FAULT_MAPPING:
                self._handled_faults.update(_UC_FAULT_MAPPING[fault])
            else:
                raise NotImplementedError(f"Fault type {fault} is not supported")

    # ----------------------------------------------------------------------------------------------
    # Default Public Interface
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Load the test case into the model. This method must be called before tracing
        the test case (trace_test_case or trace_test_case_with_taints).
        :param test_case: the test case to load
        :return: None
        :raises UcError: if an error occurs while loading the test case
        """
        test_case_obj = test_case.get_obj()

        # Load the test case into the service classes
        self.layout = SandboxLayout(self._bases, test_case.n_actors())
        self._log.set_model_layout(self.layout)
        self.state = ModelExecutionState(test_case, self.layout, self._target_desc)
        self._dispatcher.test_case_load_dispatch(test_case)

        # Create a new instance of the emulator
        assert self._architecture is not None, "_architecture must be set by subclass"
        self.emulator = Uc(*self._architecture)

        # Get binary representation of the test case
        code = test_case_obj.to_bytes(
            padded_section_size=self.layout.code_size_per_actor(), padding_byte=b'\x90')

        # Allocate memory and write the binary
        # Note: the data will be written later, by the _load_input method
        try:
            self.emulator.mem_map(self.layout.code_start(), self.layout.code_size)
            self.emulator.mem_map(self.layout.data_start(), self.layout.data_size)
            self.emulator.mem_write(self.layout.code_start(), code)
        except UcError as e:
            error(f"[UnicornModel:load_test_case] {e}")

        # Set up callbacks
        try:
            self.emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, _mem_access_hook, self)
            self.emulator.hook_add(UC_HOOK_MEM_UNMAPPED, _mem_unmapped_hook, self)
            self.emulator.hook_add(UC_HOOK_CODE, _instruction_hook, self)
        except UcError as e:
            error(f"[UnicornModel:load_test_case] {e}")

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        Execute the previously loaded test case with the inputs and collect the contract traces.
        :param inputs: the inputs to use for the test case
        :param nesting: the maximum number of speculative levels that will be simulated
        :return: list of collected contract traces, one per input
        """
        self._taint_tracker.set_enable_tracking(False)
        self.speculator.set_max_nesting(nesting)
        ctraces, _ = self._execute_test_case_with_inputs(inputs)
        return ctraces

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        Executes the previously loaded test case with the inputs and collects the contract traces
        while also tracking taints.
        :param inputs: the inputs to use for the test case
        :param nesting: the maximum number of speculative levels that will be simulated
        :return: list of collected contract traces and the taints, one of each per input
        """
        self._taint_tracker.set_enable_tracking(True)
        self.speculator.set_max_nesting(nesting)
        ctraces, taints = self._execute_test_case_with_inputs(inputs)
        return ctraces, taints

    # ----------------------------------------------------------------------------------------------
    # Unicorn-specific Public Interface
    def instruction_callback(self, address: int, size: int) -> None:
        """
        Callback function called when Unicorn executes an instruction
        :param address: the address of the instruction
        :param size: the size of the instruction
        :return: None
        """
        # Terminate execution if the exit instruction is reached
        if self.state.is_exit_addr(address):
            self.emulator.emu_stop()
            return

        # Otherwise, update the context ...
        self.state.update_context(self.emulator, address)
        self._log.dbg_instruction(address, self, self.state, self.speculator)

        # .. and pass the instruction down to the service modules
        self._dispatcher.instruction_dispatch(address, size, self, self.state)

    def mem_access_callback(self, access: int, address: int, size: int, value: int) -> None:
        """
        Callback function called when Unicorn accesses memory.
        """
        self._log.dbg_mem_access(access == UC_HOOK_MEM_WRITE, value, address, size, self,
                                 self.layout)
        self._dispatcher.mem_access_dispatch(access, address, size, value, self.state)

    def do_soft_fault(self, errno: int) -> None:
        """
        Signal a fault to the model and stop the emulator
        (without rising an exception in the emulator)
        """
        assert self.state, "Function called before load_test_case"
        self.state.pending_fault = errno
        self.emulator.emu_stop()

    def set_faulty_area_rw(self, actor_id: int, r: bool, w: bool) -> None:
        """ Sets the 'readable' and 'writable' property of the faulty area for the given actor """
        if actor_id == -1:
            actor_id = self.state.current_actor.get_id()
        faulty_base = self.layout.get_data_addr(DataArea.FAULTY, actor_id)
        faulty_size = self.layout.data_area_size(DataArea.FAULTY)
        if not r:
            self.emulator.mem_protect(faulty_base, faulty_size, UC_PROT_NONE)
        elif not w:
            self.emulator.mem_protect(faulty_base, faulty_size, UC_PROT_READ)
        else:
            self.emulator.mem_protect(faulty_base, faulty_size)

    def report_coverage(self, path: str) -> None:
        """ Write the coverage data to a file """
        self._dispatcher.coverage.report(path)

    @abstractmethod
    def print_registers(self, oneline: bool = False) -> None:
        """ Print the current values of all general-purpose registers """

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    def _execute_test_case_with_inputs(
            self, inputs: List[InputData]) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        Execute the loaded test case with the given sequence of inputs
        and collect traces and taints.
        :param inputs: the inputs to use for the test case
        :return: the collected traces and taints
        """
        traces, taints = [], []
        for index, input_ in enumerate(inputs):
            self._log.dbg_header(index)
            self.state.full_reset()
            self._dispatcher.execution_start_dispatch(input_)

            # Execute the test case with the given input
            self._load_input(input_)
            self._run_state_machine()

            # Record traces (two options possible):
            if not self._enable_mismatch_check_mode:  # Case 1: normal mode - store traces
                traces.append(self.tracer.get_trace())
            else:  # Case 2: mismatch check mode - store register values
                register_list = self._uc_target_desc.usable_registers
                registers = register_list[:-2]  # exclude RSP and EFLAGS
                reg_values = [int(self.emulator.reg_read(reg)) for reg in registers]  # type: ignore
                self.tracer.trace = [CTraceEntry("reg", val) for val in reg_values]
                traces.append(self.tracer.get_trace())

            # Record taints
            n_actors = self.state.current_test_case().n_actors()
            taints.append(self._taint_tracker.get_taint(n_actors))

        return traces, taints

    def _run_state_machine(self) -> None:
        """
        Execute the loaded test case on the model with the loaded input.

        This method implements a state machine that repeatedly executes the test case
        until it reaches the exit instruction while being in a non-speculative state.

        The state machine ensures that:
            - whenever the emulator exits without reaching the exit instruction,
              the model either rolls back (if in speculation) or exits (if not in speculation)
            - whenever a fault is triggered, the model jumps to the corresponding fault handler
              (if not in speculation) or rolls back (if in speculation)
        The complete state machine is shown in:
            `docs/assets/unicorn-model-state-machine.drawio.png`.

        """
        code_start = self.layout.code_start()
        pc = code_start
        while True:
            self.state.reset_after_em_stop(pc)

            # Handle re-entries after faults and rollbacks
            if pc != code_start:
                in_speculation = self.speculator.in_speculation()

                # When entering a new loop iterations, there are the following options:
                # 1. Re-entering after reaching the end and not in speculation
                if self.state.is_exit_addr(pc) and not in_speculation:
                    return

                # 2. Re-entering after reaching the end and in speculation
                if self.state.is_exit_addr(pc) and in_speculation:
                    pc = self.speculator.rollback()
                    self._log.dbg_rollback(pc)
                    continue

                # 3. Re-entering into a fault handler and in speculation
                if pc == self.state.fault_handler_addr and in_speculation:
                    # This case indicates that the rollback was supposed to terminate speculation,
                    # so rollback again
                    pc = self.speculator.rollback()
                    self._log.dbg_rollback(pc)
                    continue
                # 4. In all other cases, continue execution as normal

            # Execute the test case
            try:
                self.emulator.emu_start(pc, self.layout.code_end(), timeout=10 * uc.UC_SECOND_SCALE)
            except UcError as e:
                self.state.pending_fault = int(e.errno)  # type: ignore  # missing type annotation

            # Handle faults
            if self.state.pending_fault:
                self._patch_context_after_fault()
                pc = self._handle_fault()
                if pc and pc != self.state.exit_addr:
                    continue

            # If the model is in non-speculative state, a fault terminates the execution
            if not self.speculator.in_speculation():
                return

            # Otherwise (in a speculative state), a fault causes a speculation rollback
            pc = self.speculator.rollback()
            self._log.dbg_rollback(pc)
            continue

    def _handle_fault(self) -> int:
        """
        Handle a fault that was triggered during the execution
        :return: address of the next instruction to execute OR zero if the fault triggers a rollback
        """
        errno = self.state.pending_fault
        self._log.dbg_exception(errno, _err_to_str(errno))

        # clear the pending fault
        self.state.pending_fault = 0

        # when a fault is triggered, CPU stores the PC and the fault type
        # on stack - this has to be mirrored at the contract level
        rsp = self.layout.get_data_addr(DataArea.RSP_INIT, 0)
        self.tracer.observe_mem_access(UC_MEM_WRITE, rsp, 8, errno)

        # Possible fault handling scenarios:
        # 1. There is a registered speculation mechanism for this fault -> use it
        next_addr = self.speculator.handle_fault(errno)
        if next_addr:
            return next_addr

        # 2. No registered speculation mechanism, but we're already in speculation -> rollback
        if self.speculator.in_speculation():
            return 0

        # 3. Not in speculation, and we've already had a fault before -> throw an error
        if self.state.had_arch_fault:
            self.print_registers()
            error(f"Nested fault {errno} {_err_to_str(errno)}", print_last_tb=True)
        self.state.had_arch_fault = True

        # 4. Not-nested non-speculative fault, and it is in a list of expected faults -> handle it
        if errno in self._handled_faults:
            return self.state.fault_handler_addr

        # 5. Non-nested non-speculative fault, and it is an unexpected fault -> throw an error
        self.print_registers()
        error(f"Unexpected exception {errno} {_err_to_str(errno)}", print_last_tb=True)

    def _patch_context_after_fault(self) -> None:
        """ Patch the context to avoid Unicorn bugs """
        if not self.state.previous_context:
            error("Fault triggered without a previous context")

        # workaround for a Unicorn bug: after catching an exception
        # we need to restore some pre-exception context. otherwise,
        # the emulator becomes corrupted
        self.emulator.context_restore(self.state.previous_context)
        # another workaround, specifically for flags
        flags_id = self._target_desc.uc_target_desc.reg_norm_to_constant["FLAGS"]
        self.emulator.reg_write(flags_id, self.emulator.reg_read(flags_id))

    @abstractmethod
    def _load_input(self, input_: InputData) -> None:
        """ Load registers and memory with given input: this is architecture specific """


# ==================================================================================================
# Public: x86 implementation of the Unicorn Backend
# ==================================================================================================
class X86UnicornModel(UnicornModel):
    """ Model for x86 architecture """

    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:

        self._architecture = (uc.UC_ARCH_X86, uc.UC_MODE_64)
        self._flags_id = x86ucc.UC_X86_REG_EFLAGS

        self.underflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.UNDERFLOW_PAD))
        self.overflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.OVERFLOW_PAD))

        super().__init__(bases, target_desc, speculator_cls, tracer_cls, interpreter_cls,
                         enable_mismatch_check_mode)

    def _load_input(self, input_: InputData) -> None:
        """
        Set the memory and register values in the emulator according to the input object provided.
        In addition, set the memory permissions for each actor.

        :param input_: Input object containing the memory and register values for each actor.
        """

        def patch_flags(flags: np.uint64) -> np.uint64:
            return (flags & np.uint64(2263)) | np.uint64(2)

        def write_area(area: DataArea, actor_id: int, data: bytes) -> None:
            em.mem_write(self.layout.get_data_addr(area, actor_id), data)

        # shortcuts to save on typing
        em = self.emulator
        regs = self._uc_target_desc.usable_registers

        # Initialize memory for each actor:
        n_actors = self.state.current_test_case().n_actors()
        for actor_id in range(n_actors):
            input_fragment = input_[actor_id]

            # - initialize overflows with zeroes
            write_area(DataArea.OVERFLOW_PAD, actor_id, self.overflow_pad_values)
            write_area(DataArea.UNDERFLOW_PAD, actor_id, self.underflow_pad_values)

            # - sandbox data pages
            write_area(DataArea.MAIN, actor_id, input_fragment['main'].tobytes())
            write_area(DataArea.FAULTY, actor_id, input_fragment['faulty'].tobytes())

            # - GPRs
            # Note: Executor uses the GPR area to initialize EFLAGS, so we need to patch them
            #      before writing them to the emulator to ensure consistency.
            input_fragment['gpr'][6] = patch_flags(input_fragment['gpr'][6])
            # input_fragment['gpr'][7] = np.uint64(self.layout.get_data_addr(DataArea.RSP_INIT, 0))
            write_area(DataArea.GPR, actor_id, input_fragment['gpr'].tobytes())

            # - SIMD
            write_area(DataArea.SIMD, actor_id, input_fragment['simd'].tobytes())

        # Registers are initialized with the main actor's input
        input_fragment = input_[0]

        # - initialize GPRs
        value: np.uint64
        for i, value in enumerate(input_fragment['gpr']):
            em.reg_write(regs[i], int(value))

        # similarly to above, patch reg. values
        em.reg_write(x86ucc.UC_X86_REG_EFLAGS, int(patch_flags(input_fragment['gpr'][6])))
        em.reg_write(x86ucc.UC_X86_REG_RSP, self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(x86ucc.UC_X86_REG_RBP, self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(x86ucc.UC_X86_REG_R14, self.layout.get_data_addr(DataArea.MAIN, 0))

        # - initialize SIMD
        simd_values: List[int] = []
        for i, val in enumerate(input_fragment['simd']):
            if i % 4 == 0:
                simd_values.append(int(val))
            elif i % 4 == 1:
                simd_values[-1] |= int(val) << 64
            else:
                # Unicorn doesn't properly support YMM, so the upper 128 bits are ignored
                continue
        for i, simd_value in enumerate(simd_values):
            em.reg_write(self._uc_target_desc.usable_simd128_registers[i], simd_value)

    def print_registers(self, oneline: bool = False) -> None:

        def compressed(val: int) -> str:
            if self.layout.is_data_addr(val):
                return f"base+0x{self.layout.data_addr_to_offset(val):<9x}"
            return f"0x{val:016x}"

        em = self.emulator
        rax = compressed(em.reg_read(x86ucc.UC_X86_REG_RAX))  # type: ignore
        rbx = compressed(em.reg_read(x86ucc.UC_X86_REG_RBX))  # type: ignore
        rcx = compressed(em.reg_read(x86ucc.UC_X86_REG_RCX))  # type: ignore
        rdx = compressed(em.reg_read(x86ucc.UC_X86_REG_RDX))  # type: ignore
        rsi = compressed(em.reg_read(x86ucc.UC_X86_REG_RSI))  # type: ignore
        rdi = compressed(em.reg_read(x86ucc.UC_X86_REG_RDI))  # type: ignore

        if not oneline:
            print("\n\nRegisters:")
            print(f"rax: {rax}")
            print(f"rbx: {rbx}")
            print(f"rcx: {rcx}")
            print(f"rdx: {rdx}")
            print(f"rsi: {rsi}")
            print(f"rdi: {rdi}")
        else:
            if CONF.color:
                print(f"  {BLUE}rax={COL_RESET}{rax} "
                      f"{BLUE}rbx={COL_RESET}{rbx} "
                      f"{BLUE}rcx={COL_RESET}{rcx}\n"
                      f"  {BLUE}rdx={COL_RESET}{rdx} "
                      f"{BLUE}rsi={COL_RESET}{rsi} "
                      f"{BLUE}rdi={COL_RESET}{rdi}\n"
                      f"  {BLUE}flags={COL_RESET}0b{em.reg_read(x86ucc.UC_X86_REG_EFLAGS):012b}\n"
                      f"  {BLUE}xmm0={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM0):032x} "
                      f"{BLUE}xmm1={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM1):032x} \n"
                      f"  {BLUE}xmm2={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM2):032x} "
                      f"{BLUE}xmm3={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM3):032x} \n"
                      f"  {BLUE}xmm4={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM4):032x} "
                      f"{BLUE}xmm5={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM5):032x} \n"
                      f"  {BLUE}xmm6={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM6):032x} "
                      f"{BLUE}xmm7={COL_RESET}0x{em.reg_read(x86ucc.UC_X86_REG_XMM7):032x} \n")
            else:
                print(f"  rax={rax} "
                      f"rbx={rbx} "
                      f"rcx={rcx} "
                      f"rdx={rdx}\n"
                      f"  rsi={rsi} "
                      f"rdi={rdi} "
                      f"flags=0b{em.reg_read(x86ucc.UC_X86_REG_EFLAGS):012b}\n"
                      f"  xmm0=0x{em.reg_read(x86ucc.UC_X86_REG_XMM0):032x} "
                      f"xmm1=0x{em.reg_read(x86ucc.UC_X86_REG_XMM1):032x} \n"
                      f"  xmm2=0x{em.reg_read(x86ucc.UC_X86_REG_XMM2):032x} "
                      f"xmm3=0x{em.reg_read(x86ucc.UC_X86_REG_XMM3):032x} \n"
                      f"  xmm4=0x{em.reg_read(x86ucc.UC_X86_REG_XMM4):032x} "
                      f"xmm5=0x{em.reg_read(x86ucc.UC_X86_REG_XMM5):032x} \n"
                      f"  xmm6=0x{em.reg_read(x86ucc.UC_X86_REG_XMM6):032x} "
                      f"xmm7=0x{em.reg_read(x86ucc.UC_X86_REG_XMM7):032x} \n")


# ==================================================================================================
# Public: arm64 implementation of the Unicorn Backend
# ==================================================================================================
class ARM64UnicornModel(UnicornModel):
    """ Model for arm64 architecture """

    def __init__(self,
                 bases: BaseAddrTuple,
                 target_desc: TargetDesc,
                 speculator_cls: Type[UnicornSpeculator],
                 tracer_cls: Type[UnicornTracer],
                 interpreter_cls: Type[ExtraInterpreter],
                 enable_mismatch_check_mode: bool = False) -> None:

        self._architecture = (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        self._flags_id = armucc.UC_ARM64_REG_NZCV

        self.underflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.UNDERFLOW_PAD))
        self.overflow_pad_values = bytes(SandboxLayout.data_area_size(DataArea.OVERFLOW_PAD))

        super().__init__(bases, target_desc, speculator_cls, tracer_cls, interpreter_cls,
                         enable_mismatch_check_mode)

    def _load_input(self, input_: InputData) -> None:
        """
        Set the memory and register values in the emulator according to the input object provided.
        In addition, set the memory permissions for each actor.

        :param input_: Input object containing the memory and register values for each actor.
        """

        # FIXME: dudup this code with x86

        def patch_flags(flags: np.uint64) -> np.uint64:
            return (flags << np.uint64(28)) % np.uint64(pow(2, 64) - 1)

        def write_area(area: DataArea, actor_id: int, data: bytes) -> None:
            em.mem_write(self.layout.get_data_addr(area, actor_id), data)

        # shortcuts to save on typing
        em = self.emulator
        regs = self._uc_target_desc.usable_registers

        # Initialize memory for each actor:
        n_actors = self.state.current_test_case().n_actors()
        init_gpr: List[np.uint64]
        for actor_id in range(n_actors):
            input_fragment = input_[actor_id].copy()

            # - initialize overflows with zeroes
            write_area(DataArea.OVERFLOW_PAD, actor_id, self.overflow_pad_values)
            write_area(DataArea.UNDERFLOW_PAD, actor_id, self.underflow_pad_values)

            # - sandbox data pages
            write_area(DataArea.MAIN, actor_id, input_fragment['main'].tobytes())
            write_area(DataArea.FAULTY, actor_id, input_fragment['faulty'].tobytes())

            # - GPRs
            # Note: Executor uses the GPR area to initialize EFLAGS, so we need to patch them
            #      before writing them to the emulator to ensure consistency.
            input_fragment['gpr'][6] = patch_flags(input_fragment['gpr'][6])
            # input_fragment['gpr'][7] = np.uint64(self.layout.get_data_addr(DataArea.RSP_INIT, 0))
            write_area(DataArea.GPR, actor_id, input_fragment['gpr'].tobytes())

            # - SIMD
            write_area(DataArea.SIMD, actor_id, input_fragment['simd'].tobytes())

            # Save the GPR area of the main actor as it will be used to initialize registers
            if actor_id == 0:
                init_gpr = input_fragment['gpr']

        # - initialize GPRs
        value: np.uint64
        for i, value in enumerate(init_gpr):
            em.reg_write(regs[i], int(value))

        # similarly to above, patch reg. values
        em.reg_write(self._uc_target_desc.flags_register, int(init_gpr[6]))
        em.reg_write(self._uc_target_desc.sp_register,
                     self.layout.get_data_addr(DataArea.RSP_INIT, 0))
        em.reg_write(self._uc_target_desc.actor_base_register,
                     self.layout.get_data_addr(DataArea.MAIN, 0))

    def print_registers(self, oneline: bool = False) -> None:

        def compressed(val: int) -> str:
            if self.layout.is_data_addr(val):
                return f"base+0x{self.layout.data_addr_to_offset(val):<9x}"
            return f"0x{val:016x}"

        em = self.emulator
        x0 = compressed(em.reg_read(armucc.UC_ARM64_REG_X0))  # type: ignore
        x1 = compressed(em.reg_read(armucc.UC_ARM64_REG_X1))  # type: ignore
        x2 = compressed(em.reg_read(armucc.UC_ARM64_REG_X2))  # type: ignore
        x3 = compressed(em.reg_read(armucc.UC_ARM64_REG_X3))  # type: ignore
        x4 = compressed(em.reg_read(armucc.UC_ARM64_REG_X4))  # type: ignore
        x5 = compressed(em.reg_read(armucc.UC_ARM64_REG_X5))  # type: ignore
        flags = f"{em.reg_read(armucc.UC_ARM64_REG_NZCV) >> 28:04b}"  # type: ignore

        if not oneline:
            print("\n\nRegisters:")
            print(f"x0: {x0}")
            print(f"x1: {x1}")
            print(f"x2: {x2}")
            print(f"x3: {x3}")
            print(f"x4: {x4}")
            print(f"x5: {x5}")
        else:
            if CONF.color:
                print(f"  {BLUE}x0={COL_RESET}{x0} "
                      f"{BLUE}x1={COL_RESET}{x1} "
                      f"{BLUE}x2={COL_RESET}{x2}\n"
                      f"  {BLUE}x3={COL_RESET}{x3} "
                      f"{BLUE}x4={COL_RESET}{x4} "
                      f"{BLUE}x5={COL_RESET}{x5}\n"
                      f"  {BLUE}flags={COL_RESET}0b{flags}\n")
            else:
                print(f"  x0={x0} "
                      f"x1={x1} "
                      f"x2={x2} "
                      f"x3={x3}\n"
                      f"  x4={x4} "
                      f"x5={x5} "
                      f"flags=0b{flags}\n")
