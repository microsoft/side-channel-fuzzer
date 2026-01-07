"""
File: Abstract interface and architecture-specific implementation of the extra interpreter logic.

      The extra interpreter is a component that provides additional interpretation
      logic over the one provided by Unicorn.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Tuple, Dict, Callable, Set, Optional, List, Final

from unicorn import UC_ERR_NOMEM, UcError, UC_ERR_EXCEPTION, UC_MEM_WRITE, UC_ERR_INSN_INVALID, \
    UC_ERR_READ_PROT, UC_ERR_WRITE_PROT
import unicorn.x86_const as x86ucc  # type: ignore  # no type hints available

from ..tc_components.actor import ActorMode, ActorPL, Actor, ActorID, PTEMask
from ..sandbox import CodeArea, DataArea
from ..logs import warning

if TYPE_CHECKING:
    from .model import UnicornModel
    from .execution_context import ModelExecutionState
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..tc_components.instruction import Instruction
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_binary import SymbolTableEntry
    from ..tc_components.test_case_data import InputData

CRITICAL_ERROR = UC_ERR_NOMEM  # the model never handles this error, hence it will always crash


# ==================================================================================================
# Public Interface
# ==================================================================================================
class ExtraInterpreter(ABC):
    """
    Wrapper class that implements extra interpretation logic over the one provided by Unicorn.
    This, for example, includes the interpretation of macros and emulation of CPU modes.

    This class provides a generic interface, which is instantiated by the ISA-specific subclasses.
    """
    _model: Final[UnicornModel]
    _target_desc: Final[TargetDesc]
    _uc_target_desc: Final[UnicornTargetDesc]

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        self._target_desc = target_desc
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """

    @abstractmethod
    def load_input(self, input_: InputData) -> None:
        """ Load the input into the interpreter """

    def interpret_instruction(self, address: int, state: ModelExecutionState) -> None:
        """ Interpret the current instruction (stored in state.current_instruction) """
        instruction = state.current_instruction

        if instruction.name == "macro":
            self._interpret_macro(instruction, address)

        # emulate invalid opcode for certain instructions when executed in VM guest mode
        if state.current_actor.mode == ActorMode.GUEST:
            self._emulate_vm_execution(address)
        elif state.current_actor.privilege_level == ActorPL.USER:
            self._emulate_userspace_execution(address)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """ Interpret the given memory access """

    @abstractmethod
    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        """ Emulate execution of a macro instruction """

    @abstractmethod
    def _emulate_vm_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in VM guest mode """

    @abstractmethod
    def _emulate_userspace_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in userspace mode """


# ==================================================================================================
# Architecture-specific Implementations
# ==================================================================================================
class X86ExtraInterpreter(ExtraInterpreter):
    """ ExtraInterpreter implementation for the x86 architecture """

    _macro_interpreter: _X86MacroInterpreter
    _vm_interpreter: _X86VMInterpreter
    _userspace_interpreter: _X86UserspaceInterpreter
    _fault_interpreter: _X86FaultInterpreter

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        super().__init__(target_desc, model)
        self._macro_interpreter = _X86MacroInterpreter(model, target_desc)
        self._vm_interpreter = _X86VMInterpreter(model, target_desc)
        self._userspace_interpreter = _X86UserspaceInterpreter(model, target_desc)
        self._fault_interpreter = _X86FaultInterpreter(model, target_desc)

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        self._macro_interpreter.load_test_case(test_case)
        self._fault_interpreter.load_test_case(test_case)
        self._vm_interpreter.reset()
        self._userspace_interpreter.reset()

    def load_input(self, input_: InputData) -> None:
        self._fault_interpreter.load_input(input_)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        super().interpret_mem_access(access, address, size, value)
        self._fault_interpreter.induce_user_faults(self._model.state.current_actor, address)

    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        self._macro_interpreter.interpret(macro, pc)

    def _emulate_vm_execution(self, address: int) -> None:
        self._vm_interpreter.interpret(self._model.state.current_instruction, address)

    def _emulate_userspace_execution(self, address: int) -> None:
        self._userspace_interpreter.interpret(self._model.state.current_instruction, address)


class ARMExtraInterpreter(ExtraInterpreter):
    """ ExtraInterpreter implementation for the arm architecture """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        super().__init__(target_desc, model)
        self._macro_interpreter = _ARM64MacroInterpreter(model, target_desc)
        self._fault_interpreter = _ARM64FaultInterpreter(model, target_desc)

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        self._macro_interpreter.load_test_case(test_case)
        self._fault_interpreter.load_test_case(test_case)

    def load_input(self, input_: InputData) -> None:
        self._fault_interpreter.load_input(input_)

    def interpret_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        super().interpret_mem_access(access, address, size, value)
        self._fault_interpreter.emulate_crossing_fault(access, address, size)

    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        self._macro_interpreter.interpret(macro, pc)

    def _emulate_vm_execution(self, address: int) -> None:
        pass

    def _emulate_userspace_execution(self, address: int) -> None:
        pass


# ==================================================================================================
# Private: Macro Interpretation
# ==================================================================================================

_MacroCallback = Callable[[int, int, int, int], None]


class _MacroInterpreterCommon:
    """ Implementation of architecture-independent macros and common logic """
    _model: UnicornModel
    _uc_target_desc: UnicornTargetDesc

    _test_case: Optional[TestCaseProgram] = None
    _function_table: List[SymbolTableEntry]
    _macro_table: List[SymbolTableEntry]
    _macro_callbacks: Dict[str, _MacroCallback]

    _curr_targets: Dict[str, int]
    _sid_to_actor: Dict[int, Actor]

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self._function_table = []
        self._macro_table = []
        self._curr_targets = {
            "h2g": 0,
            "g2h": 0,
            "k2u": 0,
            "u2k": 0,
        }
        self._macro_callbacks = {
            "measurement_start": self._macro_measurement_start,
            "measurement_end": self._macro_measurement_end,
            "switch": self._macro_switch,
            "fault_handler": lambda *_: None,
        }

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """
        self._test_case = test_case
        test_case_obj = test_case.get_obj()
        symbol_table = test_case_obj.symbol_table()

        self._function_table = [sym for sym in symbol_table if sym.type_ == 0]
        self._function_table.sort(key=lambda s: [s.arg])
        self._macro_table = [sym for sym in symbol_table if sym.type_ != 0]
        self._sid_to_actor = {actor.get_id(): actor for actor in test_case.get_actors()}

    def interpret(self, macro: Instruction, pc: int) -> None:
        """
        Interpret the given macro instruction and execute the corresponding logic on the model
        """
        actor_id = self._model.state.current_actor.get_id()
        macro_start = self._model.layout.get_code_addr(CodeArea.MAIN, actor_id)
        macro_offset = pc - macro_start
        macro_args = self._get_macro_args(actor_id, macro_offset)
        macro_name = macro.operands[0].value.lower()[1:]
        if macro_name not in self._macro_callbacks:
            warning("interpret", f"unknown macro: {macro_name}")
            raise UcError(CRITICAL_ERROR)

        interpreter_func = self._macro_callbacks[macro_name]
        interpreter_func(*macro_args)

    def _get_macro_args(self, section_id: int, section_offset: int) -> Tuple[int, int, int, int]:
        # find the macro entry in the symbol table
        for symbol in self._macro_table:
            if symbol.sid == section_id and symbol.offset == section_offset:
                args = symbol.arg
                return args & 0xFFFF, (args >> 16) & 0xFFFF, (args >> 32) & 0xFFFF, \
                    (args >> 48) & 0xFFFF
        warning("get_macro_args", "macro not found in symbol table")
        raise UcError(CRITICAL_ERROR)

    def _find_function_by_id(self, function_id: int) -> SymbolTableEntry:
        if function_id < 0 or function_id >= len(self._function_table):
            warning("find_function_by_id", "function not found in symbol table")
            raise UcError(CRITICAL_ERROR)
        return self._function_table[function_id]

    def _macro_measurement_start(self, _: int, __: int, ___: int, ____: int) -> None:
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = True

    def _macro_measurement_end(self, _: int, __: int, ___: int, ____: int) -> None:
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = False

    def _macro_switch(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        Switch the active actor, update data area base and SP,
          and jump to the corresponding function address
        """
        model = self._model
        layout = model.layout

        # PC update
        section_addr = layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        model.emulator.reg_write(self._uc_target_desc.pc_register, function_addr)

        # data area base and SP update
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(self._uc_target_desc.sp_register, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]


class _X86MacroInterpreter(_MacroInterpreterCommon):
    """ Implements the interpretation of x86-specific macros """
    _pseudo_lstar: int
    _is_amd: bool

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        super().__init__(model, target_desc)
        self._is_amd = target_desc.cpu_desc.vendor == "AMD"
        self._macro_callbacks.update({
            "switch_k2u": self._macro_switch_k2u,
            "switch_u2k": self._macro_switch_u2k,
            "set_k2u_target": self._macro_set_k2u_target,
            "set_u2k_target": self._macro_set_u2k_target,
            "switch_h2g": self._macro_switch_h2g,
            "switch_g2h": self._macro_switch_g2h,
            "set_h2g_target": self._macro_set_h2g_target,
            "set_g2h_target": self._macro_set_g2h_target,
            "landing_k2u": self._macro_landing_k2u,
            "landing_u2k": self._macro_landing_u2k,
            "landing_h2g": self._macro_landing_h2g,
            "landing_g2h": self._macro_landing_g2h,
            "set_data_permissions": self._macro_set_data_permissions,
        })

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        super().load_test_case(test_case)
        self._pseudo_lstar = self._model.state.exit_addr

    def _macro_set_k2u_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        Decode arguments and store destination into _curr_target
        """
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["k2u"] = function_addr

    def _macro_switch_k2u(self, section_id: int, _: int, __: int, ___: int) -> None:
        """ Read the destination from _curr_target and jump to it;
        also update data area base and SP """
        model = self._model
        layout = model.layout

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["k2u"])

        # side effects
        # flags = model.emulator.reg_read(x86ucc.UC_X86_REG_EFLAGS)
        # rsp = model.emulator.reg_read(x86ucc.UC_X86_REG_RSP)
        # model.emulator.mem_write(rsp - 8, flags.to_bytes(8, byteorder='little'))  # type: ignore

        # data area base and SP update
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_set_u2k_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """ Set LSTAR to the target address if in kernel mode; otherwise, throw an exception """
        if self._model.state.current_actor.privilege_level != ActorPL.KERNEL:
            self._model.do_soft_fault(UC_ERR_EXCEPTION)
            return
        model = self._model

        # update LSTAR
        section_addr = model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._pseudo_lstar = function_addr

    def _macro_switch_u2k(self, section_id: int, _: int, __: int, ___: int) -> None:
        """ Switch the active actor, update data area base and SP, and jump to
            the _pseudo_lstar
        """
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._pseudo_lstar)

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_switch_h2g(self, section_id: int, _: int, __: int, ___: int) -> None:
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["h2g"])

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # reset flags
        model.emulator.reg_write(x86ucc.UC_X86_REG_EFLAGS, 0b10)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMRUN clobbers RAX; we model it as a zero write to RAX
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_switch_g2h(self, section_id: int, _: int, __: int, ___: int) -> None:
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["g2h"])

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMEXIT clobbers RAX; we model it as a zero write to RAX
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_set_h2g_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["h2g"] = function_addr

    def _macro_set_g2h_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["g2h"] = function_addr

    def _macro_landing_k2u(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the k2u switch """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_u2k(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the u2k switch """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_h2g(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the h2g switch """

    def _macro_landing_g2h(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the g2h switch """

    def _macro_set_data_permissions(self, actor_id: int, must_set: int, must_clear: int,
                                    _: int) -> None:
        """ Manual setting of data permissions for the actor """


class _ARM64MacroInterpreter(_MacroInterpreterCommon):
    """ Implements the interpretation of ARM64-specific macros """

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        super().__init__(model, target_desc)
        self._is_amd = target_desc.cpu_desc.vendor == "AMD"
        self._macro_callbacks.update({
            "fault_handler": lambda *_: None,
        })


# ==================================================================================================
# Private: VM mode and Userspace Emulation
# ==================================================================================================
class _X86VMInterpreter:
    """ Adds the ability to emulate VM guest execution to the Unicorn emulator """

    safe_address_cache: Set[int]
    always_exit_instructions: Set[str] = {
        "cpuid", "getsec", "xgetbv", "xsetbv", "xrstors", "xsaves", "invd", "invept", "invvpid",
        "vmptrld", "vmptrst", "vmclear", "vmxon", "vmxoff", "vmlaunch", "vmresume", "vmcall",
        "vmfunc", "hlt", "invlpg", "invpcid", "lgdt", "lidt", "lldt", "ltr", "sgdt", "sidt", "sldt",
        "str", "loadiwkey", "monitor", "mwait", "rdpmc", "rdrand", "rdseed", "rdtsc", "rdtscp",
        "rsm", "tpause", "umwait", "vmread", "vmwrite", "wbinvd", "wbnoinvd", "wrmsr", "fxsave",
        "fxsave64", "in", "ins", "insb", "insw", "insd", "out", "outs", "outsb", "outsw", "outsd",
        "pause", "rdmsr", "swapgs"
    }
    always_exiting_registers = ["cr0", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"]

    def __init__(self, model: UnicornModel, target_desc: TargetDesc) -> None:
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self.safe_address_cache = set()

    def reset(self) -> None:
        """ Reset the state of the interpreter; MUST be called for every new test case """
        self.safe_address_cache.clear()

    def interpret(self, inst: Instruction, address: int) -> None:
        """ Interpret the given instruction """

        if address in self.safe_address_cache:
            return
        stripped_name = inst.name.split()[-1]

        # always-exiting instruction
        if stripped_name in self.always_exit_instructions:
            # make sure that the memory accesses get exposed
            if inst.has_mem_operand(True):
                ops = inst.get_mem_operands(True)
                for op in ops:
                    words = op.value.split("+")
                    for word in words:
                        reg = self._uc_target_desc.reg_str_to_constant.get(word.lower(), 0)
                        if reg:
                            value = int(self._model.emulator.reg_read(reg))  # type: ignore
                            self._model.tracer.observe_mem_access(UC_MEM_WRITE, value, 8, 0)
            self._model.do_soft_fault(UC_ERR_INSN_INVALID)
            return

        # conditional exit
        if stripped_name == "mov":
            if not self._emulate_move(inst, address):
                return

        # safe instruction
        self.safe_address_cache.add(address)

    def _emulate_move(self, inst: Instruction, _: int) -> bool:
        for operand in inst.operands:
            if operand.value in self.always_exiting_registers:
                self._model.do_soft_fault(UC_ERR_INSN_INVALID)
                return False
        return True


class _X86UserspaceInterpreter(_X86VMInterpreter):
    """
    Adds the ability to emulate user-space execution to the Unicorn emulator.
    """
    always_exit_instructions: Set[str] = {
        "cpuid", "rdmsr", "wrmsr", "rdtsc", "rdtscp", "clac", "stac", "clgi", "stgi", "clts", "htl",
        "invd", "invlpg", "invlpga", "invlpgb", "invpcid", "lgdt", "lldt", "lidt", "ltr", "sgdt",
        "sidt", "sldt", "str", "psmash", "pvalidate", "rmpadjust", "rmpquery", "rmpupdate",
        "skinit", "sysretq", "sysexitq", "tlbsync", "vmmcall", "vmload", "vmsave", "vmrun",
        "wbinvd", "wbnoinvd", "smsw", "lmsw", "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase",
        "swapgs", "vmclear", "vmlaunch", "vmptrld", "vmptrst", "vmread", "vmresume", "vmwrite",
        "vmxoff", "invvpid", "getsec", "loadiwkey", "pconfig", "encls", "enclv", "hlt", "xgetbv",
        "xsetbv"
    }
    always_exiting_registers = [
        "cr0", "cr2", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
    ]


# ==================================================================================================
# Private: Fault Handling and Permissions
# ==================================================================================================
class _FaultInterpreterCommon(ABC):
    """ Class that handles page faults and permissions in the emulator """
    _model: UnicornModel
    _target_desc: TargetDesc
    _uc_target_desc: UnicornTargetDesc
    _test_case: Optional[TestCaseProgram] = None

    _faulty_page_readable: Dict[ActorID, bool]
    _faulty_page_writable: Dict[ActorID, bool]
    _faulty_page_user_accessible: Dict[ActorID, bool]
    _main_page_user_accessible: Dict[ActorID, bool]

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        self._model = model
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """
        self._test_case = test_case
        self._faulty_page_readable = {}
        self._faulty_page_writable = {}
        self._faulty_page_user_accessible = {}
        self._main_page_user_accessible = {}
        for actor in test_case.get_actors(sorted_=True):
            aid = actor.get_id()

            pte: PTEMask = actor.data_properties
            self._faulty_page_readable[aid] = self._page_is_readable(pte)
            self._faulty_page_writable[aid] = self._page_is_writable(pte)
            self._faulty_page_user_accessible[aid] = self._page_is_user_accessible(pte)
            self._main_page_user_accessible[aid] = actor.privilege_level == ActorPL.USER

            if actor.mode == ActorMode.GUEST:
                epte: PTEMask = actor.data_ept_properties
                self._faulty_page_readable[aid] &= self._extended_page_is_readable(epte)
                self._faulty_page_writable[aid] &= self._extended_page_is_writable(epte)
                # NOTE: EPT user-accessible bit is not supported yet

        # make the permissions available to other components of the model
        self._model.state.page_permissions = {}
        for actor_id in range(test_case.n_actors()):
            self._model.state.page_permissions[actor_id] = (self._faulty_page_readable[actor_id],
                                                            self._faulty_page_writable[actor_id])

    def load_input(self, _: InputData) -> None:
        """ Set memory permissions for the given input """
        assert self._test_case is not None

        # Set memory permissions
        for actor_id in range(self._test_case.n_actors()):
            if not self._faulty_page_readable[actor_id]:
                self._model.set_faulty_area_rw(actor_id, False, False)
            elif not self._faulty_page_writable[actor_id]:
                self._model.set_faulty_area_rw(actor_id, True, False)

    def induce_user_faults(self, current_actor: Actor, address: int) -> None:
        """
        Induce page faults for user/kernel access based on the page permissions
        and the current execution mode
        """
        # identify the target page privilege level
        if not self._model.layout.is_data_addr(address):
            return
        target_aid = self._model.layout.data_addr_to_actor_id(address)
        faulty_area_start = self._model.layout.get_data_addr(DataArea.FAULTY, target_aid)
        is_faulty_page = (address & 0xFFFFFFFFFFFFF000) == faulty_area_start
        target_page_is_user = self._faulty_page_user_accessible[target_aid] \
            if is_faulty_page else self._main_page_user_accessible[target_aid]

        # user actors produce faults when accessing data from kernel space
        if current_actor.privilege_level == ActorPL.USER and not target_page_is_user:
            self._model.do_soft_fault(13)
            return

        # kernel actors produce faults when accessing data of user actors
        # NOTE: this code assumes that SMAP is enabled, which may or may not be the case in practice
        if current_actor.privilege_level == ActorPL.KERNEL and target_page_is_user:
            self._model.do_soft_fault(13)

    @abstractmethod
    def _page_is_readable(self, pet: PTEMask) -> bool:
        """ Check if the page is readable according to the PTE bits """

    @abstractmethod
    def _page_is_writable(self, pet: PTEMask) -> bool:
        """ Check if the page is writable according to the PTE bits """

    @abstractmethod
    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        """ Check if the page is user-accessible according to the PTE bits """

    @abstractmethod
    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        """ Check if the page is readable according to the EPTE bits """

    @abstractmethod
    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        """ Check if the page is writable according to the EPTE bits """


class _X86FaultInterpreter(_FaultInterpreterCommon):
    """ Implements page fault handling and permission checking for the x86 architecture """

    def _page_is_readable(self, pet: PTEMask) -> bool:
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["present"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["accessed"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["reserved_bit"][0])) != 0:
            return False
        return True

    def _page_is_writable(self, pet: PTEMask) -> bool:
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["writable"][0])) == 0:
            return False
        if (pet & (1 << pte_desc["dirty"][0])) == 0:
            return False
        return True

    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["user"][0])) == 0:
            return False
        return True

    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        epte_desc = self._target_desc.vm_pte_bits
        if (epet & (1 << epte_desc["present"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["accessed"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["reserved_bit"][0])) != 0:
            return False
        return True

    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        epte_desc = self._target_desc.vm_pte_bits
        if (epet & (1 << epte_desc["writable"][0])) == 0:
            return False
        if (epet & (1 << epte_desc["dirty"][0])) == 0:
            return False
        return True


class _ARM64FaultInterpreter(_FaultInterpreterCommon):
    """ Implements page fault handling and permission checking for the ARM64 architecture """

    def _page_is_readable(self, pet: PTEMask) -> bool:
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["valid"][0])) == 0:
            return False
        return True

    def _page_is_writable(self, pet: PTEMask) -> bool:
        pte_desc = self._target_desc.pte_bits
        if (pet & (1 << pte_desc["non_writable"][0])) != 0:
            return False
        return True

    def _page_is_user_accessible(self, pet: PTEMask) -> bool:
        return True  # FIXME: implement user/supervisor bit check

    def _extended_page_is_readable(self, epet: PTEMask) -> bool:
        return True

    def _extended_page_is_writable(self, epet: PTEMask) -> bool:
        return True

    def emulate_crossing_fault(self, access: int, address: int, size: int) -> None:
        """
        Workaround: Unicorn does not trigger a fault if the memory access crosses a page
        boundary and the first page is accessible but the second is not
        """
        # No need for the workaround if the access is within a page
        if address % 0x1000 + size < 0x1000:
            return

        # Also does not apply if the crossing goes to any other page than the faulty area
        layout = self._model.layout
        access_end = address + size - 1
        actor_id = layout.data_addr_to_actor_id(address)
        if actor_id == -1:
            return
        faulty_base = layout.get_data_addr(DataArea.FAULTY, actor_id)
        faulty_end = faulty_base + layout.data_area_size(DataArea.FAULTY)
        if access_end < faulty_base or access_end >= faulty_end:
            return

        # Emulate a fault if the faulty area is non-readable/non-writable
        if not self._faulty_page_readable[actor_id]:
            self._model.do_soft_fault(UC_ERR_READ_PROT)
            return
        if access == UC_MEM_WRITE and not self._faulty_page_writable[actor_id]:
            self._model.do_soft_fault(UC_ERR_WRITE_PROT)
            return
