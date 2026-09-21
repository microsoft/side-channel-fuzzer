"""
File: Base class for unknown value speculation, implementing VSOps algorithm.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-instance-attributes, too-many-locals
# justification: pylint is disabled for this file because it is currently not maintained
# pylint: disable=too-many-branches, too-many-statements
# justification: pylint is disabled for this file because it is currently not maintained

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Set, Tuple, List, NamedTuple, Dict, Final

import re
from copy import copy

from unicorn import UC_MEM_WRITE

from rvzr.tc_components.instruction import RegisterOp, FlagsOp, MemoryOp, AgenOp
from .cond import FLAGS_CF, FLAGS_PF, FLAGS_AF, FLAGS_ZF, FLAGS_SF, FLAGS_TF, \
    FLAGS_IF, FLAGS_DF, FLAGS_OF
from .fault_speculator_abc import FaultSpeculator

if TYPE_CHECKING:
    from rvzr.tc_components.test_case_data import InputData
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


class TaintedValue(NamedTuple):
    """ A value that is tainted by the input, and the program counter at which it was observed. """
    po: int
    label: int
    value: int


Taint = Set[TaintedValue]

_FLAG_NAME_TO_BITMASK: Final[Dict[str, int]] = {
    "CF": FLAGS_CF,
    "PF": FLAGS_PF,
    "AF": FLAGS_AF,
    "ZF": FLAGS_ZF,
    "SF": FLAGS_SF,
    "TF": FLAGS_TF,
    "IF": FLAGS_IF,
    "DF": FLAGS_DF,
    "OF": FLAGS_OF
}


class VspecBaseSpeculator(FaultSpeculator, ABC):
    """
    Base class for unknown value speculation, implementing VSOps algorithm.

    The algorithm is described in Section 6 of the paper "Speculation at Fault: Modeling and Testing
    Microarchitectural Leakage of CPU Exceptions" by Hofmann et al.
    """
    _input_hash: int = 0
    _full_input_taint: TaintedValue
    _reg_taints: Dict[str, Taint]
    """ reg_taints: taints of registers """
    _reg_taints_checkpoints: List[Dict[str, Taint]]
    _mem_taints: Dict[int, Taint]
    """ mem_taints: taints of memory locations """
    _mem_taints_checkpoints: List[Dict[int, Taint]]
    _whole_memory_tainted: bool = False
    """ whole_memory_tainted: overapproximation recording whole memory as being corrupted/tainted"""
    _whole_memory_tainted_checkpoints: List[bool]
    _curr_observation: Taint = set()
    """ _curr_observation: taints+values that need to be leaked if current instruction is
        a memory access """
    _curr_mem_load: Tuple[int, int] = (-1, -1)
    """ _curr_mem_load: address and size of last memory load (needed in case of exception) """
    _curr_mem_store: Tuple[int, int] = (-1, -1)
    """ _curr_mem_store: address and size of last memory store (needed in case of exception) """
    _curr_dest_regs: List[str] = []
    """ _curr_dest_regs: current destination registers """
    _curr_dest_regs_sizes: Dict[str, int]
    """ curr_dest_regs_sizes: width of current destination registers, i.e., whether only part of
        register gets overwritten """
    _curr_taint: Taint
    """ curr_taint: current taint+values that are propagated from _speculate_instruction()
        to trace_mem_access() """
    _curr_src_tainted: bool = False
    """ remembers if any source operand was tainted in _speculate_instruction """
    _next_instruction_addr: int = 0

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

        self._reg_taints = {}
        self._reg_taints_checkpoints = []
        self._mem_taints = {}
        self._mem_taints_checkpoints = []
        self._whole_memory_tainted_checkpoints = []
        self._curr_dest_regs_sizes = {}
        self._curr_taint = set()
        self._full_input_taint = TaintedValue(0, 0, self._input_hash)\

        raise NotImplementedError("This class and its subclasses are no longer maintained."
                                  "If you need this functionality, please contact the maintainers")
        # NOTE: search for FIXME comments for a list of known issues in this class

    def _load_input(self, input_: InputData) -> None:
        # FIXME:
        # _load_input interface no longer exists; this functionality should be moved
        #    another method (reset() is a good candidate)
        self._input_hash = hash(input_)
        self._full_input_taint = TaintedValue(0, 0, self._input_hash)
        self._curr_observation = set()
        self._curr_dest_regs = []
        self._curr_dest_regs_sizes = {}
        self._curr_mem_load = (-1, -1)
        self._curr_mem_store = (-1, -1)
        self._curr_taint = set()
        self._curr_src_tainted = False
        assert len(self._reg_taints) == 0
        assert len(self._reg_taints_checkpoints) == 0
        assert len(self._mem_taints) == 0
        assert len(self._mem_taints_checkpoints) == 0
        assert not self._whole_memory_tainted
        assert len(self._whole_memory_tainted_checkpoints) == 0
        # super()._load_input(input_)

    def _assemble_reg_values(self, regs: Set[str]) -> Tuple[Taint, bool]:
        """
        Aggregate value of all registers in regs.
        If register is tainted, use taint instead.
        Set _curr_src_tainted to true if one of the registers was tainted.
        Returns set of register values (usable as taints) and Boolean flag
          to indicate if one of the registers was tainted.
        """

        reg_values = set()
        reg_values_tainted = False

        for reg in regs:
            if reg in self._reg_taints:
                reg_values.update(self._reg_taints[reg])
                # remember that one of registers was tainted
                reg_values_tainted = True
            else:
                reg_id = self._uc_target_desc.reg_norm_to_constant[reg]
                reg_value: int = self._emulator.reg_read(reg_id)  # type: ignore
                # if register is a flag, project flags register on flag
                if reg in {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"}:
                    reg_value = int((reg_value & _FLAG_NAME_TO_BITMASK[reg]) != 0)
                pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                reg_values.add(TaintedValue(pc, reg_id, reg_value))
                print(f"reg: {reg_id}, value: {reg_value}, pc: {pc}")

        return reg_values, reg_values_tainted

    def _set_taint(self, reg: str, taint: Taint) -> None:
        # sets reg to taint, only uses input hash if included in taint
        if self._full_input_taint in taint:
            self._reg_taints[reg] = {self._full_input_taint}
        else:
            self._reg_taints[reg] = taint

    def _update_reg_taints(self) -> None:
        """
        update current destination registers according to current taint
        special cases:
          1) only lower bits of register are updated, so also keep old taint
          2) current source is not tainted, but destination is tainted,
             so update taint of destination with current values of register
        """
        for reg in self._curr_dest_regs:
            # check if destination reg is already tainted
            if reg in self._reg_taints:
                # check if reg is a register, not a flag, and whether only lower bits are
                # overwritten if this is the case, we need to keep the old taint of reg
                if reg in self._curr_dest_regs_sizes and self._curr_dest_regs_sizes[reg] < 64:
                    new_taint = self._reg_taints[reg] | self._curr_taint
                    self._set_taint(reg, new_taint)
                # else, old taint is overwritten if the source is currently tainted
                elif self._curr_src_tainted:
                    self._set_taint(reg, self._curr_taint)
                # if source is not tainted and destination is overwritten, remove old taint
                else:
                    self._reg_taints.pop(reg, None)
            # if destination is not tainted already, only need to propagate source taints
            elif self._curr_src_tainted:
                # check if reg is a register, not a flag, and whether only lower bits are
                # overwritten if yes, then keep value currently in register as taint
                if reg in self._curr_dest_regs_sizes and self._curr_dest_regs_sizes[reg] < 64:
                    reg_id = self._uc_target_desc.reg_norm_to_constant[reg]
                    reg_value: int = self._emulator.reg_read(reg_id)  # type: ignore
                    pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                    new_taint = {TaintedValue(pc, reg_id, reg_value)} | self._curr_taint
                    self._set_taint(reg, new_taint)
                # if not, just set current taint as taint of reg
                else:
                    self._set_taint(reg, self._curr_taint)

    def _get_curr_load_address(self) -> int:
        return self._curr_mem_load[0]

    def _get_curr_store_address(self) -> int:
        return self._curr_mem_store[0]

    def _get_curr_load_taint(self) -> TaintedValue:
        address = self._get_curr_load_address()
        size = self._curr_mem_load[1]
        mem_value = self._emulator.mem_read(address, size)
        mem_value_int = int.from_bytes(mem_value, 'little')
        pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
        return TaintedValue(pc, address, mem_value_int)

    def _collect_src_regs(self) -> Set[str]:
        """
        Collect the src registers of the current instruction that occur outside of a memory
        operand. As a side effect, record the instruction's dest registers and their widths
        in _curr_dest_regs and _curr_dest_regs_sizes.
        """
        src_regs: Set[str] = set()
        for op in self._model.state.current_instruction.get_all_operands():
            if isinstance(op, RegisterOp):
                if op.src:
                    op_normalized = self._target_desc.reg_normalized[op.value]
                    src_regs.add(op_normalized)
                    # src_regs_sizes[op_normalized] = op.width
                if op.dest:
                    op_normalized = self._target_desc.reg_normalized[op.value]
                    self._curr_dest_regs.append(op_normalized)
                    self._curr_dest_regs_sizes[op_normalized] = op.width
            elif isinstance(op, FlagsOp):
                src_regs.update(op.get_flags_by_type('read'))
                self._curr_dest_regs.extend(op.get_flags_by_type('write'))
        return src_regs

    def _collect_fault_taints(self) -> None:
        """
        Taint the dest operands of the faulting instruction with all the values that the
        instruction depends on, i.e., its src registers and, for loads, the loaded value.
        """
        # source_values = evaluated load address + values of src regs
        # these are all the values the faulting instruction depends on
        self._curr_taint, _ = self._assemble_reg_values(self._collect_src_regs())

        if self._model.state.current_instruction.has_read():
            self._curr_taint.add(self._get_curr_load_taint())

        if self._model.state.current_instruction.has_write():
            address = self._get_curr_store_address()
            size = self._curr_mem_store[1]
            for i in range(size):
                self._mem_taints[address + i] = self._curr_taint

        # need to set _curr_src_tainted to make update_reg_taints call work
        self._curr_src_tainted = True
        self._update_reg_taints()

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # start speculation
        # set the rollback address
        self._checkpoint(self._get_rollback_address())

        # only collect new taints if none of the src operands in the faulting instruction are
        # tainted if they are, the taints have been propagated correctly already,code_start
        # so just ignore fault
        if not self._curr_src_tainted:
            self._collect_fault_taints()

        return self._get_next_instruction()

    def _get_next_instruction(self) -> int:
        # speculatively skip the faulting instruction
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0  # no need for speculation if we're at the end
        return self._next_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        Track how taints move through system and produce correct observations.
        """
        # check that the instruction size is correct (may be wrong for invalid instructions)
        if self._model.state.current_instruction.size() not in [0, size]:
            size = self._model.state.current_instruction.size()
        self._next_instruction_addr = address + size

        # print('current taints:', self.reg_taints, self.mem_taints)
        # print('current instruction:', self._model.state.current_instruction)

        # reset observation set and rvzr/dest registers
        # this must happen before we check if we can skip, otherwise trace_mem_access might
        # use old values
        self._curr_observation = set()
        self._curr_taint = set()
        self._curr_dest_regs = []
        self._curr_dest_regs_sizes = {}
        self._curr_src_tainted = False
        # might be needed when contract is refined recording which part of register is tainted
        # src_regs_sizes = dict()

        # track taints only after faults with non-empty taints
        if not self._in_speculation or (not self._reg_taints and not self._mem_taints):
            return

        src_regs = self._collect_src_regs()
        mem_src_regs = set()
        mem_dest_regs = set()

        # assemble the registers that are used as part of a memory address
        for op in self._model.state.current_instruction.get_all_operands():
            if isinstance(op, MemoryOp):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        if op.src:
                            mem_src_regs.add(normalized)
                        if op.dest:
                            mem_dest_regs.add(normalized)
            elif isinstance(op, AgenOp):
                assert self._model.state.current_instruction.name == "lea"
                assert op.src
                for sub_op in re.split(r'\[|\]|\+|-|\*| ', op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        src_regs.add(normalized)

        # assemble values of memory dest registers. if tainted, use taint instead
        mem_dest_reg_values, _ = self._assemble_reg_values(mem_dest_regs)

        # check if instruction attempted store using tainted register
        #     => location of store unknown
        tainted_mem_dest_regs = mem_dest_regs & self._reg_taints.keys()
        if tainted_mem_dest_regs:
            assert self._model.state.current_instruction.has_write()
            # record observation of store
            # leaks taint if tainted register is used
            self._curr_observation = self._curr_observation | mem_dest_reg_values
            # as destination is not known, whole memory is tainted (implicitly with input hash)
            self._whole_memory_tainted = True
            # TODO: can we write to registers and memory within one instruction? if not, return
            # if yes, other destination registers might get tainted, so continue

        # assemble values of memory src registers. if tainted, use taint instead
        mem_src_reg_values, _ = self._assemble_reg_values(mem_src_regs)

        # check if instruction attempted load using tainted register
        #     => location of load unknown
        tainted_mem_src_regs = mem_src_regs & self._reg_taints.keys()

        if tainted_mem_src_regs and not self._model.state.current_instruction.name == "lea":
            assert self._model.state.current_instruction.has_read()
            # record observation of load
            # leaks taint if tainted register is used
            self._curr_observation = self._curr_observation | mem_src_reg_values
            # load from tainted value returns content of unknown address
            #     => taint dest registers with input hash (represents full architectural state)
            # remember current taint in case store address needs to be tainted in trace_mem_access()
            self._curr_taint = {self._full_input_taint}
            for reg in self._curr_dest_regs:
                self._reg_taints[reg] = self._curr_taint
            # remember that instruction depended on tainted operand
            self._curr_src_tainted = True
            # all dest regs are tainted with maximal taint, we can return
            return

        # assemble value of all src regs, use taint if tainted
        self._curr_taint, self._curr_src_tainted = self._assemble_reg_values(src_regs)
        self._update_reg_taints()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        # remember last address and size in case of exception
        if access != UC_MEM_WRITE:
            self._curr_mem_load = (address, size)
        else:
            self._curr_mem_store = (address, size)

        if not self._in_speculation:
            # FIXME: this branch should enable/disable tracing via self._model.tracer.enable_tracing
            return

        mem_value = self._model.emulator.mem_read(address, size)

        if access != UC_MEM_WRITE:
            # for loads, check if address is tainted
            # Test if any address in the range of address+size is tainted
            is_tainted: bool = False
            taints = set()
            for i in range(size):
                if address + i in self._mem_taints:
                    is_tainted = True
                    taints.update(self._mem_taints[address + i])

            # add address taint to current taint
            if is_tainted:
                self._curr_taint.update(taints)
            elif self._whole_memory_tainted:
                self._curr_taint.add(self._full_input_taint)

            if is_tainted or self._whole_memory_tainted:
                # remember that instruction used tainted src value and update taint of dest
                # registers with address taint
                self._curr_src_tainted = True
                self._update_reg_taints()
            else:
                # if address itself is not tainted, value stored at address to current taint
                # and potentially add to taints
                mem_value_int = int.from_bytes(mem_value, 'little')
                pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
                self._curr_taint.add(TaintedValue(pc, address, mem_value_int))
                self._update_reg_taints()

        if access == UC_MEM_WRITE:
            # check if any src operand was tainted (memory location or register)
            if not self._curr_src_tainted:
                # if there is no current taint, remove possible taint from current address range
                for i in range(size):
                    self._mem_taints.pop(address + i, None)
            # if src was tainted, add current taint to current address range
            #     check if whole memory is already tainted, then nothing has to be done
            elif not self._whole_memory_tainted:
                for i in range(size):
                    self._mem_taints[address + i] = self._curr_taint

        # check if the memory access creates a tainted observation
        if self._curr_observation:
            # if current observation contains full architectural state info, then only leak the hash
            if self._full_input_taint in self._curr_observation:
                self._curr_observation = {self._full_input_taint}
            observation_list = list(self._curr_observation)
            observation_list.sort()
            # print('leaking observation', observation_list)
            # observation_hash = hash(tuple(observation_list))
            # just append hash to trace, don't do normal memory access
            # FIXME: this should be replaced with a public call to the tracer
            # self._model.tracer._add_dependencies_to_trace(observation_hash)
        # if not, do normal memory access
        else:
            pass
            # FaultSpeculator.trace_mem_access(emulator, access, address, size, value, model)

    def _checkpoint(self, next_instruction_addr: int, include_current_inst: bool = True) -> None:
        self._reg_taints_checkpoints.append(copy(self._reg_taints))
        self._mem_taints_checkpoints.append(copy(self._mem_taints))
        self._whole_memory_tainted_checkpoints.append(copy(self._whole_memory_tainted))
        return super()._checkpoint(next_instruction_addr, include_current_inst=include_current_inst)

    def rollback(self) -> int:
        self._reg_taints = self._reg_taints_checkpoints.pop()
        self._mem_taints = self._mem_taints_checkpoints.pop()
        self._whole_memory_tainted = self._whole_memory_tainted_checkpoints.pop()
        return super().rollback()

    def _get_rollback_address(self) -> int:
        # faults end program execution
        return self._model.state.fault_handler_addr


class VspecAllBaseSpeculator(VspecBaseSpeculator):
    """
    Most permissive contract.
    Uses vspec-unknown contract but destination operands in case of
    exception depends on full architectural state (= on full input)
    instead of value of src operands.
    """

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # start speculation
        # store a checkpoint
        self._checkpoint(self._get_rollback_address())

        # only collect new taints if none of the src operands in the faulting instruction are
        # tainted if they are, the taints have been propagated correctly already,
        # so just ignore fault
        if not self._curr_src_tainted:

            for op in self._model.state.current_instruction.get_all_operands():
                if isinstance(op, RegisterOp):
                    if op.dest:
                        self._curr_dest_regs.append(self._target_desc.reg_normalized[op.value])
                elif isinstance(op, FlagsOp):
                    self._curr_dest_regs.extend(op.get_flags_by_type('write'))

            if self._model.state.current_instruction.has_write():
                address = self._curr_mem_store[0]
                size = self._curr_mem_store[1]
                for i in range(size):
                    self._mem_taints[address + i] = {self._full_input_taint}

            # taint destination registers with hash of full input (represents architectural state)
            for reg in self._curr_dest_regs:
                self._reg_taints[reg] = {self._full_input_taint}

        return self._get_next_instruction()


class VspecAssistsMixin(VspecBaseSpeculator, ABC):
    """
    Mixin with the behavior shared by all speculators that model microcode assists: speculation
    is triggered by A/D-bit assists, and the page protection is restored once it ends.
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def rollback(self) -> int:
        next_instruction = super().rollback()
        if not self._in_speculation:
            # remove protection after the assists has completed
            self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return next_instruction

    def _get_rollback_address(self) -> int:
        if self._in_speculation:
            return self._model.state.fault_handler_addr
        return self._curr_instruction_addr
