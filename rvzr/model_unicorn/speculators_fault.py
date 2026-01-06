"""
File: Collection of fault-based (i.e., Meltdown type) speculators for the Unicorn backend.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Set, Tuple, List
from copy import copy
import re

from unicorn import UC_MEM_WRITE
import unicorn.x86_const as ucc  # type: ignore # no type hints for this library

from .speculator_abc import UnicornSpeculator
from ..tc_components.instruction import Instruction, RegisterOp, FlagsOp, MemoryOp, ImmediateOp

if TYPE_CHECKING:
    from ..target_desc import TargetDesc
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..tc_components.actor import ActorID


# ==================================================================================================
# Base class for all fault-based speculators
# ==================================================================================================
class FaultSpeculator(UnicornSpeculator, ABC):
    """
    Common set of functionality for all fault-based speculators.
    Namely, it:
    - provides a universal method for identifying if a given fault should trigger speculation
    - provides a method for configuring the speculation rollback address
    - records address of the current instruction,
      which is used by subclasses to determine speculation starting points
    """

    _errno_that_trigger_speculation: Set[int]  # set by subclasses
    _curr_instruction_addr: int = 0

    def _fault_triggers_speculation(self, errno: int) -> bool:
        """Check if the fault should trigger speculation"""
        # we speculate only on a subset of faults
        if errno not in self._errno_that_trigger_speculation:
            return False

        # no speculation after the maximum nesting level is reached
        if self._max_nesting_reached():
            return False
        return True

    def _get_rollback_address(self) -> int:
        return self._model.state.fault_handler_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        self._curr_instruction_addr = address

    def _restore_faulty_page_permissions(self, actor_id: ActorID) -> None:
        assert (self._model.state.page_permissions
                is not None), "Page permissions were not initialized"
        org_permissions = self._model.state.page_permissions[actor_id]
        self._model.set_faulty_area_rw(actor_id, org_permissions[0], org_permissions[1])


# ==================================================================================================
# Microcode assists
# ==================================================================================================
class SequentialAssistSpeculator(FaultSpeculator):
    """Speculator that simulates sequential handling of memory-based microcode assists"""

    def __init__(
        self,
        target_desc: TargetDesc,
        model: UnicornModel,
        taint_tracker: UnicornTaintTracker,
    ) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # no speculation - simply reset the permissions to permit access
        self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return self._curr_instruction_addr


# ==================================================================================================
# Simple Out-of-Order Exception Handling
# ==================================================================================================
class UnicornDEH(FaultSpeculator, ABC):
    """
    Base class for delayed exception handling (DEH) speculators.
    Models delayed handling in out-of-order CPUs, where an non-data-dependent instructions may
    be executed before a faulting instruction is retired.

    Example:
        mov rax, [faulty_addr]  ; load from faulty address (may fault)
        mov rbx, [non-faulty_addr] ; independent load (may be executed before the fault is handled)
        mov [some_addr], rax    ; store the loaded value (should be skipped if the load faults)
    """

    _dependencies: Set[str]
    _dependency_checkpoints: List[Set[str]]
    _next_instruction_addr: int = 0

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {6, 10, 12, 13, 21}
        self._dependencies = set()
        self._dependency_checkpoints = []

    def _checkpoint(self, next_instruction_addr: int, include_current_inst: bool = True) -> None:
        self._dependency_checkpoints.append(copy(self._dependencies))
        return super()._checkpoint(next_instruction_addr, include_current_inst=include_current_inst)

    def rollback(self) -> int:
        self._dependencies = self._dependency_checkpoints.pop()
        return super().rollback()

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # start speculation
        # we set the rollback address to the end of the testcase
        # because faults are terminating execution
        self._checkpoint(self._get_rollback_address())

        # add destinations to the dependency list
        for op in self._model.state.current_instruction.get_dest_operands(True):
            if isinstance(op, RegisterOp):
                self._dependencies.add(self._target_desc.reg_normalized[op.value])
            elif isinstance(op, FlagsOp):
                for flag in op.get_flags_by_type("write"):
                    self._dependencies.add(flag)

        # speculatively skip the faulting instruction
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0  # no need for speculation if we're at the end

        self._arm64_emulate_fault_with_post_increment()
        return self._next_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        """
        Track instruction dependencies to skip those instructions that are dependent
        on a faulting instruction
        """
        # pylint: disable=too-many-branches
        # FIXME: refactor this method to reduce complexity;
        # for now, it's left as is, because this contract is not a priority
        super()._speculate_instruction(address, size)

        # check that the instruction size is correct (may be wrong for invalid instructions)
        if self._model.state.current_instruction.size() not in [0, size]:
            size = self._model.state.current_instruction.size()
        self._next_instruction_addr = address + size

        # reset flag
        instruction = self._model.state.current_instruction

        # track dependencies only after faults
        if not self._in_speculation or not self._dependencies:
            return

        # check if the instruction should be skipped due to a dependency on a faulting instr
        reg_src_operands = []
        reg_dest_operands = []
        address_regs = []
        for op in instruction.get_all_operands():
            if isinstance(op, RegisterOp):
                if op.src:
                    reg_src_operands.append(self._target_desc.reg_normalized[op.value])
                if op.dest:
                    reg_dest_operands.append(self._target_desc.reg_normalized[op.value])
            elif isinstance(op, MemoryOp):
                for sub_op in re.split(r"\+|-|\*| ", op.value):
                    if sub_op and sub_op in self._target_desc.reg_normalized:
                        normalized = self._target_desc.reg_normalized[sub_op]
                        reg_src_operands.append(normalized)
                        address_regs.append(normalized)
            elif isinstance(op, FlagsOp):
                reg_src_operands.extend(op.get_flags_by_type("read"))
                reg_dest_operands.extend(op.get_flags_by_type("write"))

        is_dependent = False
        is_dependent_addr = False
        for reg in reg_src_operands:
            if reg in self._dependencies:
                is_dependent = True
                break
        for reg in address_regs:
            if reg in self._dependencies:
                is_dependent_addr = True

        # remove overwritten values from dependencies
        old_dependencies = list(self._dependencies)  # type cast to force copy
        for reg in reg_dest_operands:
            if reg not in reg_src_operands and reg in self._dependencies:
                self._dependencies.remove(reg)

        if not is_dependent:
            return

        # update dependencies
        for reg in reg_dest_operands:
            self._dependencies.add(reg)

        # Corner cases
        self._handle_isa_specific_corner_cases(instruction, old_dependencies, reg_dest_operands)

        # special case - many memory operations are implemented as two uops,
        # and one of them could be expected even if the other is data-dependent
        # we approximate it by simply not skipping the dependent stores
        if instruction.has_mem_operand(True) and not is_dependent_addr:
            return

        # this instruction is dependent on a faulting instruction -> skip it
        self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)

    @abstractmethod
    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        """Handle ISA-specific corner cases in dependency tracking"""

    def _arm64_emulate_fault_with_post_increment(self) -> None:
        """ Workaround for ARM64 post-incrementing loads/stores that trigger a page fault"""


class X86UnicornDEH(UnicornDEH):
    """
    x86-64 implementation of delayed exception handling (DEH).
    Extends the base DEH class with x86-specific corner cases, such as:
    - cmpxchg does not always taint RAX
    - exchange instruction swaps dependencies
    - XADD overrides the src taint with the dest taint
    - zeroing and reset patterns (e.g., xor rax, rax)
    """

    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        # pylint: disable=too-many-branches

        # special case 1 - cmpxchg does not always taint RAX
        name = instruction.name
        if "cmpxchg" in name:
            dest = instruction.operands[0]
            if (isinstance(dest, MemoryOp)
                    or self._target_desc.reg_normalized[dest.value] not in old_dependencies):
                self._dependencies.remove(self._target_desc.reg_normalized["rax"])
                flags = instruction.get_flags_operand()
                assert flags
                for flag in flags.get_flags_by_type("write"):
                    self._dependencies.remove(flag)
            return

        # special case 2 - exchange instruction swaps dependencies
        if "xchg" in name:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if isinstance(op1, RegisterOp):
                # swap dependencies
                op1_val, op2_val = [self._target_desc.reg_normalized[op.value] for op in [op1, op2]]
                if op1_val in old_dependencies and op2_val not in old_dependencies:
                    self._dependencies.remove(op1_val)
                elif op1_val not in old_dependencies and op2_val in old_dependencies:
                    self._dependencies.remove(op2_val)
            else:
                # memory is never tainted -> override the src dependency
                op2_val = self._target_desc.reg_normalized[op2.value]
                if op2_val in old_dependencies:
                    self._dependencies.remove(op2_val)
            return

        # special case 3 - XADD overrides the src taint with the dest taint
        if "xadd" in name:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if (isinstance(op1, MemoryOp)
                    or self._target_desc.reg_normalized[op1.value] not in old_dependencies):
                self._dependencies.remove(self._target_desc.reg_normalized[op2.value])
            return

        # special case 4 - zeroing and reset patterns
        if name in ["sub", "lock sub", "sbb", "lock sbb", "xor", "lock xor", "cmp"]:
            assert len(instruction.operands) == 2
            op1, op2 = instruction.operands
            if op1.value == op2.value:
                for reg in reg_dest_operands:
                    self._dependencies.remove(reg)
            return


class ARMUnicornDEH(UnicornDEH):
    """
    ARM64 implementation of delayed exception handling (DEH).
    Currently, there are no known corner cases for ARM64.
    """

    def _handle_isa_specific_corner_cases(self, instruction: Instruction,
                                          old_dependencies: List[str],
                                          reg_dest_operands: List[str]) -> None:
        pass  # No known corner cases for ARM yet

    def _arm64_emulate_fault_with_post_increment(self) -> None:
        """
        Workaround for ARM64 handling of faults:
        If a post-incrementing load/store triggers a page fault,
        the address register is still incremented by the immediate value.

        E.g., if the instruction is `ldr x0, [x1], #8` and it faults,
        x1 is still speculatively incremented by 8, even though the load did not complete.
        """
        instr = self._model.state.current_instruction
        if "ldr" not in instr.name and "str" not in instr.name:
            return  # instruction cannot have post-increment

        # check if the instruction has a post-incrementing operand
        operands = instr.get_all_operands()
        if not isinstance(operands[-1], ImmediateOp):
            return

        # find the register being incremented
        mem_addr_op = operands[-2]
        assert isinstance(mem_addr_op, MemoryOp)
        addr_reg = mem_addr_op.get_base_register()
        if addr_reg is None:
            return

        # increment the register
        increment_str = operands[-1].value
        increment = int(increment_str[1:]) if increment_str.startswith("#") else int(increment_str)
        uc_reg = self._target_desc.uc_target_desc.reg_str_to_constant[addr_reg.value]
        curr_value = int(self._emulator.reg_read(uc_reg))  # type: ignore
        new_value = curr_value + increment
        self._emulator.reg_write(uc_reg, new_value)


# ==================================================================================================
# Value-injection Speculation
# ==================================================================================================
class X86UnicornNull(FaultSpeculator):
    """
    Contract describing zero injection on faults.

    Algorithm:
    - On a faulting load:
        * store the checkpoint
        * overwrite the loaded value with zero
        * change the permissions on the faulting page to RW
        * re-execute the instruction
    - On rollback:
        * restore the original permissions on the faulting page
        * rollback the memory and register values
        * jump to the rollback address
    """

    _curr_load: Tuple[int, int]
    _pending_re_execution: bool = False
    _pending_restore_permissions: bool = False

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def reset(self) -> None:
        if not getattr(self._model, "state", None):
            super().reset()
            return

        # This contract handles REP instructions incorrectly (it's a known bug)
        # Explicitly fail if a REP instruction is detected
        for bb in self._model.state.current_test_case().iter_basic_blocks():
            for instr in bb:
                if "rep" in instr.name:
                    raise ValueError(
                        "REP instructions are not supported by this contract\n"
                        "Exclude all REP instructions from the instruction set, or change contract")
        super().reset()

    def rollback(self) -> int:
        actor_id = self._model.state.current_actor.get_id()
        self._model.set_faulty_area_rw(actor_id, True, True)
        return super().rollback()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        # (this method is called before _speculate_fault)

        if access == UC_MEM_WRITE:
            return
        # save load address in case this instruction may fault
        self._curr_load = (address, size)

    def _speculate_fault(self, errno: int) -> int:
        # (this method is called after _speculate_mem_access)

        # check if the fault should trigger speculation
        if not self._fault_triggers_speculation(errno):
            return 0

        # store a checkpoint
        self._checkpoint(self._get_rollback_address())

        # inject zero in the load
        address, size = self._curr_load
        if address != 0:
            # log old value before injecting zero value
            prev_value = bytes(self._emulator.mem_read(address, 8))
            self._store_logs[-1].append((address, prev_value))

            # inject zeros
            self._emulator.mem_write(address, bytes([0 for _ in range(size)]))

        # enable access to the faulting page and repeat the instruction
        self._pending_re_execution = True
        actor_id = self._model.state.current_actor.get_id()
        self._model.set_faulty_area_rw(actor_id, True, True)
        return self._curr_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        super()._speculate_instruction(address, size)

        # Case 1: this method is called after a fault (i.e., after _speculate_fault)
        #  -> re-executed the faulting instruction
        if self._pending_re_execution:
            self._pending_re_execution = False
            self._pending_restore_permissions = True
            self._curr_load = (0, 0)
            return

        # Case 2: this method is called after the first instruction in speculation
        # (i.e., after one call of _speculate_instruction)
        #  -> restore the permissions of the faulting page
        if self._pending_restore_permissions:
            self._pending_restore_permissions = False
            self._restore_faulty_page_permissions(self._model.state.current_actor.get_id())
            self._curr_load = (0, 0)
            return

        # Case 3: any other case
        #  -> Do nothing
        self._curr_load = (0, 0)


class X86UnicornNullAssist(X86UnicornNull):
    """Variant of X86UnicornNull that does *not* terminate execution after a fault,
    and instead rolls back to the faulting instruction after speculation, and executes
     it without a fault."""

    def _get_rollback_address(self) -> int:
        return self._curr_instruction_addr


class X86Meltdown(FaultSpeculator):
    """
    Loads from the faulty region speculatively return the in-memory value
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {12, 13}

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # store a checkpoint
        self._checkpoint(self._get_rollback_address())

        # remove protection
        self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True, True)
        return self._curr_instruction_addr


class X86NonCanonicalAddress(FaultSpeculator):
    """
    Load from non-canonical address
    """

    faulty_instruction_addr: int = -1
    address_register: int = -1
    register_value: int = -1

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {6, 7}

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        self._checkpoint(self._model.state.fault_handler_addr)
        self.faulty_instruction_addr = self._curr_instruction_addr
        return self._curr_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        super()._speculate_instruction(address, size)

        if not self._in_speculation:
            return

        model = self._model
        if self.address_register != -1:
            model.emulator.reg_write(self.address_register, self.register_value)
            self.address_register = -1
            return

        if self.faulty_instruction_addr != address:
            return

        # Fix non-canonical address
        for mem_op in model.state.current_instruction.get_mem_operands(True):
            registers = re.split(r"\+|-|\*| ", mem_op.value)
            if len(registers) > 1:
                continue

            uc_reg = self._target_desc.uc_target_desc.reg_str_to_constant[registers[0]]
            load_address: int = model.emulator.reg_read(uc_reg)  # type: ignore
            is_canonical: bool = (
                load_address > 0xFFFF800000000000 or load_address < 0x00007FFFFFFFFFFF)
            if not is_canonical:
                self.address_register = uc_reg
                self.register_value = load_address

                if load_address & (1 << 47):  # bit 48 is 1 => high address
                    load_address = load_address | 0xFFFF800000000000
                else:  # bit 48 is 0 => low address
                    load_address = load_address & 0x00007FFFFFFFFFF
                model.emulator.reg_write(uc_reg, load_address)
                return
        return

    def reset(self) -> None:
        self.faulty_instruction_addr = -1
        self.address_register = -1
        self.register_value = -1
        return super().reset()
