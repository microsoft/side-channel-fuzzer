"""
File: Value-injection Speculation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Tuple

from unicorn import UC_MEM_WRITE

from .fault_speculator_abc import FaultSpeculator

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


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
    """
    Variant of X86UnicornNull that does *not* terminate execution after a fault,
    and instead rolls back to the faulting instruction after speculation, and executes
     it without a fault.
     """

    def _get_rollback_address(self) -> int:
        return self._curr_instruction_addr
