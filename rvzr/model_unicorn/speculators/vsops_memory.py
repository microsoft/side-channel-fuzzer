"""
File: Speculator for memory faults and general protection faults, implementing VSOps algorithm.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from unicorn import UC_MEM_WRITE

from .noncanonical_address import X86NonCanonicalAddress
from .vsops_abc import VspecAssistsMixin, VspecBaseSpeculator, TaintedValue

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


class VspecMemoryFaultsSpeculator(VspecBaseSpeculator):
    """ Operand value  speculation on page faults """

    pending_restore_protection: bool = False
    pending_re_execution: bool = False

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        # Page faults and other memory errors
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

    def _get_curr_load_taint(self) -> TaintedValue:
        # The loaded value is undefined for faulting loads,
        # hence the memory value should not be included in dependencies
        load_addr = self._curr_mem_load[0]
        pc = self._model.layout.code_addr_to_offset(self._curr_instruction_addr)
        return TaintedValue(pc, load_addr, 0)

    def _speculate_instruction(self, address: int, size: int) -> None:
        if self.pending_restore_protection:
            self.pending_restore_protection = False
            # FIXME: this is outdated;
            # see speculator_faults.py:X86UnicornNull for a maintained implementation
            # of a similar algorithm
            # aid = self._model.state.current_actor.get_id()
            # if self.rw_forbidden[aid]:
            #     self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), False,
            #                                    False)
            # elif self.w_forbidden[aid]:
            #     self._model.set_faulty_area_rw(self._model.state.current_actor.get_id(), True,
            #                                    False)
        elif self.pending_re_execution:
            self.pending_re_execution = False
            self.pending_restore_protection = True
        super()._speculate_instruction(address, size)

    def _get_next_instruction(self) -> int:
        if self._model.state.is_exit_addr(self._next_instruction_addr):
            return 0  # no need for speculation if we're at the end

        # FIXME: uses outdated interfaces
        # aid = self.current_actor.get_id()
        # if self.pending_fault == UC_ERR_WRITE_PROT and self.w_forbidden[aid]:
        #     # remove protection
        #     self._model.set_faulty_area_rw(self.current_actor.get_id(), True, True)
        #     self.pending_re_execution = True
        #     return self._curr_instruction_addr
        return self._next_instruction_addr


class VspecMemoryAssistsSpeculator(VspecAssistsMixin, VspecMemoryFaultsSpeculator):
    """ Operand value  speculation on page faults with memory assists """


class VspecGPSpeculator(VspecBaseSpeculator, X86NonCanonicalAddress):
    """ Operand value  speculation on General Protection Faults """

    address_register: int
    register_value: int

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation.update([6, 7])

    # def _speculate_fault(self, errno: int) -> int:
    #     if not self._fault_triggers_speculation(errno):
    #         return 0

    #     self._checkpoint(self._model.state.fault_handler_addr)
    #     self.faulty_instruction_addr = self._curr_instruction_addr
    #     return self._curr_instruction_addr

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        # only collect new taints if none of the src operands in the faulting instruction are
        # tainted if they are, the taints have been propagated correctly already,code_start
        # so just ignore fault
        if not self._curr_src_tainted:
            self._collect_fault_taints()

        # speculatively skip the faulting instruction
        return self._curr_instruction_addr

    def _get_curr_load_address(self) -> int:
        return self._noncanonical_to_canonical(self._curr_mem_load[0])

    def _get_curr_store_address(self) -> int:
        return self._noncanonical_to_canonical(self._curr_mem_store[0])

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        if self._curr_instruction_addr == self.faulty_instruction_addr:
            if access != UC_MEM_WRITE:
                self._curr_mem_load = (address, size)
            else:
                self._curr_mem_store = (address, size)
            self._speculate_fault(6)
        super()._speculate_mem_access(access, address, size, value)

    def _speculate_instruction(self, address: int, size: int) -> None:
        super(X86NonCanonicalAddress, self)._speculate_instruction(address, size)
        if address != self.faulty_instruction_addr:
            super(VspecBaseSpeculator, self)._speculate_instruction(address, size)

    def _noncanonical_to_canonical(self, address: int) -> int:
        if address & (1 << 47):  # bit 48 is 1 => high address
            address = address | 0xFFFF800000000000
        else:  # bit 48 is 0 => low address
            address = address & 0x00007FFFFFFFFFF
        return address

    def _get_rollback_address(self) -> int:
        return self._model.state.fault_handler_addr

    def reset(self) -> None:
        self.faulty_instruction_addr = -1
        self.address_register = -1
        self.register_value = -1
        return super().reset()
