"""
File: Speculator for memory faults and general protection faults, implementing VSOps-All algorithm.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from .vsops_abc import VspecAllBaseSpeculator, VspecAssistsMixin

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


class VspecAllMemoryFaultsSpeculator(VspecAllBaseSpeculator):
    """ Any-value speculation on page faults """

    pending_restore_protection: bool = False
    pending_re_execution: bool = False

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        # Page faults and other memory errors
        self._errno_that_trigger_speculation = {6, 7, 12, 13}

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
            return
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


class VspecAllMemoryAssistsSpeculator(VspecAssistsMixin, VspecAllBaseSpeculator):
    """ Any-value speculation on A/D-bit microcode assists (MDS style) """
