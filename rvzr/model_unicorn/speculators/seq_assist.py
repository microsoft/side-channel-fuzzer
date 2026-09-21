"""
File: Speculator for sequential handling of memory-based microcode assists

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .fault_speculator_abc import FaultSpeculator

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


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
