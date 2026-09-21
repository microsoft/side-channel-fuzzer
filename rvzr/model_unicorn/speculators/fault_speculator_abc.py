"""
File: Base classes for all fault- and assist-based speculators

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Set

from rvzr.model_unicorn.speculator_abc import UnicornSpeculator

if TYPE_CHECKING:
    from rvzr.tc_components.actor import ActorID


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
