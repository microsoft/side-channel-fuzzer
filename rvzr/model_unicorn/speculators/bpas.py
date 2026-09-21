"""
File: Speculator for Speculative Store Bypass (Spectre v4)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import NamedTuple, Optional
from unicorn import UC_MEM_WRITE

from rvzr.model_unicorn.speculator_abc import UnicornSpeculator


class _PendingStore(NamedTuple):
    """ A store that has been executed but not yet bypassed. """
    address: int
    size: int
    old_value: bytes


class StoreBpasSpeculator(UnicornSpeculator):
    """
    Implementation of the execution clause for Speculative Store Bypass (Spectre v4).

    Models the case when the CPU's memory disambiguation predictor mispredicts that a store
    does not alias with a subsequent load, and thus the load reads the stale value from memory
    instead of the value written by the store.

    The model is an over-approximation of the hardware behavior: every store is assumed to be
    bypassed, regardless of whether its address was resolved in time, and the resulting
    speculative window is assumed to be unbounded (i.e., it is terminated only by the
    speculator's generic nesting/window limits, not by store address resolution).
    """
    _previous_store: Optional[_PendingStore] = None

    def rollback(self) -> int:
        # if there are any pending speculative store bypasses, cancel them
        self._previous_store = None
        return super().rollback()

    def reset(self) -> None:
        self._previous_store = None
        super().reset()

    def _speculate_mem_access(self, access: int, address: int, size: int, _: int) -> None:
        # Since Unicorn does not have post-instruction hooks, we have to implement it a dirty way:
        # Save the information about the store here, but execute all the
        # contract logic in a hook before the next instruction (see _speculate_instruction)
        if access != UC_MEM_WRITE:
            return

        prev = self._previous_store
        if prev is not None:
            if prev.address <= address and address + size <= prev.address + prev.size:
                return  # a redundant hook call within the range of the pending store
            raise NotImplementedError("Instructions with multiple stores are not supported")

        old_value = bytes(self._emulator.mem_read(address, size))
        self._previous_store = _PendingStore(address, size, old_value)

    def _speculate_instruction(self, address: int, _: int) -> None:
        store = self._previous_store
        self._previous_store = None
        if store is None or self._max_nesting_reached():
            return

        # a barrier between the store and the subsequent loads prevents the bypass; note that the
        # base class does not catch this case because the speculation has not started yet
        if self._model.state.current_instruction.name in self._uc_target_desc.barriers:
            return

        # the store has already been applied by the time this hook runs, hence the new value is
        # read back from memory rather than reconstructed from the hook argument
        new_value = bytes(self._emulator.mem_read(store.address, store.size))

        # store a checkpoint (do not include the effects of the current instruction as the
        # speculation was actually triggered by the previous instruction)
        self._checkpoint(address, include_current_inst=False)

        # cancel the previous store but preserve its value
        self._emulator.mem_write(store.address, store.old_value)
        self._store_logs[-1].append((store.address, new_value))
