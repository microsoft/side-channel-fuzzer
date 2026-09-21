"""
File: Speculator for Speculative Store Bypass (Spectre v4)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Tuple, Optional
from unicorn import UC_MEM_WRITE

from rvzr.model_unicorn.speculator_abc import UnicornSpeculator


class StoreBpasSpeculator(UnicornSpeculator):
    """
    Speculator for speculative store bypasses.
    Speculatively skips memory store if it is followed by a load from the same address.
    """
    _previous_store: Optional[Tuple[int, int, int, int]] = None

    def rollback(self) -> int:
        # if there are any pending speculative store bypasses, cancel them
        self._previous_store = None
        return super().rollback()

    def reset(self) -> None:
        self._previous_store = None
        super().reset()

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        # Since Unicorn does not have post-instruction hooks,
        # we have to implement it in a dirty way:
        # Save the information about the store here, but execute all the
        # contract logic in a hook before the next instruction (see trace_instruction)
        if access == UC_MEM_WRITE:
            # check for duplicate calls
            if self._previous_store is not None:
                end_addr = address + size
                prev_addr, prev_size = self._previous_store[0:2]
                if address >= prev_addr and end_addr <= (prev_addr + prev_size):
                    prev_val = self._previous_store[3].\
                        to_bytes(prev_size, byteorder='little', signed=self._previous_store[3] < 0)
                    sliced = prev_val[address - prev_addr:end_addr - prev_addr][0]
                    if sliced == value:
                        return
                    raise NotImplementedError("Self-overwriting instructions are not supported")
                raise NotImplementedError("Instructions with multiple stores are not supported")

            # it's not a duplicate - initiate speculation
            old_val: int = self._emulator.mem_read(address, size)  # type: ignore
            self._previous_store = (address, size, old_val, value)

    def _speculate_instruction(self, address: int, _: int) -> None:
        if self._max_nesting_reached():  # reached max spec. window? skip
            self._previous_store = None  # clear pending speculation requests
            return

        if self._previous_store is not None:
            store_addr = self._previous_store[0]
            old_value = bytes(self._previous_store[2])
            new_is_signed = self._previous_store[3] < 0
            new_value = (self._previous_store[3]). \
                to_bytes(self._previous_store[1], byteorder='little', signed=new_is_signed)

            # store a checkpoint (do not include the effects of the current instruction as the
            # speculation was actually triggered by the previous instruction)
            self._checkpoint(address, include_current_inst=False)

            # cancel the previous store but preserve its value
            self._emulator.mem_write(store_addr, old_value)
            self._store_logs[-1].append((store_addr, new_value))
        self._previous_store = None
