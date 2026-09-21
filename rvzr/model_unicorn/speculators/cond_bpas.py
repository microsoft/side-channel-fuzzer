"""
File: Speculator for emulating combination of Spectre V1 and V4

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from .cond import X86CondSpeculator
from .bpas import StoreBpasSpeculator


class X86CondBpasSpeculator(X86CondSpeculator, StoreBpasSpeculator):
    """
    Speculator that combines conditional branch mispredictions and speculative store bypass.
    """

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        StoreBpasSpeculator._speculate_mem_access(self, access, address, size, value)

    def _speculate_instruction(self, address: int, size: int) -> None:
        # the store bypass belongs to the previous instruction, hence it is applied first;
        # otherwise, the branch misprediction would corrupt the checkpoint taken by the bypass
        StoreBpasSpeculator._speculate_instruction(self, address, size)
        X86CondSpeculator._speculate_instruction(self, address, size)
