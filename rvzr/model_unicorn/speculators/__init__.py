"""
Public list of all available speculators.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from .seq import SeqSpeculator
from .seq_assist import SequentialAssistSpeculator
from .bpas import StoreBpasSpeculator
from .cond import X86CondSpeculator, ARM64CondSpeculator
from .cond_bpas import X86CondBpasSpeculator
from .delayed_exception_handling import X86UnicornDEH, ARM64UnicornDEH
from .null_injection import X86UnicornNull, X86UnicornNullAssist
from .meltdown import X86Meltdown
from .noncanonical_address import X86NonCanonicalAddress
from .vsops_div import VspecDIVSpeculator
from .vsops_all_div import VspecAllDIVSpeculator
from .vsops_memory import VspecMemoryFaultsSpeculator, VspecMemoryAssistsSpeculator, \
    VspecGPSpeculator
from .vsops_all_memory import VspecAllMemoryFaultsSpeculator, VspecAllMemoryAssistsSpeculator

__all__ = [
    "SeqSpeculator",
    "SequentialAssistSpeculator",

    # Spectre-class Speculators
    "X86CondSpeculator",
    "ARM64CondSpeculator",
    "StoreBpasSpeculator",

    # Meltdown-class Speculators
    "X86Meltdown",
    "X86UnicornDEH",
    "ARM64UnicornDEH",
    "X86UnicornNull",
    "X86UnicornNullAssist",
    "X86NonCanonicalAddress",

    # VSOps Speculators
    "VspecDIVSpeculator",
    "VspecAllDIVSpeculator",
    "VspecMemoryFaultsSpeculator",
    "VspecAllMemoryFaultsSpeculator",
    "VspecMemoryAssistsSpeculator",
    "VspecAllMemoryAssistsSpeculator",
    "VspecGPSpeculator",

    # Compound Speculators
    "X86CondBpasSpeculator",
]
