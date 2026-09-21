"""
File: Sequential speculator for Unicorn-based models

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from ..speculator_abc import UnicornSpeculator


class SeqSpeculator(UnicornSpeculator):
    """
    Trivial speculator that does not implement any speculation; that is, it models
    sequential execution of all instructions
    """

    is_sequential: bool = True
