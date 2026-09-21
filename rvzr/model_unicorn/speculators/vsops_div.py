"""
File: Speculator for division errors, implementing VSOps algorithm.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .vsops_abc import VspecBaseSpeculator

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


class VspecDIVSpeculator(VspecBaseSpeculator):
    """ Operand value speculation on division errors """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        # DIV exceptions only
        self._errno_that_trigger_speculation = {21}
