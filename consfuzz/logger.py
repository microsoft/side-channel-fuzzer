"""
File: Module responsible for logging.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations


class ProgressBar:
    """
    Customizable progress bar for tracking the progress of fuzzing stages.
    """

    def __init__(self, total: int, name: str) -> None:
        self._name = name
        self._total = total
        self._current = 0

    def start(self) -> None:
        """Initialize the progress bar."""
        print(f"{self._name:20} [{'_' * 50}] 0/{self._total} (00.00%)", end="", flush=True)

    def update(self, increment: int = 1) -> None:
        """Update the progress bar by a given increment."""
        self._current += increment
        percent = (self._current / self._total) * 100
        n_ticks = int(percent // 2)  # 50 ticks for 100%
        print(
            f"\r{self._name:20} [{'#' * n_ticks}{'_' * (50 - n_ticks)}] "
            f"{self._current}/{self._total} "
            f"({percent:2.2f}%)",
            end="",
            flush=True)
        if self._current >= self._total:
            print("")  # Print a newline when the progress bar is complete
