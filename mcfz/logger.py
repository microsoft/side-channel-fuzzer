"""
File: Module responsible for logging.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations


class Logger:
    """
    Logger class for managing logging operations.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def critical(self, message: str) -> None:
        """Log a critical message with the logger's name."""
        print(f"[CRITICAL] {self._name}: {message}")
        raise SystemExit(1)

    def error(self, message: str) -> None:
        """Log an error message with the logger's name."""
        print(f"[ERROR] {self._name}: {message}")

    def info(self, message: str) -> None:
        """Log an informational message with the logger's name."""
        print(f"[INFO] {self._name}: {message}")
