"""
File: Implementation of the high-level fuzzing logic for model-based constant-time testing.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List

from .fuzz_gen import FuzzGen
from .boost import Boost
from .tracer import Tracer
from .reporter import Reporter

if TYPE_CHECKING:
    from .config import Config


class FuzzerCore:
    """
    Class responsible for orchestrating the fuzzing process.
    """
    _config: Config
    _working_dir: str

    def __init__(self, config: Config) -> None:
        self._config = config

    def all(self, cmd: List[str], native_bin: str, target_cov: int, timeout_s: int) -> None:
        """
        Run all fuzzing stages: fuzzing-based generation, boosting, tracing, and reporting.

        :param cmd: Command to run the target binary, with placeholders for inputs (@@)
        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if successful, 1 if error occurs
        """
        print("\033[32m[ORCHESTRATOR] Starting fuzzing-based input generation...\033[0m")
        self.fuzz_gen(cmd, target_cov, timeout_s)
        print("\n\033[32m[ORCHESTRATOR] Fuzzing-based input generation completed.\033[0m")
        print("\033[32m[ORCHESTRATOR] Starting input boosting...\033[0m")
        self.boost()
        print("\033[32m[ORCHESTRATOR] Input boosting completed.\033[0m")
        trace_cmd = self._patch_cmd_with_native_bin(cmd, native_bin)
        print("\033[32m[ORCHESTRATOR] Starting tracing...\033[0m")
        self.trace(trace_cmd)
        print("\033[32m[ORCHESTRATOR] Tracing completed.\033[0m")
        print("\033[32m[ORCHESTRATOR] Starting report construction...\033[0m")
        self.report()
        print("\033[32m[ORCHESTRATOR] Report construction completed.\033[0m")

    def fuzz_gen(self, cmd: List[str], target_cov: int, timeout_s: int) -> None:
        """
        Fuzzing Stage 1:
            Generate diverse inputs via fuzzing

        :param cmd: Command to run the target binary, with placeholders for inputs (@@)
        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        fuzz_gen = FuzzGen(self._config)
        fuzz_gen.generate(cmd, target_cov, timeout_s)

    def boost(self) -> None:
        """
        Fuzzing Stage 2:
            Boost inputs by generating public-equivalent variants
        :return: 0 if successful, 1 if error occurs
        """
        boost = Boost(self._config)
        boost.generate()

    def trace(self, cmd: List[str]) -> None:
        """
        Fuzzing Stage 3:
            Collect contract traces for each input pair.

        :param cmd: Command to run the target binary, with placeholders for inputs (@@)
        :return: 0 if successful, 1 if error occurs
        """
        tracer = Tracer(self._config)
        tracer.collect_traces(cmd)

    def report(self) -> None:
        """
        Fuzzing Stage 4:
            Analyze the target binary for software leakage and generate a report.

        :param target_binary: Path to the target binary
        """
        reporter = Reporter(self._config)
        reporter.analyze()
        reporter.generate_report()

    def _patch_cmd_with_native_bin(self, cmd: List[str], native_bin: str) -> List[str]:
        """
        Replace the AFL-built binary in the command with the provided native binary.
        Assumes that the first element in the command is the binary.

        :param cmd: Original command to run the target binary
        :param native_bin: Path to the native binary to use
        :return: Patched command with the native binary
        """
        patched_cmd = cmd.copy()
        patched_cmd[0] = native_bin
        return patched_cmd
