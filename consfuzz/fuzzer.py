"""
File: Implementation of the high-level fuzzing logic for the software leakage fuzzer.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List

from .pub_gen import PubGen
from .sec_gen import SecGen
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

    def all(self, cmd: List[str], target_cov: int, timeout_s: int, num_sec_inputs: int) -> int:
        """
        Run all fuzzing stages: public input generation, private input generation, and reporting.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :param num_sec_inputs: Number of secret (private) inputs to generate for each public input
        :return: 0 if successful, 1 if error occurs
        """
        if self.generate_public_inputs(cmd, target_cov, timeout_s) != 0:
            return 1
        print("\n")  # Print a newline for better readability in the console output

        if self.stage2(cmd, num_sec_inputs) != 0:
            return 1

        return self.report(cmd[0])

    def generate_public_inputs(self, cmd: List[str], target_cov: int, timeout_s: int) -> int:
        """
        Fuzzing Stage 1:
            Generate public inputs with PubGen.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        pub_gen = PubGen(self._config)
        return pub_gen.generate(cmd, target_cov, timeout_s)

    def stage2(self, cmd: List[str], num_sec_inputs: int) -> int:
        """
        Fuzzing Stage 2:
            Generate private inputs, and collect contract traces for each public-private input pair.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :param num_sec_inputs: Number of secret (private) inputs to generate for each public input
        :return: 0 if successful, 1 if error occurs
        """
        sec_gen = SecGen(self._config)
        tracer = Tracer(self._config)

        sec_gen.generate(num_sec_inputs)
        return tracer.collect_traces(cmd)

    def report(self, target_binary: str) -> int:
        """
        Fuzzing Stage 3:
            Analyze the target binary for software leakage and generate a report.

        :param target_binary: Path to the target binary
        :return: 0 if successful, 1 if error occurs
        """
        reporter = Reporter(self._config)
        reporter.analyze()
        reporter.generate_report(target_binary)
        reporter.process_coverage(target_binary)
        return 0
