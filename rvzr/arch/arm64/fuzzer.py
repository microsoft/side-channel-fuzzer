"""
File: arm64 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Generator
from contextlib import contextmanager
import tempfile
import os

from rvzr.fuzzer import Fuzzer, ArchitecturalFuzzer, ArchDiffFuzzer
from rvzr.traces import HTrace
from rvzr.tc_components.test_case_data import InputData
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.stats import FuzzingStats
from rvzr.config import CONF
from .executor import ARM64Executor

if TYPE_CHECKING:
    from rvzr.asm_parser import AsmParser
    from rvzr.elf_parser import ELFParser
    from rvzr.code_generator import CodeGenerator
    from rvzr.executor import Executor

STAT = FuzzingStats()


# ==================================================================================================
# ARM64-specific Implementation of the Fuzzer
# ==================================================================================================
class ARM64Fuzzer(Fuzzer):
    """
    Implementation of the standard fuzzing mode for the arm64 architecture.

    Extends the generic Fuzzer class with:
    1. Checking of the instruction set for compatibility with the required faults
    2. Filtering of non-useful test cases with a Speculation Filter and an Observation Filter
    """

    executor: ARM64Executor

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    def _filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        This function implements a multi-stage algorithm that gradually filters out
        uninteresting test cases

        :param test_case: the target test case
        :param inputs: list of inputs to be tested
        :return: True if the test case should be filtered out; False otherwise
        """
        # Exit if all filters are disabled
        if not CONF.enable_observation_filter:
            return False

        # Number of repetitions for each input
        reps = CONF.executor_filtering_repetitions

        with _quick_and_dirty_mode(self.executor):  # Speed up the execution by disabling checks
            # Collect hardware traces for the test case
            try:
                self.executor.load_test_case(test_case)
                org_htraces = self.executor.trace_test_case(inputs, reps)
            except IOError:
                return True

            if self._observation_filter(test_case, inputs, reps, org_htraces):
                return True

            return False

    def _observation_filter(self, test_case: TestCaseProgram, inputs: List[InputData], reps: int,
                            org_htraces: List[HTrace]) -> bool:
        """
        Check if any of the htraces contain a speculative cache eviction
        for this create a fenced version of the test case and collect traces for it
        :param test_case: the target test case
        :param inputs: list of inputs to be tested
        :param reps: number of repetitions for each input
        :param org_htraces: list of HTrace objects collected while executing the test case
        :return: True if the test case should be filtered out; False otherwise
        """
        # pylint: disable=duplicate-code  # justification: intentionally shared with the x86 fuzzer

        if not CONF.enable_observation_filter:
            return False

        with tempfile.NamedTemporaryFile(suffix=".asm", delete=False) as fenced:
            fenced_name = fenced.name
        try:
            fenced_test_case = _create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                        self.asm_parser, self.code_gen,
                                                        self.elf_parser)
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, reps)
        except IOError:
            return True  # skip the test case if there is an error
        finally:
            # remove the fenced asm file and the files derived from it by parse_file
            for path in (fenced_name, fenced_name + ".patched.asm", fenced_name[:-4] + ".o"):
                if os.path.exists(path):
                    os.remove(path)

        traces_match = True
        for i, _ in enumerate(inputs):
            if not self.analyser.htraces_are_equivalent(fenced_htraces[i], org_htraces[i]):
                traces_match = False
                break
        if traces_match:
            STAT.observ_filter += 1
            return True

        return False


# ==================================================================================================
# Non-standard Fuzzers
# ==================================================================================================
class ARM64ArchitecturalFuzzer(ArchitecturalFuzzer):
    """
    ARM64-specific implementation of the ArchitecturalFuzzer.
    """
    # No ARM64-specific implementation is needed


class ARM64ArchDiffFuzzer(ArchDiffFuzzer):
    """
    ARM64-specific implementation of the ArchDiffFuzzer.
    """

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        return _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)


# ==================================================================================================
# Helper functions
# ==================================================================================================
@contextmanager
def _quick_and_dirty_mode(executor: Executor) -> Generator[None, None, None]:
    """
    Context manager that enables us to use quick and dirty mode in the form of `with` statement
    """
    try:
        executor.set_quick_and_dirty(True)
        yield
    finally:
        executor.set_quick_and_dirty(False)


def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                             generator: CodeGenerator, elf_parser: ELFParser) -> TestCaseProgram:
    """ Add fences to all instructions in the test case """
    with open(original_asm, 'r') as f:
        with open(fenced_asm, 'w') as fenced_file:
            for line in f:
                fenced_file.write(line)
                line = line.strip().lower()

                # no need to add fences after empty lines and comments
                if not line or line[0] == "/":
                    continue

                # don't add fences after assembler directives or macros
                if line[0] == "." or "macro" in line:
                    continue

                # adding a fence after a control-flow instruction breaks assumptions of our asm
                # parser (a terminator must be the last instruction of a basic block); this is an
                # issue in the parser, and this check is a workaround
                mnemonic = line.split()[0]
                if mnemonic[0] == "b" or mnemonic in ("cbz", "cbnz", "tbz", "tbnz", "ret"):
                    continue

                # add fences after all other instructions
                fenced_file.write('dsb SY\n isb\n')
    fenced_test_case = asm_parser.parse_file(fenced_asm, generator, elf_parser)
    return fenced_test_case
