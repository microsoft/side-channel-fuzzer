"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import List, Generator, TYPE_CHECKING
from contextlib import contextmanager
import tempfile
import os

from rvzr.fuzzer import Fuzzer, ArchitecturalFuzzer, ArchDiffFuzzer, FuzzingMode
from rvzr.traces import HTrace
from rvzr.executor import Executor
from rvzr.tc_components.test_case_data import InputData
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.logs import warning
from rvzr.stats import FuzzingStats
from rvzr.config import CONF
from .executor import X86IntelExecutor

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.asm_parser import AsmParser
    from rvzr.elf_parser import ELFParser
    from rvzr.code_generator import CodeGenerator

STAT = FuzzingStats()


# ==================================================================================================
# X86-specific Implementation of the Fuzzer
# ==================================================================================================
class X86Fuzzer(Fuzzer):
    """
    Implementation of the standard fuzzing mode for the x86 architecture.

    Extends the generic Fuzzer class with:
    1. Checking of the instruction set for compatibility with the required faults
    2. Filtering of non-useful test cases with a Speculation Filter and an Observation Filter
    """

    executor: X86IntelExecutor

    # ----------------------------------------------------------------------------------------------
    # Public Interface
    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)

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
        if not CONF.enable_speculation_filter and not CONF.enable_observation_filter:
            return False

        # Number of repetitions for each input
        reps = CONF.executor_filtering_repetitions

        with _quick_and_dirty_mode(self.executor):  # Speed up the execution by disabling some
            # Collect hardware traces for the test case
            try:
                self.executor.load_test_case(test_case)
                org_htraces = self.executor.trace_test_case(inputs, reps)
            except IOError:
                return True

            if self._speculation_filter(org_htraces):
                return True

            if self._observation_filter(test_case, inputs, reps, org_htraces):
                return True

            return False

    @staticmethod
    def _speculation_filter(htraces: List[HTrace]) -> bool:
        """
        Execute on the test case on the HW and monitor PFCs
        if there are no mispredictions, this test case is unlikely
        to produce a violation, so just move on to the next one
        :param htraces: list of HTrace objects collected while executing the test case
        :return: True if the test case should be filtered out; False otherwise
        """
        if not CONF.enable_speculation_filter:
            return False

        for _, htrace in enumerate(htraces):
            pfc_values = htrace.get_max_pfc()
            if pfc_values[0] == 0:  # zero indicates an error; filtering is not possible
                return False
            if pfc_values[0] > pfc_values[1] or pfc_values[2] > 0:
                return False
        STAT.spec_filter += 1
        return True

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
        # pylint: disable=duplicate-code  # justification: intentionally shared with the arm fuzzer

        if not CONF.enable_observation_filter:
            return False

        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_name = fenced.name
        fenced_test_case = _create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                    self.asm_parser, self.code_gen, self.elf_parser)
        try:
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, reps)
        except IOError:
            return True  # skip the test case if there is an error
        os.remove(fenced.name)

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
class X86ArchitecturalFuzzer(ArchitecturalFuzzer):
    """
    X86-specific implementation of the ArchitecturalFuzzer.
    Essentially the same as the generic ArchitecturalFuzzer, but with some additional checks
    on the instruction set
    """

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)


class X86ArchDiffFuzzer(ArchDiffFuzzer):
    """
    Fuzzer that compares the execution of a test case with and without fences.
    If the results differ, it reports a violation.

    Used to detect architectural bugs caused by speculative execution.
    """

    executor: X86IntelExecutor

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        _check_instruction_list(self._isa_spec)
        return super().start(num_test_cases, num_inputs, timeout, nonstop, save_violations, type_)

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        return _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)


# ==================================================================================================
# Helper functions
# ==================================================================================================
def _check_instruction_list(instruction_set: InstructionSet) -> None:
    """ Check if the instruction set contains the instructions required for the faults """
    all_instruction_names = {i.name for i in instruction_set.instructions}
    if 'div-by-zero' in CONF.faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            warning("fuzzer", "div-by-zero enabled, but DIV/IDIV instructions are missing")
    if 'div-overflow' in CONF.faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            warning("fuzzer", "div-overflow enabled, but DIV/IDIV instructions are missing")
    if 'breakpoint' in CONF.faults_allowlist:
        if 'int3' not in all_instruction_names:
            warning("fuzzer", "breakpoint enabled, but INT3 instruction is missing")
    if 'debug-register' in CONF.faults_allowlist:
        if 'int1' not in all_instruction_names:
            warning("fuzzer", "debug-register enabled, but INT1 instruction is missing")


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
            lines = f.readlines()
            n_lines = len(lines)

            for i, line in enumerate(lines):
                fenced_file.write(line)
                line = line.strip().lower()

                # no need to add fences after empty lines and comments
                if not line or line[0] == "#":
                    continue

                # adding a fence after a jump instruction breaks assumptions of our asm parser;
                # this is an issue in the parser, and this check is a workaround
                if line[0] == "j" or "loop" in line:
                    continue

                # don't add fences after assembler directives
                if "section" in line \
                   or "syntax" in line \
                   or "function" in line \
                   or "macro" in line:
                    continue

                # stop adding fences after the test case exit
                if "test_case_exit" in line:
                    break

                # adding a fence before the landing pad will mess with the parsing algorithm,
                # and it won't have any meaningful effect anyways. So we skip it
                if i < n_lines and "landing" in lines[i + 1]:
                    continue

                # add fences after all other instructions
                fenced_file.write('lfence\n')

    fenced_test_case = asm_parser.parse_file(fenced_asm, generator, elf_parser)
    return fenced_test_case
