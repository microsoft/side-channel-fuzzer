"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-instance-attributes
# justification: FIXME pending

from __future__ import annotations

import shutil
import os
import tempfile
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List, Callable, Literal, Final
from typing_extensions import assert_never
import numpy as np

from . import factory

from .traces import HTrace, CTrace, Violation, RawHTraceSample, ArrayOfSamples, CTraceEntry, \
    TraceBundle
from .tc_components.actor import ActorMode
from .tc_components.test_case_code import TestCaseProgram
from .tc_components.test_case_data import InputData
from .isa_spec import InstructionSet
from .analyser import Analyser
from .config import CONF
from .stats import FuzzingStats
from .logs import FuzzLogger, warning, update_logging_after_config_change

if TYPE_CHECKING:
    from .code_generator import CodeGenerator
    from .data_generator import DataGenerator
    from .asm_parser import AsmParser
    from .elf_parser import ELFParser
    from .model import Model
    from .executor import Executor

FuzzingMode = Literal["random", "template", "asm"]
RoundStage = Literal["fast", "nesting", "taint_mistake", "priming", "noise", "arch_mismatch",
                     "priming_large"]

STAT = FuzzingStats()


# ==================================================================================================
# Private: Round Manager
# ==================================================================================================
class _RoundState:
    """
    Collection of configuration options for various modules
    in Revizor that are used in a fuzzing round, and that get updated
    as the round progresses.
    """
    executor_n_reps: int
    """ The number of repetitions to be used by the executor """

    _start_nesting: int
    max_nesting: int
    model_nesting: int
    """ Nesting level to be used by the model """

    enable_fast_contract_tracing: bool
    """ Whether to use the fast boosting feature in the _boost_inputs function """

    enable_priming: bool
    """ Whether to use the priming stage of the fuzzing round """

    record_stats: bool = True
    """ Whether to record statistics in the analyser """

    update_ignore_list: bool = False
    """ Whether to update the ignore list of the executor """

    reuse_boosts: bool = False
    """ Whether to reuse the boosted inputs collected by the previous stage of the round """

    reuse_ctraces: bool = False
    """ Whether to reuse contract traces collected by the previous stage of the round """

    extend_htraces: bool = False
    """ If true, all new collected htraces will be added
    to the existing ones instead of replacing them """

    is_initial: bool = True
    """ Whether this is the first round of the fuzzing process """

    def __init__(self, is_speculative: bool) -> None:
        self.executor_n_reps = CONF.executor_sample_sizes[0]

        self._start_nesting = CONF.model_min_nesting if is_speculative else 1
        self.max_nesting = CONF.model_max_nesting if is_speculative else 1
        assert self._start_nesting <= self.max_nesting
        self.model_nesting = self._start_nesting

        self.enable_fast_contract_tracing = CONF.enable_fast_path_model
        self.enable_priming = CONF.enable_priming


class _RoundManager:
    """
    A helper class responsible for maintaining a consistent configuration throughout
    a fuzzing round, as well as for dispatching the test case to the model and executor.
    """
    test_case: TestCaseProgram
    org_inputs: List[InputData]
    boosted_inputs: List[InputData]

    htraces: List[HTrace]
    _reference_htraces: List[HTrace]

    ctraces: List[CTrace]
    _non_boosted_ctraces: List[CTrace]

    violations: List[Violation]
    arch_violations: List[Violation]

    fuzzer: Final[Fuzzer]
    conf: Final[_RoundState]

    def __init__(self, fuzzer: Fuzzer, test_case: TestCaseProgram, inputs: List[InputData]) -> None:
        self.test_case = test_case
        self.org_inputs = inputs
        self.boosted_inputs = []

        self.htraces = []
        self.ctraces = []
        self.violations = []
        self.arch_violations = []

        self.fuzzer = fuzzer
        self.conf = _RoundState(fuzzer.model.is_speculative)

        self.fuzzer.model.load_test_case(self.test_case)
        self.fuzzer.executor.load_test_case(self.test_case)

    def execute_stage(self, stage: RoundStage) -> None:
        """ Run a given stage of the fuzzing round """
        # pylint: disable=too-many-return-statements,too-many-branches
        # justification: This is a selector function, so the large number of returns is justified

        if stage == "fast":
            assert self.conf.is_initial, "Fast path can be run only in the first round"
            self._normal_stage()
            self.conf.is_initial = False  # make sure that the fast path is run only once
            self.conf.record_stats = False  # record stats only in the fast path
            self._reference_htraces = self.htraces  # use the fast path traces as a reference
            return

        if stage == "nesting":
            if self.conf.model_nesting != self.conf.max_nesting:
                self.conf.model_nesting = self.conf.max_nesting
                self._normal_stage()

            # after this stage, the list of boosted inputs is stable, so we can start reusing
            # them, and we can also start ignoring non-violating inputs in the executor
            self.conf.reuse_boosts = True
            self.conf.update_ignore_list = True
            return

        if stage == "taint_mistake":
            if self.conf.enable_fast_contract_tracing:  # applicable only after fast tracing

                self.conf.enable_fast_contract_tracing = False
                self._normal_stage()

            # after `nesting` and `taint_mistake` stages, we can be confident in contract traces
            # and can start reusing them
            assert self.conf.model_nesting == self.conf.max_nesting, "Invalid stage order"
            self.conf.reuse_ctraces = True
            return

        if stage == "priming":
            if not self.conf.enable_priming:
                return
            self._priming_check()
            return

        if stage == "noise":
            if len(CONF.executor_sample_sizes) == 1:
                return
            self.conf.extend_htraces = True

            for sample_size in CONF.executor_sample_sizes[1:]:
                self.fuzzer.log.sample_size_increase(sample_size)
                self.conf.executor_n_reps = sample_size - len(self.htraces[0])
                self._normal_stage()
                if not self.violations:
                    return
            return

        if stage == "priming_large":
            if not self.conf.enable_priming or len(CONF.executor_sample_sizes) == 1:
                return
            self.conf.executor_n_reps = CONF.executor_sample_sizes[-1]
            self._priming_check()
            return

        if stage == "arch_mismatch":
            self._check_for_architectural_mismatch()
            return

    def finalize(self) -> None:
        """ Finalize the fuzzing round """
        self.fuzzer.log.dbg_dump_traces(self.boosted_inputs, self.htraces, self._reference_htraces,
                                        self.ctraces)

    def _normal_stage(self) -> None:
        """ Run a single stage of the fuzzing round """
        self._boost_inputs()
        self._collect_ctraces()
        try:
            self._collect_htraces()
        except IOError:
            self.violations = []
            return
        if len(self.org_inputs) > 0:
            self._check_violations()
            if not self.violations:
                return
            self._update_ignore_list()

    def _boost_inputs(self) -> None:
        """
        Trace the test case with the original inputs, collect taints, and use them to
        generate boosted inputs
        """
        # no need to taint track if we aren't going to boost
        if CONF.inputs_per_class == 1:
            self._non_boosted_ctraces = \
                self.fuzzer.model.trace_test_case(self.org_inputs, self.conf.model_nesting)
            self.boosted_inputs = self.org_inputs
            return

        # Normal case - boost the inputs
        self._non_boosted_ctraces, taints = \
            self.fuzzer.model.trace_test_case_with_taints(self.org_inputs, self.conf.model_nesting)
        self.boosted_inputs = self.fuzzer.data_gen.generate_boosted(self.org_inputs, taints,
                                                                    CONF.inputs_per_class)

    def _collect_ctraces(self) -> None:
        """ Collect contract traces for the boosted inputs """
        # contract traces are already collected
        if self.conf.reuse_ctraces:
            assert len(self.ctraces) == len(self.boosted_inputs), "No ctraces to reuse"
            return

        # records same ctrace for all members of the same input class
        if self.conf.enable_fast_contract_tracing:
            self.ctraces = self._non_boosted_ctraces * CONF.inputs_per_class
            return

        # compute ctraces separately for every boosted input
        self.ctraces = \
            self.fuzzer.model.trace_test_case(self.boosted_inputs, self.conf.model_nesting)

    def _collect_htraces(self) -> None:
        """ Collect hardware traces for the boosted inputs """
        new_htraces = self.fuzzer.executor.trace_test_case(self.boosted_inputs,
                                                           self.conf.executor_n_reps)
        if not self.conf.extend_htraces:
            self.htraces = new_htraces
            return

        # Merge new htraces with the existing ones
        assert len(self.htraces) == len(new_htraces), "Number of htraces does not match"
        for i, htrace in enumerate(new_htraces):
            self.htraces[i] = htrace.merge(self.htraces[i])

    def _check_violations(self) -> None:
        """ Check the collected traces for contract violations """
        assert self.ctraces and len(self.ctraces) == len(self.htraces), \
            f"Invalid number of c- or htraces: {len(self.ctraces)} vs {len(self.htraces)}"
        self.violations = self.fuzzer.analyser.filter_violations(
            ctraces=self.ctraces,
            htraces=self.htraces,
            test_case_code=self.test_case,
            inputs=self.boosted_inputs,
            stats_=self.conf.record_stats)

    def _update_ignore_list(self) -> None:
        """
        Label all non-violating inputs as ignored by executor, so that we don't trigger
        a chain reaction of false positives when the measurement results are non-deterministic
        """
        if self.conf.update_ignore_list:
            violating_ids = [m.input_id for v in self.violations for m in v.measurements]
            ignored_input_ids = [
                i for i in range(len(self.boosted_inputs)) if i not in violating_ids
            ]
            self.fuzzer.executor.extend_ignore_list(ignored_input_ids)

    def _priming_check(self) -> None:
        """
        Perform a priming check, as described next.

        Goal: Distinguish between violations caused by input data leaks and those caused by
        cross-talk between inputs.

        Approach: The priming check swaps the inputs that caused the violation with each other and
        checks if the violation is still present. If the violation is still present, it is a genuine
        violation; otherwise, it is a false positive.

        Example: Given a violation caused by an input sequence (i1, i2, i1', i2'), where inputs
        i2 and i2' produce the same contract trace but different hardware traces, hence causing a
        violation. The violation could be caused either by the difference in the input data of
        i2 vs i2', or it could be caused by the difference in the microarchitectural state
        created by i1 vs i1'. The former is a genuine violation, while the latter is a false
        positive.

        To distinguish between the two, the priming check creates two new sequences:
        (i1, i2', i1', i2') and (i1, i2, i1', i2).

        If the trace produced by the first instance of i2' in the first sequence matches
        the trace produced by i2' in the original sequence, AND
        the trace produced by the second instance of i2 in the second sequence matches
        the trace produced by i2 in the original sequence,
        then the violation is genuine.
        """

        while self.violations:
            self.fuzzer.log.priming(len(self.violations))

            violation: Violation = self.violations.pop()
            n_reps = violation.measurements[0].htrace.sample_size()
            measurements_to_test = [hc[0] for hc in violation.get_hw_classes()]

            for current_measurement in measurements_to_test:
                current_input_id = current_measurement.input_id
                htrace_to_reproduce = current_measurement.htrace
                other_measurements = [m for m in measurements_to_test if m != current_measurement]

                # list of inputs that produced a different HTrace
                input_ids_to_test: List[int] = [m.input_id for m in other_measurements]

                # iterate over inputs in the violation and swap them with current_input_id
                for input_id in input_ids_to_test:
                    self.fuzzer.log.dbg_priming_progress(input_id, current_input_id)

                    # insert the tested input into its new place
                    primer = list(self.boosted_inputs)
                    primer[current_input_id] = self.boosted_inputs[input_id]

                    # try the new input sequence and check if the traces observed for the new input
                    # are equivalent to the original ones
                    htraces: List[HTrace] = self.fuzzer.executor.trace_test_case(primer, n_reps)
                    new_htrace = htraces[current_input_id]

                    # fast exit in case of a tracing error
                    if new_htrace.is_empty() or new_htrace.is_corrupted_or_ignored():
                        warning("fuzzer", "Tracing error during priming. "
                                "Skipping this test case")
                        self.violations = []
                        return

                    if self.fuzzer.analyser.htraces_are_equivalent(new_htrace, htrace_to_reproduce):
                        continue

                    self.fuzzer.log.dbg_priming_fail(input_id, current_input_id,
                                                     htrace_to_reproduce, new_htrace)

                    # could not reproduce; it's a genuine violation
                    self.violations = [violation]
                    return

            # all traces were reproduced, so it's a false positive
            self.violations = []
            return

    def _check_for_architectural_mismatch(self) -> None:
        """
        Check if the given test cases causes an architectural mismatch between the model
        and the executor. For example, this may happen if the model incorrectly emulates the
        execution of an instruction due to a bug in the emulator.
        """
        hardware_regs: List[List[int]] = []
        model_regs: List[List[int]] = []

        self.fuzzer.arch_model.load_test_case(self.test_case)
        self.fuzzer.arch_executor.load_test_case(self.test_case)

        # This function may be called standalone (see ArchitecturalFuzzer),
        # in which case boosted_inputs are not yet set
        if not self.boosted_inputs:
            self.boosted_inputs = self.org_inputs

        # Collect architectural hardware traces
        try:
            htraces = self.fuzzer.arch_executor.trace_test_case(self.boosted_inputs, n_reps=1)
        except IOError:
            warning("fuzz", "Error during architectural mismatch check. Skipping this test case")
            self.arch_violations = []  # skip test case in case of a tracing error
            return
        for htrace_obj in htraces:
            raw_traces = htrace_obj.get_raw_readings()
            assert len(raw_traces) == 1, "Expected only one hardware trace"
            raw_trace_int = [int(v) for v in raw_traces[0]]
            hardware_regs.append(raw_trace_int)

        # Collect architectural model traces
        ctraces = self.fuzzer.arch_model.trace_test_case(self.boosted_inputs,
                                                         CONF.model_max_nesting)
        for ctrace in ctraces:
            model_regs.append([v % (2**64) for v in ctrace.get_untyped()[:6]])

        # Debug outputs
        self.fuzzer.log.dbg_dump_architectural_traces(hardware_regs, model_regs)

        # Check for violations
        # Note: since we simply check the equality of traces, we don't need to invoke the analyser
        for i, input_ in enumerate(self.boosted_inputs):
            if model_regs[i] == hardware_regs[i]:
                continue
            measurement = TraceBundle(i, input_, ctraces[i], htraces[i])
            violation = Violation([measurement], self.boosted_inputs, self.test_case)
            violation.set_trivial_hw_classes()
            self.arch_violations = [violation]
            return
        return


# ==================================================================================================
# Public: Fuzzer
# ==================================================================================================
class Fuzzer:
    """
    The main class that orchestrates the fuzzing process. It creates all necessary modules
    and takes care of invoking them in the right order and passing the data between them.

    The main interface to start fuzzing is the `start` method, which implements a multi-stage
    algorithm to detect contract violations. The method implements the core fuzzing loop, which
    is to generate a test case, prepare inputs, collect their traces, and check for violations.

    The class also provides a set of stand-alone interfaces for generating test cases, analyzing
    traces from files, and filtering out non-useful test cases.
    """

    model: Model
    executor: Executor
    asm_parser: AsmParser
    code_gen: CodeGenerator
    data_gen: DataGenerator
    analyser: Analyser
    elf_parser: ELFParser

    arch_executor: Executor
    arch_model: Model
    log: FuzzLogger

    _isa_spec: InstructionSet
    _existing_test_case: str
    _work_dir: str
    _input_paths: List[str]
    _generation_function: Callable[[str], TestCaseProgram]
    _taint_bug_seen: bool = False

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 input_paths: Optional[List[str]] = None):
        self._adjust_config(existing_test_case)

        self._existing_test_case = existing_test_case
        self._input_paths = input_paths if input_paths is not None else []
        self._work_dir = work_dir

        # Create all main modules
        self.log = FuzzLogger()
        constraints = factory.get_instruction_pool_constraints()
        self._isa_spec = InstructionSet(instruction_set_spec, CONF.instruction_categories,
                                        constraints)
        self.code_gen = factory.get_program_generator(CONF.program_generator_seed, self._isa_spec)
        self.data_gen = factory.get_data_generator(CONF.data_generator_seed)
        self.executor = factory.get_executor()
        self.model = factory.get_model(self.executor.read_base_addresses())
        self.analyser = factory.get_analyser()
        self.asm_parser = factory.get_asm_parser(self._isa_spec)
        self.elf_parser = factory.get_elf_parser()

        self.arch_executor = factory.get_executor(enable_mismatch_check_mode=True)
        self.arch_model = factory.get_model(
            self.arch_executor.read_base_addresses(), enable_mismatch_check_mode=True)

    # ==============================================================================================
    # Fuzzing Interface
    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
              save_violations: bool, type_: FuzzingMode) -> bool:
        """
        Start the fuzzing process with the given parameters.
        :param num_test_cases: the number of test cases to be generated
        :param num_inputs: the number of inputs to be generated for each test case
        :param timeout: the maximum time (in seconds) to run the fuzzer
        :param nonstop: whether to continue the fuzzing process after the first violation
        :param save_violations: whether to store the violation artifacts
        :param type_: the type of fuzzing to be performed (random, template, asm)
        :return: True if at least one violation was detected, False otherwise
        """
        # Print header
        start_time = datetime.today()
        self.log.start(num_test_cases, start_time)

        # Find an appropriate generation function
        self._set_generation_function(type_)

        # Start the fuzzing loop
        for i in range(num_test_cases):
            self.log.start_round(i)

            # Generate a test case
            test_case: TestCaseProgram = self._generation_function(self._existing_test_case)
            STAT.test_cases += 1

            # Prepare inputs
            inputs: List[InputData]
            if self._input_paths:
                inputs = self.data_gen.load(self._input_paths)
            else:
                inputs = self.data_gen.generate(num_inputs, n_actors=test_case.n_actors())
            STAT.num_inputs += len(inputs) * CONF.inputs_per_class

            # Check if the test case is useful
            if self._filter(test_case, inputs):
                continue

            # Fuzz the test case
            violation = self.fuzzing_round(test_case, inputs, [])
            if violation:
                self.log.report_violations(violation)
                self.log.dbg_violation(violation, self.model)
                if save_violations:
                    self._store_violation_artifact(violation, self._work_dir)
                STAT.violations += 1
                if not nonstop:
                    break

            # Terminate the fuzzer if the timeout has expired
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    self.log.timeout()
                    break

        self.log.finish()
        self.log.report_model_coverage(self.model)
        return STAT.violations > 0

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      starting_ignore_list: List[int]) -> Optional[Violation]:
        """
        Run a single fuzzing round: collect contract and hardware traces for the given test
        case and inputs, and check for contract violations.

        The function is typically used as a part of the fuzzing loop
        (invoked by .start), but can be also used stand-alone by other classes.

        The function implements a multi-stage approach to testing, with the first measurement being
        fast but with a chance of false positives, and the later stages filtering out various
        types of potential false positives. The exact number of stages depends on
        the configuration.

        :param test_case: the test case to be executed
        :param inputs: the inputs to be tested
        :param starting_ignore_list: a list of input IDs to be ignored by the executor
        :return: the first detected violation or None if no violations were found
        """
        # pylint: disable=too-many-return-statements
        # justification: multi-stage check that returns early at each stage

        # Initialize the round manager and load the test case
        round_manager = _RoundManager(self, test_case, inputs)

        # If a list of ignored inputs is provided, set it in the executor
        if starting_ignore_list:
            self.executor.set_ignore_list(starting_ignore_list)

        # 1. Fast path: Collect traces with minimal nesting and repetitions
        round_manager.execute_stage("fast")
        if not round_manager.violations:
            STAT.fast_path += 1
            round_manager.finalize()
            return None

        # 2. Slow path: Go through potential sources of false violations in the fast path,
        #    and check them one at a time, starting with the most likely ones
        self.log.slow_path()

        # 2.1 FP might appear because the model did not go deep enough into nested speculation.
        #     To remove such FPs, we re-run the model tracing with max nesting. As taints depend on
        #     contract traces, we also have to re-boost the inputs, and re-collect hardware traces
        #     for the new inputs
        round_manager.execute_stage("nesting")
        if not round_manager.violations:
            STAT.fp_nesting += 1
            round_manager.finalize()
            return None

        # 2.2 FP might appear because of imperfect tainting (e.g., due to a bug in taint tracker).
        #     To remove such FPs, we collect contract traces for all boosted inputs, and check if
        #     the violation is still present
        prev_ctraces = list(round_manager.ctraces)
        round_manager.execute_stage("taint_mistake")
        if round_manager.ctraces != prev_ctraces:  # this triggers on taint analysis bugs
            self._report_bug_tainting(round_manager)
        if not round_manager.violations and round_manager.ctraces != prev_ctraces:
            STAT.fp_taint_mistakes += 1  # separate branch because not all tain bugs are violations
        if not round_manager.violations:
            round_manager.finalize()
            return None

        # 2.3 FP might appear because of interference between inputs. To remove such FPs, we
        #     use the priming test where we swap inputs that caused the violation with each other
        round_manager.execute_stage("priming")
        if not round_manager.violations:
            STAT.fp_priming += 1
            round_manager.finalize()
            return None

        # 2.4 FP might appear because we experienced noise. Retry the experiment with a larger
        #     sample size to reduce the impact of noise
        round_manager.execute_stage("noise")
        if not round_manager.violations:
            STAT.fp_large_sample += 1
            return None

        # 2.5 Priming might have failed because the sample size was too small, causing
        #     non-deterministic results. Retry the priming test with the largest sample size
        round_manager.execute_stage("priming_large")
        if not round_manager.violations:
            STAT.fp_priming += 1
            round_manager.finalize()
            return None

        # 2.6 FP might appear because of a mismatch between the model and the executor.
        # Such cases are rare, hence we check for them last.
        # To remove such FPs, we check if the violation is caused by an architectural mismatch
        round_manager.execute_stage("arch_mismatch")
        if round_manager.arch_violations:
            self._report_bug_arch(round_manager)
            round_manager.finalize()
            return None

        # Violation survived all checks. Report it
        round_manager.finalize()
        return round_manager.violations[0]

    # ==============================================================================================
    # Single-stage Interfaces
    def standalone_filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """ Check if the given test case should be filtered out """
        return self._filter(test_case, inputs)

    def standalone_generate(self, program_generator_seed: int, num_test_cases: int, num_inputs: int,
                            permit_overwrite: bool) -> None:
        """
        Run a standalone test case generation and store the generated test case programs
        and their inputs in the work directory
        """
        self.log.start(0, datetime.today())

        # prepare for generation
        STAT.test_cases = num_test_cases
        CONF.program_generator_seed = program_generator_seed
        program_gen = factory.get_program_generator(CONF.program_generator_seed, self._isa_spec)
        data_gen = factory.get_data_generator(CONF.data_generator_seed)

        # generate test cases
        Path(self._work_dir).mkdir(exist_ok=True)
        for i in range(0, num_test_cases):
            test_case_dir = self._work_dir + "/tc" + str(i)
            try:
                Path(test_case_dir).mkdir(exist_ok=permit_overwrite)
            except FileExistsError:
                raise FileExistsError(f"Directory '{test_case_dir}' already exists\n"
                                      "       Use --permit-overwrite to overwrite the test case")

            program_gen.create_test_case(test_case_dir + "/" + "program.asm", True)
            inputs = data_gen.generate(num_inputs, n_actors=1)
            for j, input_ in enumerate(inputs):
                input_.save(f"{test_case_dir}/input{j}.bin")

        self.log.finish()

    def standalone_analyse(self, ctrace_file: str, htrace_file: str) -> None:
        """ Check the contract and hardware traces in the given files for contract violations """
        if "dbg_violation" in CONF.logging_modes:
            CONF.logging_modes.remove("dbg_violation")
            update_logging_after_config_change()

        self.log.start(0, datetime.today())
        STAT.test_cases = 1

        # read traces
        ctraces: List[CTrace] = []
        htraces: List[HTrace] = []

        with open(ctrace_file, 'r') as f:
            for line in f:
                ctraces.append(CTrace([CTraceEntry("val", int(line))]))
        with open(htrace_file, 'r') as f:
            for line in f:
                sample: ArrayOfSamples = np.ndarray(1, dtype=RawHTraceSample)
                sample[0]['trace'] = int(line)
                htraces.append(HTrace(sample))

        assert len(ctraces) == len(htraces), \
            "The number of hardware traces does not match the number of contract traces"

        dummy_inputs = factory.get_data_generator(0).generate(len(ctraces), n_actors=1)
        dummy_tc = TestCaseProgram("generated.asm", 0)

        # check for violations
        analyser = factory.get_analyser()
        violations = analyser.filter_violations(ctraces, htraces, dummy_tc, dummy_inputs, True)

        # print results
        if violations:
            self.log.report_violations(violations[0])

        self.log.finish()

    # ==============================================================================================
    # Private Methods
    def _set_generation_function(self, type_: FuzzingMode) -> None:
        """ Set the generation function based on the fuzzing mode """
        if type_ == "random":
            self._generation_function = self.code_gen.create_test_case
        elif type_ == "template":
            self._generation_function = self.code_gen.create_test_case_from_template
        elif type_ == "asm":
            self._generation_function = self._asm_parser_adapter
        else:
            assert_never(f"Unknown fuzzing mode: {type_}")

    @staticmethod
    def _create_timestamped_dir(path: str, prefix: str = "violation") -> str:
        parent = Path(path)
        parent.mkdir(exist_ok=True)

        timestamp = datetime.today().strftime('%y%m%d-%H%M%S')
        new_dir = parent / f"{prefix}-{timestamp}"

        # if the directory already exists, append a counter to keep the name unique
        counter = 1
        while new_dir.exists():
            new_dir = parent / f"{prefix}-{timestamp}-{counter}"
            counter += 1

        new_dir.mkdir()
        return str(new_dir)

    def _store_violation_artifact(self, violation: Violation, path: str) -> None:
        """
        Store a violation artifact into the given directory.

        A violation artifact consists of:
        - the test case that caused the violation (program.asm)
        - the inputs that caused the violation (input_*.bin)
        - the original configuration file (org-config.yaml)
        - the configuration file for reproducing violation from artifact (reproduce.yaml)
        - the configuration file for minimization (minimize.yaml)

        :param violation: the violation to be stored
        :param path: the path to the directory where the artifact should be stored;
                    if empty, the artifact is stored in the current directory
        """
        # if the path is empty, store the artifact in the current directory
        if not path:
            path = "."

        # create a subdirectory for the violation artifact
        violation_dir = self._create_timestamped_dir(path)

        # store violation
        test_case = violation.test_case_code
        test_case.save(f"{violation_dir}/program.asm")
        for i, input_ in enumerate(violation.input_sequence):
            input_.save(f"{violation_dir}/input_{i:04}.bin")

        # store the original configuration file
        if CONF._config_path:
            shutil.copy2(CONF._config_path, f"{violation_dir}/org-config.yaml")
        else:
            with open(f"{violation_dir}/org-config.yaml", "w") as f:
                f.write("# Original violation used a default config, hence this file is empty\n")

        # create patched configs for reproducing and minimizing the violation
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/reproduce.yaml")
        with open(f"{violation_dir}/reproduce.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"data_generator_seed: {violation.input_sequence[0].seed}\n")
            f.write("inputs_per_class: 1\n")
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/minimize.yaml")
        with open(f"{violation_dir}/minimize.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"data_generator_seed: {violation.input_sequence[0].seed}\n")

        # we're about to store stats into a file - disable colors
        color_on = CONF.color
        CONF.color = False

        # store the violation report
        with open(f"{violation_dir}/report.txt", "w") as f:
            f.write("# Violation Report\n\n")
            f.write(f"* Test Case ID: {STAT.test_cases - 1}\n")
            f.write(f"* Detected: {datetime.today().strftime('%d.%m.%y at %H:%M:%S')}\n\n")
            f.write("* Time to detection:"
                    f" {(datetime.today() - self.log.start_time).total_seconds()}\n")
            f.write("* Statistics:\n")
            f.write(str(STAT) + "\n")

            f.write("\n## Generation Properties\n")
            f.write(f"* Program seed: {test_case.generator_seed}\n")
            f.write(f"* Input seed: {violation.input_sequence[0].seed}\n")
            f.write("* Faulty page properties:\n")
            target_desc = self.code_gen._target_desc
            for actor in test_case.get_actors(sorted_=True):
                actor_id = actor.get_id()
                f.write(f"  - Actor {actor_id}:\n")

                pte_fields = []
                for field in target_desc.pte_bits:
                    offset, default = target_desc.pte_bits[field]
                    value = bool(actor.data_properties & (1 << offset))
                    if value != default:
                        pte_fields.append(f"{field}={value}")
                f.write(f"    * PTE: {'; '.join(pte_fields)}\n")

                if actor.mode != ActorMode.GUEST:
                    continue
                vm_pte_fields = []
                for field in target_desc.vm_pte_bits:
                    offset, default = target_desc.vm_pte_bits[field]
                    value = bool(actor.data_ept_properties & (1 << offset))
                    if value != default:
                        vm_pte_fields.append(f"{field}={value}")
                f.write(f"    * EPTE: {'; '.join(vm_pte_fields)}\n")

            f.write("\n## Counterexample Inputs\n")
            for m in violation.measurements:
                f.write(f"\nInput #{m.input_id}\n")
                f.write(f"* Hardware trace:\n {m.htrace.full_str()}\n")
                f.write(f"* Contract trace (hash): {m.ctrace}\n")
                f.write(f"* Contract trace (detailed): {m.ctrace.full_str()}\n")

        # re-enable colors if enabled previously
        CONF.color = color_on

    def _report_bug_tainting(self, round_manager: _RoundManager) -> None:
        warning("fuzzer", "Fast path contract traces do not match the full traces")
        if not self._work_dir or not CONF.is_generation_enabled():
            return

        # only store the artifact for the first occurrence; subsequent saves are near-identical
        # and carry no additional diagnostic value, so we skip them to avoid wasting disk space
        if self._taint_bug_seen:
            return
        self._taint_bug_seen = True

        # note that we don't use _store_violation_artifact here because there is no actual
        # violation - we just want to store the test case and inputs
        bugs_dir = f"{self._work_dir}/bugs"
        warning("fuzzer", f"Storing the bug into {bugs_dir}/")
        bug_dir = self._create_timestamped_dir(bugs_dir, prefix="taint-bug")
        round_manager.test_case.save(f"{bug_dir}/program.asm")
        for i, input_ in enumerate(round_manager.org_inputs):
            input_.save(f"{bug_dir}/input_{i:04}.bin")

    def _report_bug_arch(self, round_manager: _RoundManager) -> None:
        warning("fuzzer", "Architectural mismatch between model and executor detected")
        if not self._work_dir or not CONF.is_generation_enabled():
            return
        warning("fuzzer", f"Storing the bug into {self._work_dir}/bugs/")
        self._store_violation_artifact(round_manager.violations[0], f"{self._work_dir}/bugs/")

    # ----------------------------------------------------------------------------------------------
    # Private: Subclass hooks for ISA-specific customization
    def _filter(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        A filter function that can be used to check if a test case is not useful.

        The function is typically used as a part of the fuzzing loop
        (invoked by self.start_* methods), but can be also used stand-alone by other classes.

        :param test_case: The test case to be checked
        :param inputs: The inputs to be used with the test case
        :return: True if the test case should be filtered out (not useful), False otherwise (useful)
        """
        return False  # implemented by architecture-specific subclasses

    def _adjust_config(self, _: str) -> None:
        """ Adjust the configuration based on the given test case """

    def _asm_parser_adapter(self, asm: str) -> TestCaseProgram:
        # FIXME: this is a hack to fit the interface; refactor this
        return self.asm_parser.parse_file(asm, self.code_gen, self.elf_parser)


class ArchitecturalFuzzer(Fuzzer):
    """
    A simplified fuzzer that checks for architectural mismatches between the model and the
    executor. This fuzzer is useful for detecting bugs in Revizor, but it cannot detect
    contract violations.

    The fuzzer piggy-backs on the check_for_architectural_mismatch function of Fuzzer
    to check for mismatches.
    """

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: Optional[List[str]] = None):
        super().__init__(instruction_set_spec, work_dir, existing_test_case, inputs)
        warning("fuzzer", "Running in architectural mode. "
                "Contract violations can't be detected!")

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      _: List[int]) -> Optional[Violation]:
        """
        Run a single fuzzing round: collect contract and hardware traces for the given test
        case and inputs, and check for architectural mismatches.
        """
        round_manager = _RoundManager(self, test_case, inputs)
        round_manager.execute_stage("arch_mismatch")
        return round_manager.arch_violations[0] if round_manager.arch_violations else None


class ArchDiffFuzzer(Fuzzer):
    """
    Fuzzer that compares the execution of a test case with and without speculation fences.
    If the results differ, it reports a violation.

    Used to detect architectural bugs caused by speculative execution.
    """

    def fuzzing_round(self, test_case: TestCaseProgram, inputs: List[InputData],
                      _: List[int]) -> Optional[Violation]:
        # collect non-fenced traces
        self.arch_executor.load_test_case(test_case)
        reg_values: List[List[int]] = []
        try:
            htraces: List[HTrace] = self.arch_executor.trace_test_case(inputs, 1)
        except IOError:
            return None
        for htrace in htraces:
            reg_values.append(htrace.get_raw_readings()[0].tolist())

        # collect fenced traces
        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_name = fenced.name
        fenced_test_case = self._create_fenced_test_case(test_case.asm_path(), fenced_name,
                                                         self.asm_parser, self.code_gen,
                                                         self.elf_parser)
        self.arch_executor.load_test_case(fenced_test_case)
        fenced_reg_values: List[List[int]] = []
        try:
            htraces = self.arch_executor.trace_test_case(inputs, 1)
        except IOError:
            return None
        for htrace in htraces:
            fenced_reg_values.append(htrace.get_raw_readings()[0].tolist())
        os.remove(fenced_name)

        for i, input_ in enumerate(inputs):
            if fenced_reg_values[i] == reg_values[i]:
                if "dbg_dump_htraces" in CONF.logging_modes:
                    print(f"Input #{i}")
                    print(f"Fenced:       {list(fenced_reg_values[i])}")
                    print(f"Non-fenced:   {list(reg_values[i])}")
                continue

            if "dbg_violation" in CONF.logging_modes:
                print(f"Input #{i}")
                print(f"Fenced:       {list(fenced_reg_values[i])}")
                print(f"Non-fenced:   {list(reg_values[i])}")

            return Violation.pseudo_violation_from_inputs([input_], test_case)
        return None

    @staticmethod
    def _create_fenced_test_case(original_asm: str, fenced_asm: str, asm_parser: AsmParser,
                                 generator: CodeGenerator,
                                 elf_parser: ELFParser) -> TestCaseProgram:
        """
        Hook function to create a test case with speculation fences."
        Must be implemented by ISA-specific subclasses that know what a fence looks like for
        their architecture.
        """

        raise NotImplementedError("This method should be implemented by the subclass")
