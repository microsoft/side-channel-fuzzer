"""
File: Implementation of the high-level fuzzing logic for model-based constant-time testing.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Optional

from .fuzz_gen import FuzzGen
from .boost import Boost
from .tracer import Tracer
from .leak_detector import LeakDetector
from .reporter import Reporter
from .util import console

if TYPE_CHECKING:
    from .config import Config


class _ReportingScheduler:
    """
    Service class that emits preliminary reports while tracing and leak detection are still in
    progress, so that intermediate results can be inspected without waiting for
    the entire fuzzing campaign to complete.

    Since the results are strictly append-only, the reports are written to the same files
    as the final ones, and are overwritten by every subsequent pass as well as by the final report.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._detector = LeakDetector(config)
        self._detector.prepare_output_dir()
        self._reporter: Optional[Reporter] = None
        self._groups_done = 0

    def on_group_done(self) -> None:
        """
        Count a completed input group and, every `intermediate_report_interval` groups, merge
        the leaks detected so far into a preliminary report.
        """
        self._groups_done += 1
        interval = self._config.intermediate_report_interval
        if interval <= 0 or self._groups_done % interval != 0:
            return

        # Merge without cleanup: leak detection is still in progress, so the .leaks files
        # must be preserved for the subsequent passes and for the final report
        leakage_map = self._detector.merge(cleanup=False)

        # The reporter is created lazily and reused, as it parses the (potentially large) DWARF
        # info of the target binary; it also depends on mappings.txt, which is only written once
        # the tracer has completed its determinism check
        if self._reporter is None:
            self._reporter = Reporter(self._config)
        self._reporter.generate_report(leakage_map)

        console.info(f"Intermediate report written after {self._groups_done} input groups")


class FuzzerCore:
    """
    Class responsible for orchestrating the fuzzing process.
    """
    _config: Config
    _working_dir: str

    def __init__(self, config: Config) -> None:
        self._config = config

    def all(self, timeout_s: int) -> None:
        """
        Run all fuzzing stages: fuzzing-based generation, boosting, tracing, and reporting.

        If `pipeline_trace_and_detect` is enabled, the tracing and leak detection stages are
        pipelined: each group of traces is analysed as soon as it has been collected, and the
        reporting stage is reduced to merging the results.

        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if successful, 1 if error occurs
        """
        self.fuzz_gen(timeout_s)
        self.boost()
        self.trace()
        self.report(0)
        console.success(f"All stages complete. Reports are in {self._config.stage4_wd}")

    def fuzz_gen(self, timeout_s: int) -> None:
        """
        Fuzzing Stage 1:
            Generate diverse inputs via fuzzing

        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        console.section("Stage 1/4: Fuzzing-based input generation")
        fuzz_gen = FuzzGen(self._config)
        fuzz_gen.generate(timeout_s)
        console.success("Input generation complete.")

    def boost(self) -> None:
        """
        Fuzzing Stage 2:
            Boost inputs by generating public-equivalent variants
        :return: 0 if successful, 1 if error occurs
        """
        console.section("Stage 2/4: Input boosting")
        boost = Boost(self._config)
        boost.generate()
        console.success("Input boosting complete.")

    def trace(self) -> None:
        """
        Fuzzing Stage 3:
            Collect contract traces for each input pair.

        If `pipeline_trace_and_detect` is enabled, each group of traces is also analysed for leaks
        as soon as it has been collected, and preliminary reports are emitted along the way.
        """
        if not self._config.pipeline_trace_and_detect:
            console.section("Stage 3/4: Trace collection")
            Tracer(self._config).collect_traces()
            console.success("Trace collection complete.")
            return

        console.section("Stages 3-4/4: Trace collection & leak detection (pipelined)")
        scheduler = _ReportingScheduler(self._config)
        Tracer(self._config).collect_traces(on_group_done=scheduler.on_group_done)
        console.success("Trace collection and leak detection complete.")

    def report(self, num_traces: int) -> None:
        """
        Fuzzing Stage 4:
            Analyze the target binary for software leakage and generate a report.

        If `pipeline_trace_and_detect` is enabled, the leaks have already been detected during
        tracing, and this stage only merges them into the final report.

        :param num_traces: Process only the first N traces (for debugging purposes);
               if 0, process all traces
        """
        console.section("Stage 4/4: Leak analysis & reporting")
        detector = LeakDetector(self._config)
        leakage_map = detector.build_leakage_map(self._config.stage3_wd, num_traces)

        reporter = Reporter(self._config)
        reporter.generate_report(leakage_map)
        console.info(f"Reports written to {self._config.stage4_wd}")
