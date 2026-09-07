"""
File: Module responsible for collecting contract traces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Callable, List, Final, Dict, Optional, Tuple

import os
import subprocess
from pathlib import Path

from rvzr.model_dynamorio.trace_decoder import TraceDecoder
from .leak_detector import LeakDetector
from .util.logger import Logger
from .util.compressor import Compressor
from .util.worker_pool import send_to_worker_pool
from .util import console

if TYPE_CHECKING:
    from .config import Config

DirName = str
FileName = str
FilePath = str
WorkDirMap = Dict[DirName, List[FileName]]

TemplateCmd = List[str]
ExpandedCmd = str


class ProgramException(Exception):
    """ Exception raised when the target program throws an exception during execution. """


class InstrException(Exception):
    """ Exception raised when the instrumentation throws an exception during execution """


class UnknownExecutionException(Exception):
    """ Exception raised when an unknown error occurs during execution. """


class Tracer:
    """
    Class responsible for executing the target binary on the leakage model and retrieving the
    collected contract traces.
    """

    _drrun_cmd: Final[str]
    _log: Final[Logger]

    def __init__(self, config: Config) -> None:
        self._log = Logger("Tracer")
        self._compressor = Compressor(config)

        # In pipelined mode, each group of traces is analysed for leaks as soon as it has been
        # collected, so the tracer needs its own leak detector
        self._detector = LeakDetector(config) if config.pipeline_trace_and_detect else None

        self._config = config
        cmd = f"{config.model_root}/drrun " \
            f"-c {config.model_root}/libdr_model.so " \
            f"--instrumented-func {config.tracing_entrypoint} " \
            f"--tracer {config.contract_observation_clause} " \
            f"--speculator {config.contract_execution_clause} "
        if config.tracing_ignorelist is not None:
            cmd += f"--ignorelist {config.tracing_ignorelist} "
        if config.max_spec_window is not None:
            cmd += f"--max-spec-window {config.max_spec_window} "

        cmd += "{mappings_flag} --trace-output {trace_file} -- {cmd}"
        self._drrun_cmd = cmd

    def collect_traces(self, on_group_done: Optional[Callable[[], None]] = None) -> int:
        """
        Iterate over all previously-generated public-private input pairs and collect contract traces
        for each pair.

        :param on_group_done: Callback invoked in the parent process every time an input group has
               been fully processed
        :return: 0 if successful, 1 if error occurs
        """
        # Check if the stage2 working directory exists and contains inputs
        if not os.path.isdir(self._config.stage2_wd):
            raise FileNotFoundError(
                f"Stage 2 working directory '{self._config.stage2_wd}' does not exist.")
        if not os.listdir(self._config.stage2_wd):
            raise FileNotFoundError(
                f"Stage 2 working directory '{self._config.stage2_wd}' is empty.")

        # Check if the traces are deterministic; abort if they are not
        if not self._check_determinism(self._config.stage2_wd):
            return 1

        input_map = self._build_directory_map()

        # Initialize a progress bar to track the progress of the tracing process
        n_inputs = sum(len(v) for v in input_map.values())
        desc = "Tracing & analyzing" if self._detector is not None else "Tracing inputs"
        progress_bar = console.progress_bar(total=n_inputs, desc=desc)

        # Process all inputs using a worker pool
        def on_complete(n_processed: int) -> None:
            progress_bar.update(n=n_processed)
            if on_group_done is not None:
                on_group_done()

        send_to_worker_pool(
            task=self._process_group,
            work_items=list(input_map.items()),
            num_workers=self._config.num_workers_tracer,
            on_complete=on_complete,
            task_timeout=self._config.tracing_total_timeout_s,
        )

        # We're done; close the progress bar
        progress_bar.close()

        return 0

    def _build_directory_map(self) -> WorkDirMap:
        """
        Build a todo-list for the tracer - a map of all stage2 subdirs that need to be processed,
        as well as the valid inputs in each group.
        """
        input_map: WorkDirMap = {}
        for subdir_name in os.listdir(self._config.stage2_wd):
            subdir = os.path.join(self._config.stage2_wd, subdir_name)
            if not os.path.isdir(subdir):
                continue

            file_list = [
                input_name for input_name in os.listdir(subdir)
                if os.path.isfile(os.path.join(subdir, input_name))
            ]
            if file_list:
                input_map[subdir] = file_list

        return input_map

    def _process_group(self, work_item: tuple[DirName, list[FileName]]) -> int:
        """ Collect traces for all inputs in this group. Returns number of inputs processed. """
        # pylint: disable=consider-using-with  # justification: the process outlives this scope
        input_group_dir, input_files = work_item
        trace_files = []
        for input_name in input_files:
            input_path = os.path.join(input_group_dir, input_name)
            output_base = self._get_output_base_path(input_path)
            expanded_cmd = self._expand_template_cmd(self._config.template_cmd, input_path)

            try:
                self._collect_one_trace(
                    expanded_cmd, output_base, timeout=self._config.tracing_timeout_s)
            except InstrException:
                # Mark this test as failed by creating a .failed file
                Path(f"{output_base}.failed").touch()
                continue
            except subprocess.TimeoutExpired:
                # Mark this test by creating a .timeout file
                Path(f"{output_base}.timeout").touch()
                # Remove trace, as it will be corrupted
                if os.path.exists(f"{output_base}.trace"):
                    os.remove(f"{output_base}.trace")
                continue
            except ProgramException:
                # NOTE: we intentionally ignore ProgramException in the target program,
                # as many files generated by AFL++ are invalid which leads to errors during
                # execution;
                # this is expected and does not affect the correctness of the fuzzing process
                continue

            trace_files.append(f"{output_base}.trace")

        if not trace_files:
            return len(input_files)

        # If `discard_non_leaky_traces` is set and all traces are identical, discard them
        traces_discarded = False
        if self._config.discard_non_leaky_traces and trace_files:
            traces_discarded = self._discard_if_not_leaky(trace_files)

        if not traces_discarded:
            # If the tracing and detection stages are pipelined, analyse the traces right away,
            # while they are still uncompressed
            if self._detector is not None:
                self._detector.detect_group(trace_files)

            # If configured, compress all collected traces in this input group
            self._compressor.compress_file_list(trace_files)

        return len(input_files)

    def _collect_one_trace(self,
                           expanded_cmd: ExpandedCmd,
                           output_base_path: FilePath,
                           store_mappings: bool = False,
                           timeout: int = 60 * 5) -> None:
        """
        Execute the target binary on the leakage model and collect a contract trace.
        :raise: InstrException, ProgramException
        """
        # Create the output directory and define paths for the trace and log files
        dir_ = os.path.dirname(output_base_path)
        os.makedirs(dir_, exist_ok=True)
        trace_file = f"{output_base_path}.trace"
        log_file = f"{output_base_path}.log"

        # Build the full tracing command
        tracing_cmd = self._expand_dr_cmd(expanded_cmd, trace_file, store_mappings)
        # print(tracing_cmd, flush=True); exit(1)

        # Execute the tracing command and capture output in the log file
        try:
            with open(log_file, "a") as f:
                f.write("$> " + tracing_cmd + "\n")
                subprocess.check_call(tracing_cmd, shell=True, stdout=f, stderr=f, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise e
        except subprocess.CalledProcessError as e:
            if TraceDecoder().is_trace_corrupted(trace_file):
                raise InstrException() from e
            raise ProgramException() from e

    def _get_output_base_path(self, input_path: FilePath) -> FilePath:
        """ Get the base filename for all tracer output files that correspond to the given input """
        rel_path = os.path.relpath(input_path, self._config.stage2_wd)
        output_path = os.path.join(self._config.stage3_wd, rel_path)
        base = output_path.removesuffix(".bin")
        return base

    def _expand_template_cmd(self, cmd: TemplateCmd, input_: FilePath) -> ExpandedCmd:
        """ Replace the placeholders in the command with the actual binary and input file. """
        assert self._config.bin_native is not None  # enforced by config validation
        expanded_cmd = [self._config.bin_native if s == "@#" else s for s in cmd]
        expanded_cmd = [s if s != "@@" else input_ for s in expanded_cmd]
        expanded_str = " ".join(expanded_cmd)
        return expanded_str

    def _expand_dr_cmd(self, expanded_cmd: ExpandedCmd, trace_file: FilePath,
                       store_mappings: bool) -> ExpandedCmd:
        """ Expand the DynamoRIO command with the given command and trace file path. """
        mappings_flag = f"--store-mappings {self._config.stage3_wd}/mappings.txt " \
            if store_mappings else ""
        dr_cmd = self._drrun_cmd.format(
            cmd=expanded_cmd, trace_file=trace_file, mappings_flag=mappings_flag)
        return dr_cmd

    def _find_reference_input(self, stage2_wd: DirName) -> Tuple[str, str]:
        """
        Find an arbitrary input that the target can trace without error, to use as the
        reference for the determinism check.

        Inputs that raise an exception or time out are skipped; a single summary line is
        emitted if any were skipped before a usable reference was found.

        :param stage2_wd: Path to the stage2 working directory where inputs can be found
        :return: Tuple of (expanded command, reference input path)
        :raise AssertionError: If no valid input is found
        """
        n_skipped = 0
        for input_group in os.listdir(stage2_wd):
            input_group_dir = os.path.join(stage2_wd, input_group)
            if not os.path.isdir(input_group_dir):
                continue

            # check if the directory contains 000.bin file
            ref_input = os.path.join(input_group_dir, "000.bin")
            if not os.path.isfile(ref_input):
                continue

            # try running the target binary with the reference input
            expanded_cmd = self._expand_template_cmd(self._config.template_cmd, ref_input)
            output_base = self._get_output_base_path(ref_input)
            try:
                self._collect_one_trace(
                    expanded_cmd,
                    output_base,
                    timeout=self._config.tracing_timeout_s,
                    store_mappings=True)
            except (InstrException, ProgramException, subprocess.TimeoutExpired):
                n_skipped += 1
                continue

            if n_skipped:
                console.info(f"Skipped {n_skipped} input(s) before finding a traceable "
                             "reference for the determinism check.")
            return expanded_cmd, ref_input

        raise AssertionError("No valid inputs found in the working directory; aborting")

    def _check_determinism(self, stage2_wd: DirName) -> bool:
        """
        Check if the traces are deterministic by running the target binary multiple times
        with the same inputs and comparing the outputs.

        NOTE: this function also has a side-effect of writing the mappings.txt file
        :param stage2_wd: Path to the stage2 working directory where inputs can be found
        :return: True if the traces are deterministic, False otherwise
        :raise: AssertionError if no input files are found
        """
        # find an arbitrary input in the working directory that does not produce an error
        expanded_cmd, ref_input = self._find_reference_input(stage2_wd)

        # execute the target binary twice and collect traces
        # Get the relative path for the determinism check files
        rel_path = os.path.relpath(ref_input, self._config.stage2_wd)
        output_dir = os.path.join(self._config.stage3_wd, os.path.dirname(rel_path))
        os.makedirs(output_dir, exist_ok=True)

        for i in [0, 1]:
            output_base = os.path.join(output_dir, f"determinism_check_{i}")
            self._collect_one_trace(
                expanded_cmd, output_base, timeout=self._config.tracing_timeout_s)

        # compare the traces
        with open(os.path.join(output_dir, "determinism_check_0.trace"), "rb") as f0, \
                open(os.path.join(output_dir, "determinism_check_1.trace"), "rb") as f1:
            trace_0_content = f0.read()
            trace_1_content = f1.read()
        if trace_0_content != trace_1_content:
            self._log.error(
                "The target binary produces non-deterministic traces. Tracing aborted.\n"
                f"    Reproduce with input: {ref_input}\n")
            return False

        # delete the traces if no issue was found
        os.remove(os.path.join(output_dir, "determinism_check_0.trace"))
        os.remove(os.path.join(output_dir, "determinism_check_1.trace"))
        return True

    def _discard_if_not_leaky(self, trace_files: List[FilePath]) -> bool:
        """ Discard all traces in the group if they are identical. """
        discarded = False

        # Check if there are any non-identical traces in the group
        all_identical = True
        ref_trace = trace_files[0]
        for trace_file in trace_files[1:]:
            # use diff tool for comparing traces as it is extremely fast for large files
            diff_cmd = f"diff -q {ref_trace} {trace_file}"
            result = subprocess.run(
                diff_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if result.returncode != 0:
                all_identical = False
                break

        # If all traces are identical, discard them
        if all_identical:
            for trace_file in trace_files:
                os.remove(trace_file)
            discarded = True

        # After discarding, leave a marker file to indicate that the traces were collected
        # successfully but discarded due to lack of leakage
        if discarded:
            dir_name = os.path.dirname(ref_trace)
            Path(f"{dir_name}/noleak").touch()

        return discarded
