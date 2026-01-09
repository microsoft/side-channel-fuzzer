"""
File: Module responsible for collecting contract traces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Final

import os
import subprocess
from enum import Enum
from tqdm import tqdm

from rvzr.model_dynamorio.trace_decoder import TraceDecoder
from .logger import Logger

if TYPE_CHECKING:
    from .config import Config


class _ExecOutcome(Enum):
    """
    Outcome of an execution of the tracer. The program can either exit without errors, or throw
    an (architectural) exception, or an unexpected failure can be happening in the instrumentation.
    """
    SUCCESS = 0
    PROGRAM_EXCEPTION = 1
    INSTR_EXCEPTION = 2
    COV_EXCEPTION = 3
    UNKNOWN = 4


class Tracer:
    """
    Class responsible for executing the target binary on the leakage model and retrieving the
    collected contract traces.
    """

    _drrun_cmd: Final[str]
    _log: Final[Logger]

    def __init__(self, config: Config) -> None:
        self._log = Logger("Tracer")

        self._config = config
        self._drrun_cmd = f"{config.model_root}/drrun " \
            f"-c {config.model_root}/libdr_model.so " \
            f"--tracer {config.contract_observation_clause} " \
            f"--speculator {config.contract_execution_clause} " \
            "--instrumented-func start_driver --trace-output {trace_file} -- {cmd}"
        self._coverage_cmd = "LLVM_PROFILE_FILE={cov_file} {cmd}"

    def collect_traces(self, cmd: List[str]) -> int:
        """
        Iterate over all previously-generated public-private input pairs and collect contract traces
        for each pair.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                        and private (@#) inputs
        :return: 0 if successful, 1 if error occurs
        """
        # Check if the traces are deterministic; abort if they are not
        if not self._check_determinism(self._config.stage2_wd, cmd):
            self._log.error("The target binary produces non-deterministic traces. Tracing aborted.")
            return 1

        # Get a list of input groups
        input_group_dirs = []
        for input_group in os.listdir(self._config.stage2_wd):
            input_group_dir = os.path.join(self._config.stage2_wd, input_group)
            if not os.path.isdir(input_group_dir):
                continue
            input_group_dirs.append(input_group_dir)

        # Iterate over all input groups and collect traces
        inputs: List[str] = []
        for input_group_dir in input_group_dirs:
            # Get a list of all inputs
            for input_name in os.listdir(input_group_dir):
                if ".bin" not in input_name:
                    continue
                input_path = os.path.join(input_group_dir, input_name)
                inputs.append(input_path)

        # Initialize a progress bar to track the progress of the tracing process
        progress_bar = tqdm(total=len(inputs))

        # Process each pair
        for input_ in inputs:
            # Expand the command with the public and private inputs
            expanded_cmd = self._expand_target_cmd(cmd, input_)

            # Get the output path in stage3_wd
            output_base = self._get_output_path(input_)

            # Execute the target binary and collect traces
                self._execute(expanded_cmd, input_, output_base, self._config.coverage)
                # Mark this test as failed by creating a .failed file
                with open(f"{output_base}.failed", "w") as failed_log:
                    failed_log.close()

            progress_bar.update()

        progress_bar.close()
        return 0

    def _get_output_path(self, input_path: str) -> str:
        """
        Convert an input path from stage2_wd to the corresponding output path in stage3_wd.

        :param input_path: Path to the input file in stage2_wd
        :return: Base path for output files in stage3_wd (without extension)
        """
        # Get the relative path from stage2_wd
        rel_path = os.path.relpath(input_path, self._config.stage2_wd)

        # Construct the output path in stage3_wd
        output_path = os.path.join(self._config.stage3_wd, rel_path)

        # Create the output directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        # Remove the .bin extension to get the base path
        base = output_path.rstrip(".bin")
        return base

    def _expand_target_cmd(self, cmd: List[str], input_: str) -> str:
        """
        Replace the placeholders in the command with the actual public and private inputs.
        """
        expanded_cmd = cmd
        expanded_cmd = [s if s != "@@" else input_ for s in expanded_cmd]
        expanded_str = " ".join(expanded_cmd)
        return expanded_str

    def _execute(self, expanded_str: str, input_name: str, output_base: str,
                 enable_cov: bool) -> None:
        """
        Execute the target binary on the leakage model with the given public and private inputs.

        If `enable_cov` is True, the command will also collect coverage information.

        :param expanded_str: Command to run the target binary, with public and private inputs
        :param input_name: Path to the input file (used in the command)
        :param output_base: Base path for the output files (trace and log) in stage3_wd
        :param enable_cov: Whether to collect coverage information
        :return: The outcome of the execution (either success or reason for failures)
        """
        trace_file = f"{output_base}.trace"
        log_file = f"{output_base}.log"

        complete_cmd = self._drrun_cmd.format(cmd=expanded_str, trace_file=trace_file)
        # print(complete_cmd, flush=True)
        try:
            with open(log_file, "a") as f:
                f.write("$> " + complete_cmd + "\n")
                subprocess.check_call(complete_cmd, shell=True, stdout=f, stderr=f)
        except subprocess.CalledProcessError:
            if TraceDecoder().is_trace_corrupted(trace_file):
                return _ExecOutcome.INSTR_EXCEPTION
            return _ExecOutcome.PROGRAM_EXCEPTION

        if not enable_cov:
            return _ExecOutcome.SUCCESS

        # If coverage is enabled, run the command with coverage collection
        cov_file = f"{output_base}.profraw"
        coverage_cmd = self._coverage_cmd.format(cov_file=cov_file, cmd=expanded_str)
        try:
            subprocess.check_call(
                coverage_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            self._log.error(f"Error executing coverage command: {coverage_cmd}")
            return _ExecOutcome.COV_EXCEPTION
        return _ExecOutcome.SUCCESS

    def _check_determinism(self, wd: str, cmd: List[str]) -> bool:
        """
        Check if the traces are deterministic by running the target binary multiple times
        with the same inputs and comparing the outputs.
        :param wd: Working directory containing the input pairs
        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :return: True if the traces are deterministic, False otherwise
        :raise: AssertionError if no input pairs are found
        """
        # find an arbitrary input in the working directory that does not produce an error
        # and construct a command to run it
        found: bool = False
        expanded_cmd = ""
        ref_input = ""
        for input_group in os.listdir(wd):
            input_group_dir = os.path.join(wd, input_group)
            if not os.path.isdir(input_group_dir):
                continue

            # check if the directory contains 000.bin file
            ref_input = os.path.join(input_group_dir, "000.bin")
            if not os.path.isfile(ref_input):
                continue

            # try running the target binary with the reference input
            expanded_cmd = self._expand_target_cmd(cmd, ref_input)
            err = self._execute(expanded_cmd, ref_input, False)
            if err in (_ExecOutcome.INSTR_EXCEPTION, _ExecOutcome.PROGRAM_EXCEPTION):
                # if the target binary throws an exception, skip this input group
                continue
            found = True
            break
        if not found:
            raise AssertionError("No valid inputs found in the working directory; aborting")

        # execute the target binary twice and collect traces
        # Get the relative path for the determinism check files
        rel_path = os.path.relpath(ref_input, self._config.stage2_wd)
        output_dir = os.path.join(self._config.stage3_wd, os.path.dirname(rel_path))
        os.makedirs(output_dir, exist_ok=True)
        for i in [0, 1]:
            pair_name = os.path.join(input_group_dir, f"determinism_check_{i}")
            err = self._execute(expanded_cmd, pair_name, False)
            assert err not in (_ExecOutcome.INSTR_EXCEPTION, _ExecOutcome.PROGRAM_EXCEPTION)

        # compare the traces
        with open(os.path.join(output_dir, "determinism_check_0.trace"), "rb") as f0, \
                open(os.path.join(output_dir, "determinism_check_1.trace"), "rb") as f1:
            trace_0_content = f0.read()
            trace_1_content = f1.read()
        if trace_0_content != trace_1_content:
            return False

        return True
