"""
File: Module responsible for collecting contract traces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Final

import os
import subprocess

if TYPE_CHECKING:
    from .config import Config


class Tracer:
    """
    Class responsible for executing the target binary on the leakage model and retrieving the
    collected contract traces.
    """

    _drrun_cmd: Final[str]

    def __init__(self, config: Config) -> None:
        self._config = config
        self._drrun_cmd = f"{config.model_root}/drrun " \
                          f"-c {config.model_root}/libdr_model.so " \
                          f"--tracer {config.contract_observation_clause} " \
                          f"--speculator {config.contract_execution_clause} " \
                          "--instrumented-func wrapper -- {cmd} > {trace_file}"

    def collect_traces(self, cmd: List[str]) -> int:
        """
        Iterate over all previously-generated public-private input pairs and collect contract traces
        for each pair.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                        and private (@#) inputs
        :return: 0 if successful, 1 if error occurs
        """
        # Get a list of input groups
        input_group_dirs = []
        for input_group in os.listdir(self._config.stage2_wd):
            input_group_dir = os.path.join(self._config.stage2_wd, input_group)
            if not os.path.isdir(input_group_dir):
                continue
            input_group_dirs.append(input_group_dir)

        # Iterate over all input groups and collect traces
        for input_group_dir in input_group_dirs:
            # Get a list of public-private input pairs
            pairs = []
            pub_input = os.path.join(input_group_dir, "public")
            for sec_input_ in os.listdir(input_group_dir):
                if "private" not in sec_input_:
                    continue
                if "log" in sec_input_ or "trace" in sec_input_:
                    continue
                sec_input = os.path.join(input_group_dir, sec_input_)
                pairs.append((pub_input, sec_input))

            # Process each pair
            for pub_input, sec_input in pairs:
                pair_name = os.path.basename(sec_input)

                # Expand the command with the public and private inputs
                expanded_cmd = self._expand_target_cmd(cmd, pub_input, sec_input)
                trace_file = os.path.join(input_group_dir, f"{pair_name}.trace")
                log_file = os.path.join(input_group_dir, f"{pair_name}.log")

                # Execute the target binary and collect traces
                _ = self._execute(expanded_cmd, trace_file, log_file)
                # NOTE: we intentionally ignore the return value here, as many files generated
                # by AFL++ are invalid, which leads to errors during execution; this is
                # expected and does not affect the correctness of the fuzzing process

        return 0

    def _expand_target_cmd(self, cmd: List[str], public_input: str, private_input: str) -> str:
        """
        Replace the placeholders in the command with the actual public and private inputs.
        """
        expanded_cmd = cmd
        expanded_cmd = [s if s != "@@" else public_input for s in expanded_cmd]
        expanded_cmd = [s if s != "@#" else private_input for s in expanded_cmd]
        expanded_str = " ".join(expanded_cmd)
        return expanded_str

    def _execute(self, expanded_str: str, trace_file: str, log_file: str) -> bool:
        """
        Execute the target binary on the leakage model with the given public and private inputs.
        """
        complete_cmd = self._drrun_cmd.format(cmd=expanded_str, trace_file=trace_file)
        # print(complete_cmd, flush=True)
        try:
            with open(log_file, "a") as f:
                subprocess.check_call(complete_cmd, shell=True, stdout=f, stderr=f)
        except subprocess.CalledProcessError:
            return True
        return False
