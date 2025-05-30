"""
File: Module responsible for generation of diverse public inputs for the target binary.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final, List, Optional

import os
import sys
import subprocess

from .sec_gen import generate_one_secret

if TYPE_CHECKING:
    from .config import Config


class PubGen:
    """
    Class responsible for generating public inputs for the target binary using AFL++.
    """
    _config: Config
    _wd: Final[str]  # Working directory for AFL++

    _afl_bin: Final[str]  # Path to the AFL++ binary
    _libcompcov: Final[str]  # Path to the libcompcov.so library
    _baseline_private_input: Optional[str] = None

    def __init__(self, config: Config) -> None:
        self._config = config
        self._wd = config.stage1_wd
        self._afl_bin = os.path.join(config.afl_root, "afl-fuzz")
        self._libcompcov = os.path.join(config.afl_root, "libcompcov.so")

    def generate(self, cmd: List[str], target_cov: int, timeout_s: int) -> int:
        """
        Generate public inputs for the target binary invoked with the given command.
        The generation continues until either the target coverage is achieved or
        the timeout is reached.

        :param cmd: Command to run the target binary, with placeholders for public (@@)
                    and private (@#) inputs
        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        self._generate_baseline_private_input()
        return self._start_afl_fuzz(cmd, target_cov, timeout_s)

    def _generate_baseline_private_input(self) -> None:
        """
        Generate a private input that will be used as a basis for generating new public inputs.
        """
        # -----------------
        # FIXME: the approach of generating public inputs based on a single private input
        # has a known issue where a secret-dependent branch is always takes the same path,
        # thus bounding the coverage. This problem will be fixed in the future.
        # -----------------
        self._baseline_private_input = os.path.join(self._wd, "main.sec")
        generate_one_secret(
            self._baseline_private_input,
            self._config.secret_size_bytes,
        )

    def _start_afl_fuzz(self, cmd: List[str], _: int, timeout_s: int) -> int:
        """
        Starts the AFL++ fuzzing process.
        """
        assert self._baseline_private_input is not None, "Private input not generated yet."
        assert self._config.afl_seed_dir is not None, "AFL seed directory not set."

        # configure the AFL++ environment
        env = os.environ.copy()
        env["AFL_COMPCOV_LEVEL"] = "2"
        env["AFL_PRELOAD"] = self._libcompcov
        env["AFL_KEEP_TRACES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"

        afl_flags = [
            "-V",
            str(timeout_s), "-c", cmd[0], "-i", self._config.afl_seed_dir, "-o", self._wd
        ]

        cmd = [self._afl_bin] + afl_flags + ["--"] + cmd
        cmd = [s if s != "@#" else self._baseline_private_input for s in cmd]
        # print(cmd, flush=True)

        try:
            subprocess.check_call(cmd, timeout=timeout_s, env=env, shell=False)
        except subprocess.TimeoutExpired:
            # ignore timeout errors
            # it just means a clock mismatch between AFL and this function
            pass
        except subprocess.CalledProcessError as e:
            print(f"[AFL ERROR]: {e}")
            return 1
        finally:
            # Workaround: AFL++ corrupts the terminal output under some environments;
            # Force cursor restoration to mitigate this issue.
            sys.stdout.write('\033[?25h')  # ANSI escape to show cursor
            sys.stdout.flush()

        return 0
