"""
File: Global ConSFuzz configuration.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Dict, Optional, Literal, Any, Final, List
import os
import pathlib
import shutil

import yaml
from typing_extensions import assert_never

FuzzingStages = Literal["fuzz", "pub_gen", "stage2", "report"]
YAMLData = Dict[str, Any]
ReportVerbosity = Literal[1, 2, 3]


# ==================================================================================================
# Service Classes
# ==================================================================================================
class _ConfigException(SystemExit):
    """ Custom exception class for configuration errors. """

    def __init__(self, var: str, message: str) -> None:
        super().__init__(f"[ERROR] Invalid value of config variable {var}\nIssue: {message}\n")


class _WorkingDirManager:
    """
    Context manager for handling the working directory.
    It ensures that the working directory is created and preserved properly.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def set_working_dirs(self, stage: FuzzingStages) -> None:
        """
        Ensure that the working directory is set up correctly.

        Algorithm:
        1. If the directory does not exist, throw an exception.
        2. If the directory is empty, do nothing.
        3. If the directory is not empty:
           - If `force_working_dir_overwrite` is set, remove the contents of the subdirectory
                corresponding to the given stage.
           - If `archive_dir` is set, archive the contents of the subdirectory corresponding
              to the given stage into `archive_dir` and remove the contents of the subdirectory.
           - If `archive_dir` is not set, throw an exception.

        """
        assert self.config.working_dir is not None, \
            "working_dir must be checked before calling this method."

        # Throw an exception if the working directory does not exist
        if not pathlib.Path(self.config.working_dir).is_dir():
            raise _ConfigException(
                "working_dir",
                f"Working directory {self.config.working_dir} does not exist. "
                "Please create it before running the fuzzer.",
            )

        # Empty working directory? No risk of overwriting anything
        if not os.listdir(self.config.working_dir):
            if stage == "fuzz":
                os.makedirs(self.config.stage1_wd, exist_ok=True)
                os.makedirs(self.config.stage2_wd, exist_ok=True)
                os.makedirs(self.config.stage3_wd, exist_ok=True)
            return

        # Identify the target directory for the given stage
        if stage == "fuzz":
            stage_dir = self.config.working_dir
        elif stage == "pub_gen":
            stage_dir = self.config.stage1_wd
        elif stage == "stage2":
            stage_dir = self.config.stage2_wd
        elif stage == "report":
            stage_dir = self.config.stage3_wd
        else:
            assert_never(stage)

        # Stage directory does not exist? Create it
        if not os.path.exists(stage_dir):
            os.makedirs(stage_dir, exist_ok=True)
            return

        # Stage directory exists, but is empty? We're good to go
        if not os.listdir(stage_dir):
            return

        # If force overwrite is set, remove the contents of the target directory
        if self.config.force_working_dir_overwrite:
            print(f"[INFO] Directory {stage_dir} is not empty; removing its contents.")
            self._reset_dirs(stage_dir, stage)
            os.makedirs(stage_dir, exist_ok=True)
            return

        # If archive directory is not set and force overwrite is not set, raise an exception
        if self.config.archive_dir is None:
            raise _ConfigException(
                "archive_dir",
                "Working directory is not empty and force_working_dir_overwrite is not set. "
                "Please set archive_dir to preserve the contents of the working directory.",
            )

        # Archive based on the stage
        self._archive(stage_dir, stage, self.config.working_dir, self.config.archive_dir)
        self._reset_dirs(stage_dir, stage)

    def _archive(self, source_dir: str, target_name: str, working_dir: str,
                 archive_dir: str) -> None:
        """ Archive the contents of source_dir to the archive directory """
        # Ensure that archives have unique names
        primary_timestamp = int(pathlib.Path(working_dir).stat().st_mtime)
        archive_name = f"{primary_timestamp}_{target_name}"

        # Ensure that different per-stage archives from the same work dir have unique names
        if source_dir != working_dir:
            secondary_timestamp = int(pathlib.Path(source_dir).stat().st_mtime)
            archive_name += f"_{secondary_timestamp}"

        archive_path = archive_dir + "/" + archive_name

        # Create the archive
        shutil.make_archive(archive_path, 'gztar', str(source_dir))
        print(f"[INFO] Archived {working_dir} to {archive_path}.tar.gz.")

    def _reset_dirs(self, stage_dir: str, stage: FuzzingStages) -> None:
        shutil.rmtree(stage_dir)
        os.makedirs(stage_dir, exist_ok=True)
        if stage == "fuzz":
            os.makedirs(self.config.stage1_wd, exist_ok=True)
            os.makedirs(self.config.stage2_wd, exist_ok=True)
            os.makedirs(self.config.stage3_wd, exist_ok=True)


# ==================================================================================================
# Main Configuration Class
# ==================================================================================================
class Config:
    """
    Class responsible for storing global fuzzing configuration.

    Note: This class is expected to be instantiated only once by `rvzr-sw.py` and passed to all
          other modules by reference.
    """
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    # NOTE: disabling is justified here, as this class is a configuration holder

    __config_instantiated: bool = False
    """ Class-local flag that allows us to detect attempts to instantiate Config more than once. """

    _internal_opts: Final[List[str]] = ["stage1_wd", "stage2_wd", "stage3_wd"]
    _help: str = ""

    # ==============================================================================================
    # Fuzzing directories
    working_dir: Optional[str] = None
    _help += """\n\n working_dir (None)
    Working directory for the fuzzer. It will contain all fuzzing artifacts as well as
    log files and fuzzing reports. """

    archive_dir: Optional[str] = None
    _help += """\n\n archive_dir (None)
    Directory where the fuzzing artifacts from previous runs will be archived.
    If the working directory is non-empty and `force_working_dir_overwrite` is False,
    the contents of the working_dir will be moved into archive_dir into a timestamped archive. """

    force_working_dir_overwrite: bool = False
    _help += """\n\n force_working_dir_overwrite (False)
    Flag indicating whether the fuzzer should overwrite the working directory
    if it already exists.
        * If set to True, the fuzzer will remove the contents of
          the working directory before starting.
        * If set to False, the fuzzer will refuse to run if the working directory is not empty and
          the `archive_dir` is not set. """

    # internal working directories for each stage of the fuzzing process
    # (cannot be set directly from the config YAML file)
    stage1_wd: str
    stage2_wd: str
    stage3_wd: str

    # ==============================================================================================
    # Fuzzing parameters
    secret_size_bytes: int = 32
    _help += """\n\n secret_size_bytes (32)
    Size of the secret (private) input, in bytes. """

    contract_observation_clause: str = "ct"
    _help += """\n\n contract_observation_clause (ct)"""
    contract_execution_clause: str = "seq"
    _help += """\n\n contract_execution_clause (seq)"""

    coverage: bool = True
    _help += """\n\n coverage (True)
    Flag indicating whether the fuzzer should collect coverage information.
    If set to True, the fuzzer will execute an additional run in Stage 2 where it will run
    the target binary with the generated public-private input pairs and collect
    coverage information. This information will be later used to build a coverage model
    for the complete fuzzing campaign, and it will be summarized in the final report.
    """

    # ==============================================================================================
    # DR backend parameters
    model_root: str = "~/.local/dynamorio/"
    _help += """\n\n model_root (~/.local/dynamorio/)
    Path to the directory containing the installation of the leakage model. """

    # ==============================================================================================
    # AFL++ parameters
    afl_root: str = "~/.local/afl/"
    _help += """\n\n afl_root (~/.local/afl/)
    th to the directory containing the installation of AFL++. """

    afl_seed_dir: Optional[str] = None
    _help += """\n\n afl_seed_dir (None)
    Path to the directory containing the seed corpus for AFL++. """

    afl_exec_timeout_ms: int = 100
    _help += """\n\n afl_exec_timeout_ms (100)
    Timeout for AFL++ execution, in milliseconds. """

    # afl_qemu_mode: bool = False
    # """ Flag indicating whether AFL++ should be run in QEMU mode. """

    # ==============================================================================================
    # Reporting parameters
    report_verbosity: ReportVerbosity = 3
    _help += """\n\n report_verbosity (3)
    Verbosity level for the report:
        * 1 - only lines of code with leaks;
        * 2 - also include PC of the instructions that cause the leaks;
        * 3 - also include the file names of the traces that contain the leaks """

    report_allowlist: Optional[str] = None
    _help += """\n\n report_allowlist (None)
    Path to a file containing a list of allowed lines of code, in the format:
    <file_path>:<line_number>
    If set, the report will only include lines of code that are not in this list.
    This is useful for filtering out known leaks or false positives. """

    llvm_cov_cmd: str = "llvm-cov"
    llvm_profdata_cmd: str = "llvm-profdata"

    def __init__(self, config_yaml: str, stage: FuzzingStages) -> None:
        if Config.__config_instantiated:
            raise RuntimeError("Config class should be instantiated only once.")
        Config.__config_instantiated = True

        # Parse the config YAML file and ensure that it is set up correctly
        yaml_data = self._parse_yaml(config_yaml)
        self._set_from_yaml(yaml_data)
        self._validate_config()

        # Ensure that the working directory is managed properly
        wd_manager = _WorkingDirManager(self)
        wd_manager.set_working_dirs(stage)

    @classmethod
    def help(cls) -> str:
        """
        Return a help string describing all configuration options.
        :return: Help string
        """
        help_str = "ConSFuzz Configuration Options:\n"
        help_str += cls._help
        return help_str

    def _parse_yaml(self, config_yaml: str) -> YAMLData:
        """
        Parse the YAML configuration file.
        :param config_yaml: Path to the YAML configuration file
        :return: Parsed configuration data as a dictionary
        """
        if not os.path.exists(config_yaml):
            raise SystemExit(f"[ERROR] Config YAML file {config_yaml} does not exist.")
        with open(config_yaml, 'r') as file:
            config_data = yaml.safe_load(file)
        if not isinstance(config_data, dict):
            raise SystemExit(f"[ERROR] YAML file {config_yaml} isn't a valid ConSFuzz config file.")
        return config_data

    def _set_from_yaml(self, yaml_data: YAMLData) -> None:
        """
        Set configuration values from the parsed YAML data.
        :param yaml_data: Parsed configuration data as a dictionary
        """
        self.working_dir = yaml_data.get("working_dir", None)
        if self.working_dir is None:
            raise _ConfigException("working_dir",
                                   "working_dir is a required field in the config file.")

        self.working_dir = str(pathlib.Path(self.working_dir).expanduser())
        self.stage1_wd = os.path.join(self.working_dir, "stage1")
        self.stage2_wd = os.path.join(self.working_dir, "stage2")
        self.stage3_wd = os.path.join(self.working_dir, "stage3")

        self.archive_dir = yaml_data.get("archive_dir", None)
        if self.archive_dir is not None:
            self.archive_dir = str(pathlib.Path(self.archive_dir).expanduser())

        self.force_working_dir_overwrite = yaml_data.get("force_working_dir_overwrite",
                                                         self.force_working_dir_overwrite)

        self.model_root = yaml_data.get("model_root", self.model_root)
        if not self.model_root.startswith("/"):
            self.model_root = str(pathlib.Path(self.model_root).expanduser())

        self.afl_root = yaml_data.get("afl_root", self.afl_root)
        if not self.afl_root.startswith("/"):
            self.afl_root = str(pathlib.Path(self.afl_root).expanduser())

        self.afl_seed_dir = yaml_data.get("afl_seed_dir", self.afl_seed_dir)
        if self.afl_seed_dir is not None:
            self.afl_seed_dir = str(pathlib.Path(self.afl_seed_dir).expanduser())

        self.afl_exec_timeout_ms = yaml_data.get("afl_exec_timeout_ms", self.afl_exec_timeout_ms)

        self.contract_observation_clause = yaml_data.get("contract_observation_clause",
                                                         self.contract_observation_clause)
        self.contract_execution_clause = yaml_data.get("contract_execution_clause",
                                                       self.contract_execution_clause)

        self.report_verbosity = yaml_data.get("report_verbosity", self.report_verbosity)
        self.report_allowlist = yaml_data.get("report_allowlist", self.report_allowlist)

        self.llvm_cov_cmd = yaml_data.get("llvm_cov_cmd", self.llvm_cov_cmd)
        self.llvm_profdata_cmd = yaml_data.get("llvm_profdata_cmd", self.llvm_profdata_cmd)

        # check for attempts to set internal config variables
        for opt in self._internal_opts:
            if opt in yaml_data:
                raise _ConfigException(
                    opt, f"Option {opt} is for internal use only and should not be set in"
                    " the user config; use working_dir instead.")

    def _validate_config(self) -> None:
        """
        Validate the configuration values.
        """
        if not pathlib.Path(self.model_root).expanduser().is_dir():
            raise _ConfigException("model_root", f"{self.model_root} does not exist.")
        if not pathlib.Path(self.afl_root).expanduser().is_dir():
            raise _ConfigException("afl_root", f"{self.afl_root} does not exist.")
        if self.afl_seed_dir is None:
            raise _ConfigException("afl_seed_dir", "Seed directory is not set.")
        if not pathlib.Path(self.afl_seed_dir).expanduser().is_dir():
            raise _ConfigException("afl_seed_dir", f"{self.afl_seed_dir} does not exist.")

        if not shutil.which(self.llvm_cov_cmd):
            raise _ConfigException("llvm_cov_cmd", f"command {self.llvm_cov_cmd} not found.")
        if not shutil.which(self.llvm_profdata_cmd):
            raise _ConfigException("llvm_profdata_cmd",
                                   f"command {self.llvm_profdata_cmd} not found.")
