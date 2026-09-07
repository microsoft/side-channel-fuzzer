"""
File: Global McFuzz configuration.

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

from .util import console

TestingStages = Literal["fuzz", "fuzz_gen", "boost", "trace", "report"]
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

    def create_working_dirs(self, stage: TestingStages) -> None:
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
                self._create_all_stage_dirs()
            return

        # Prepare every directory that the given stage writes into
        stage_dirs = self._get_stage_dirs(stage)
        for stage_dir in stage_dirs:
            # Disambiguate the archive names when the stage owns more than one directory
            name = stage if len(stage_dirs) == 1 else f"{stage}_{os.path.basename(stage_dir)}"
            self._prepare_stage_dir(stage_dir, stage, name)

    def _prepare_stage_dir(self, stage_dir: str, stage: TestingStages, archive_name: str) -> None:
        """ Archive or reset a single working directory owned by the given stage. """
        assert self.config.working_dir is not None

        # Stage directory does not exist? Create it
        if not os.path.exists(stage_dir):
            os.makedirs(stage_dir, exist_ok=True)
            return

        # Stage directory exists, but is empty? We're good to go
        if not os.listdir(stage_dir):
            return

        # If force overwrite is set, remove the contents of the target directory
        if self.config.force_working_dir_overwrite:
            console.info(f"Working directory not empty; removing contents of {stage_dir}")
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
        self._archive(stage_dir, archive_name, self.config.working_dir, self.config.archive_dir)
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
        console.info(f"Archived {working_dir} → {archive_path}.tar.gz")

    def _reset_dirs(self, stage_dir: str, stage: TestingStages) -> None:
        shutil.rmtree(stage_dir)
        os.makedirs(stage_dir, exist_ok=True)
        if stage == "fuzz":
            self._create_all_stage_dirs()

    def _create_all_stage_dirs(self) -> None:
        """ Create the four per-stage working directories (used for the 'fuzz' stage). """
        for stage_wd in (self.config.stage1_wd, self.config.stage2_wd, self.config.stage3_wd,
                         self.config.stage4_wd):
            os.makedirs(stage_wd, exist_ok=True)

    def _get_stage_dirs(self, stage: TestingStages) -> List[str]:
        """
        Return the working directories owned by the given stage, i.e. the directories that the
        stage writes into and that therefore have to be archived or reset before it starts.

        Most stages own exactly one directory. The exception is the pipelined mode, in which the
        tracing stage also produces the leak files that the reporting stage would otherwise
        produce itself: there, `trace` owns the stage4 directory as well, and `report` owns
        nothing, as it merely merges results that already exist.
        """
        if stage == "fuzz":
            assert self.config.working_dir is not None
            return [self.config.working_dir]
        if stage == "fuzz_gen":
            return [self.config.stage1_wd]
        if stage == "boost":
            return [self.config.stage2_wd]
        if stage == "trace":
            if self.config.pipeline_trace_and_detect:
                return [self.config.stage3_wd, self.config.stage4_wd]
            return [self.config.stage3_wd]
        if stage == "report":
            if self.config.pipeline_trace_and_detect:
                return []
            return [self.config.stage4_wd]
        assert_never(stage)


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
    # justification: this class is a configuration holder

    __config_instantiated: bool = False
    """ Class-local flag that allows us to detect attempts to instantiate Config more than once. """

    _internal_opts: Final[List[str]] = ["stage1_wd", "stage2_wd", "stage3_wd", "stage4_wd"]
    _help: str = ""
    _required_opts: List[str] = []

    # ==============================================================================================
    # Fuzzing directories
    working_dir: Optional[str] = None
    _help += """\n\n working_dir (required)
    Working directory for the fuzzer. It will contain all fuzzing artifacts as well as
    log files and fuzzing reports. """
    _required_opts.append("working_dir")

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

    template_cmd: List[str]
    _help += """\n\n template_cmd (required)
    Command to invoke the target binary, as a string.
    Use '@#' as a placeholder for the target binary (replaced with bin_instrumented or bin_native
    depending on the stage) and '@@' as a placeholder for the generated driver input file.
    Example: "@# -d @@ -p policy.txt" """
    _required_opts.append("template_cmd")

    bin_instrumented: str = ""
    _help += """\n\n bin_instrumented (required)
    Path to an AFL++-instrumented binary to be used during the fuzzing-based input generation stage.
    Replaces the @# placeholder in the target command. """
    _required_opts.append("bin_instrumented")

    bin_native: str = ""
    _help += """\n\n bin_native (required)
    Path to a native (non-AFL-instrumented) binary to be used during the tracing stage.
    Replaces the @# placeholder in the target command. """
    _required_opts.append("bin_native")

    # internal working directories for each stage of the fuzzing process
    # (cannot be set directly from the config YAML file)
    stage1_wd: str
    stage2_wd: str
    stage3_wd: str
    stage4_wd: str

    # ==============================================================================================
    # Multiprocessing parameters
    num_workers_fuzz_gen: int = 1
    _help += """\n\n num_workers_fuzz_gen (1)
    Number of parallel workers to use for fuzzing-based input generation. """

    num_workers_tracer: int = 1
    _help += """\n\n num_workers_tracer (1)
    Number of parallel workers to use for tracing. """

    num_workers_detector: int = 1
    _help += """\n\n num_workers_detector (1)
    Number of parallel workers to use for leak detection. """

    # ==============================================================================================
    # Fuzzing parameters
    contract_observation_clause: str = "ct"
    _help += """\n\n contract_observation_clause (ct)"""
    contract_execution_clause: str = "seq"
    _help += """\n\n contract_execution_clause (seq)"""

    # ==============================================================================================
    # Boosting parameters
    num_secrets_per_class: int = 2
    _help += """\n\n num_secrets_per_class (2)
    Number of public-equivalent inputs to be generated per original randomly-generated input.
    E.g., if set to 2, for each randomly-generated input created during Stage 1, one more input
    will be generated during Stage 2, such that the public values in the two inputs are identical,
    but the secret values differ. """

    boost_seed: Optional[int] = None
    _help += """\n\n boost_seed (None)
    Seed for the random generation of secret (private) data during the boosting stage.
    If set to an integer, the secret data is generated deterministically, making the boosting
    stage reproducible. If None (the default), the secret data is generated using an unseeded
    cryptographically secure random source (os.urandom). """

    # ==============================================================================================
    # Tracing parameters
    model_root: str = "~/.local/dynamorio/"
    _help += """\n\n model_root (~/.local/dynamorio/)
    Path to the directory containing the installation of the leakage model. """

    discard_non_leaky_traces: bool = True
    _help += """\n\n discard_non_leaky_traces (True)
    When enabled, discards traces from input groups where all inputs produce identical results,
    indicating no observable leakage. """

    compression_tool: str = "bzip2"
    _help += """\n\n compression_tool (gzip)
    Tool used to compress the collected traces.\n
    Options: gzip, bzip2, none. """

    tracing_ignorelist: Optional[str] = None
    _help += """\n\n tracing_ignorelist (optional)
    File containing a list of symbols for which instrumentation should be paused. """

    tracing_entrypoint: str = "start_harness"
    _help += """\n\n tracing_entrypoint (start_harness)
    Name of the function that triggers instrumentation start. """

    max_spec_window: Optional[int] = None
    _help += """\n\n max_spec_window (optional)
    Maximum size of the speculation window. """

    tracing_total_timeout_s: int = 60 * 60 * 10
    _help += """\n\n tracing_total_timeout_s (optional)
    Maximum time to spend for each worker. """

    tracing_timeout_s: int = 60 * 60
    _help += """\n\n tracing_timeout_s (optional)
    Maximum time to spend on each input. """

    # ==============================================================================================
    # AFL++ parameters
    afl_root: str = "~/.local/afl/"
    _help += """\n\n afl_root (~/.local/afl/)
    Path to the directory containing the installation of AFL++. """

    afl_seed_dir: str = ""
    _help += """\n\n afl_seed_dir (required)
    Path to the directory containing the seed corpus for AFL++. """
    _required_opts.append("afl_seed_dir")

    afl_exec_timeout_ms: int = 100
    _help += """\n\n afl_exec_timeout_ms (100)
    Timeout for AFL++ execution, in milliseconds. """

    fuzzing_timeout_s: int = 3600
    _help += """\n\n fuzzing_timeout_s (3600)
    Timeout for fuzzing, in seconds. """

    afl_quiet: bool = True
    _help += """\n\n afl_quiet (True)
    Flag indicating whether AFL++ should run in quiet mode. """

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

    allowlist: Optional[str] = None
    _help += """\n\n allowlist (None)
    Path to a file containing a list of allowed lines of code, in the format:
    <file_path>:<line_number>
    If set, the report will only include lines of code that are not in this list.
    This is useful for filtering out known leaks or false positives. """

    keep_stage4_files: bool = False
    _help += """\n\n keep_stage4_files (False)
    Keep all the files generated by the leak detector in stage4. """

    # ==============================================================================================
    # Pipelining parameters
    pipeline_trace_and_detect: bool = False
    _help += """\n\n pipeline_trace_and_detect (False)
    Pipeline the tracing and leak detection stages: instead of detecting leaks only after all
    traces have been collected, each group of traces is analysed by the leak detector as soon
    as it has been traced. Applies to the `fuzz` and `trace` subcommands; when enabled, `trace`
    also produces the leak files in the stage4 directory, and `report` merges them instead of
    re-running the detection. """

    intermediate_report_interval: int = 0
    _help += """\n\n intermediate_report_interval (0)
    Number of completed input groups between intermediate reports. When set to a positive value
    (and pipeline_trace_and_detect is enabled), preliminary reports are written to the stage4
    directory during the run, so that leaks can be inspected before the run completes.
    The reports use the same file names as the final ones, and are overwritten by every
    subsequent pass. When set to 0, a report is generated only at the end of the run. """

    def __init__(self, config_yaml: str, stage: Optional[TestingStages]) -> None:
        if Config.__config_instantiated:
            raise RuntimeError("Config class should be instantiated only once.")
        Config.__config_instantiated = True

        # Parse the config YAML file and ensure that it is set up correctly
        yaml_data = self._parse_yaml(config_yaml)
        self._set_from_yaml(yaml_data)
        self._check_required_opts()
        self._expand_user_paths()
        self._set_stage_dirs()
        self._validate_paths()
        self._validate_config()

        # If we're in the fuzzing mode (or one of its sub-stages),
        # set up the working directories
        if stage is not None:
            wd_manager = _WorkingDirManager(self)
            wd_manager.create_working_dirs(stage)

    @classmethod
    def help(cls) -> str:
        """
        Return a help string describing all configuration options.
        :return: Help string
        """
        help_str = "McFuzz Configuration Options:\n"
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
            raise SystemExit(f"[ERROR] YAML file {config_yaml} isn't a valid McFuzz config file.")
        return config_data

    def _set_from_yaml(self, yaml_data: YAMLData) -> None:
        """
        Set configuration values from the parsed YAML data.
        :param yaml_data: Parsed configuration data as a dictionary
        """
        template_cmd_str = yaml_data.get("template_cmd", None)
        if template_cmd_str is None:
            raise _ConfigException("template_cmd",
                                   "template_cmd is a required field in the config file.")
        if not isinstance(template_cmd_str, str):
            raise _ConfigException(
                "template_cmd",
                "template_cmd must be a string containing the command to invoke the target binary, "
                "with '@#' as a placeholder for the target binary and '@@' as a placeholder for "
                "the generated driver input file.")
        self.template_cmd = template_cmd_str.split()

        self.bin_native = yaml_data.get("bin_native", self.bin_native)
        self.bin_instrumented = yaml_data.get("bin_instrumented", self.bin_instrumented)

        self.working_dir = yaml_data.get("working_dir", self.working_dir)
        self.archive_dir = yaml_data.get("archive_dir", self.archive_dir)
        self.force_working_dir_overwrite = yaml_data.get("force_working_dir_overwrite",
                                                         self.force_working_dir_overwrite)

        self.model_root = yaml_data.get("model_root", self.model_root)

        self.discard_non_leaky_traces = yaml_data.get("discard_non_leaky_traces",
                                                      self.discard_non_leaky_traces)
        self.compression_tool = yaml_data.get("compression_tool", self.compression_tool)
        self.tracing_ignorelist = yaml_data.get("tracing_ignorelist", self.tracing_ignorelist)
        self.tracing_entrypoint = yaml_data.get("tracing_entrypoint", self.tracing_entrypoint)
        self.max_spec_window = yaml_data.get("max_spec_window", self.max_spec_window)

        self.tracing_total_timeout_s = yaml_data.get("tracing_total_timeout_s",
                                                     self.tracing_total_timeout_s)
        self.tracing_timeout_s = yaml_data.get("tracing_timeout_s", self.tracing_timeout_s)
        self.fuzzing_timeout_s = yaml_data.get("fuzzing_timeout_s", self.fuzzing_timeout_s)

        self.num_workers_fuzz_gen = yaml_data.get("num_workers_fuzz_gen", self.num_workers_fuzz_gen)
        self.num_workers_tracer = yaml_data.get("num_workers_tracer", self.num_workers_tracer)
        self.num_workers_detector = yaml_data.get("num_workers_detector", self.num_workers_detector)

        self.afl_root = yaml_data.get("afl_root", self.afl_root)
        self.afl_seed_dir = yaml_data.get("afl_seed_dir", self.afl_seed_dir)
        self.afl_exec_timeout_ms = yaml_data.get("afl_exec_timeout_ms", self.afl_exec_timeout_ms)
        self.afl_quiet = yaml_data.get("afl_quiet", self.afl_quiet)

        self.contract_observation_clause = yaml_data.get("contract_observation_clause",
                                                         self.contract_observation_clause)
        self.contract_execution_clause = yaml_data.get("contract_execution_clause",
                                                       self.contract_execution_clause)

        self.num_secrets_per_class = yaml_data.get("num_secrets_per_class",
                                                   self.num_secrets_per_class)
        self.boost_seed = yaml_data.get("boost_seed", self.boost_seed)

        self.report_verbosity = yaml_data.get("report_verbosity", self.report_verbosity)
        self.allowlist = yaml_data.get("allowlist", self.allowlist)
        self.keep_stage4_files = yaml_data.get("keep_stage4_files", self.keep_stage4_files)

        self.pipeline_trace_and_detect = yaml_data.get("pipeline_trace_and_detect",
                                                       self.pipeline_trace_and_detect)
        self.intermediate_report_interval = yaml_data.get("intermediate_report_interval",
                                                          self.intermediate_report_interval)

        # check for attempts to set internal config variables
        for opt in self._internal_opts:
            if opt in yaml_data:
                raise _ConfigException(
                    opt, f"Option {opt} is for internal use only and should not be set in"
                    " the user config; use working_dir instead.")

    def _expand_user_paths(self) -> None:
        """ Iterate over all config variables and expand user paths (i.e., paths containing ~) """
        for var_name, var_value in self.__dict__.items():
            if isinstance(var_value, str):
                if var_value.startswith("~/"):
                    setattr(self, var_name, os.path.expanduser(var_value))

        # special handling for target_cmd, as it is a list of strings
        if self.template_cmd is not None:
            expanded_cmd = []
            for part in self.template_cmd:
                if part.startswith("~/"):
                    expanded_cmd.append(os.path.expanduser(part))
                else:
                    expanded_cmd.append(part)
            self.template_cmd = expanded_cmd

    def _check_required_opts(self) -> None:
        """ Check that all required options are set in the config """
        for opt in self._required_opts:
            val = getattr(self, opt, None)
            if val is None or val == "":
                raise _ConfigException(opt, f"{opt} is a required option and must be set.")

    def _validate_paths(self) -> None:
        """ Validate existence of directories and files """
        if not pathlib.Path(self.model_root).is_dir():
            raise _ConfigException("model_root", f"{self.model_root} does not exist.")
        if not pathlib.Path(self.afl_root).is_dir():
            raise _ConfigException("afl_root", f"{self.afl_root} does not exist.")
        if not pathlib.Path(self.afl_seed_dir).is_dir():
            raise _ConfigException("afl_seed_dir", f"{self.afl_seed_dir} does not exist.")
        if self.allowlist is not None and not pathlib.Path(self.allowlist).is_file():
            raise _ConfigException(
                "allowlist", f"Allowlist file {self.allowlist} does not exist. \n"
                "Please create it or remove the allowlist option from the config file.")

    def _validate_config(self) -> None:
        """ Validate the configuration values """

        if self.num_secrets_per_class < 2:
            raise _ConfigException(
                "num_secrets_per_class", "num_secrets_per_class must be at least 2."
                "(fuzzing is meaningless otherwise).")
        if self.num_secrets_per_class > 10:
            console.warn("num_secrets_per_class is set to a high value;"
                         " this may lead to very long fuzzing times.")

        if self.compression_tool not in ["gzip", "bzip2", "none"]:
            raise _ConfigException("compression_tool",
                                   "compression_tool must be one of: gzip, bzip2, none.")

        if self.num_workers_fuzz_gen < 1:
            raise _ConfigException("num_workers_fuzz_gen",
                                   "num_workers_fuzz_gen must be at least 1.")
        if self.num_workers_tracer < 1:
            raise _ConfigException("num_workers_tracer", "num_workers_tracer must be at least 1.")
        if self.num_workers_detector < 1:
            raise _ConfigException("num_workers_detector",
                                   "num_workers_detector must be at least 1.")

        if not pathlib.Path(self.bin_native).is_file():
            raise _ConfigException("bin_native", f"{self.bin_native} does not exist.")
        if not pathlib.Path(self.bin_instrumented).is_file():
            raise _ConfigException("bin_instrumented", f"{self.bin_instrumented} does not exist.")

        if self.template_cmd.count("@@") != 1:
            raise _ConfigException(
                "template_cmd", "template_cmd must contain exactly one occurrence of '@@' as "
                "a placeholder for the driver input file.")
        if self.template_cmd.count("@#") != 1:
            raise _ConfigException(
                "template_cmd", "template_cmd must contain exactly one occurrence of '@#' as "
                "a placeholder for the binary-under-test.")

        if self.intermediate_report_interval < 0:
            raise _ConfigException("intermediate_report_interval",
                                   "intermediate_report_interval must not be negative.")
        if self.intermediate_report_interval > 0 and not self.pipeline_trace_and_detect:
            console.warn("intermediate_report_interval is set, but pipeline_trace_and_detect is "
                         "disabled; no intermediate reports will be generated.")

    def _set_stage_dirs(self) -> None:
        """ Set the internal stage working directories based on the main working directory """
        assert self.working_dir is not None, \
            "working_dir must be set before setting stage directories."
        self.stage1_wd = os.path.join(self.working_dir, "stage1")
        self.stage2_wd = os.path.join(self.working_dir, "stage2")
        self.stage3_wd = os.path.join(self.working_dir, "stage3")
        self.stage4_wd = os.path.join(self.working_dir, "stage4")
