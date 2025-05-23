"""
File: Global ConSFuzz configuration.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Final, Dict, Optional

import os
import pathlib
import yaml


class ConfigException(SystemExit):
    """ Custom exception class for configuration errors. """

    def __init__(self, var, message: str) -> None:
        super().__init__(f"[ERROR] Invalid value of config variable {var}\nIssue: {message}\n")


class Config:
    """
    Class responsible for storing global fuzzing configuration.

    Note: This class is expected to be instantiated only once by `rvzr-sw.py` and passed to all
          other modules by reference.
    """

    __config_instantiated: bool = False
    """ Class-local flag that allows us to detect attempts to instantiate Config more than once. """

    working_dir: Final[str]
    stage1_wd: Final[str]
    stage2_wd: Final[str]
    stage3_wd: Final[str]

    model_root: str = "~/.local/dynamorio/"
    """ Path to the directory containing the installation of the leakage model. """

    afl_root: str = "~/.local/afl/"
    """ Path to the directory containing the installation of AFL++. """

    afl_seed_dir: Optional[str] = None
    """ Path to the directory containing the seed corpus for AFL++. """

    # afl_qemu_mode: bool = False
    # """ Flag indicating whether AFL++ should be run in QEMU mode. """

    secret_size_bytes: int = 32
    """ Size of the secret (private) input, in bytes. """

    contract_observation_clause: str = "ct"
    contract_execution_clause: str = "seq"

    def __init__(self, config_yaml: str, working_dir: str) -> None:
        if self.__config_instantiated:
            raise RuntimeError("Config class should be instantiated only once.")
        self.__config_instantiated = True

        self.working_dir = working_dir
        self._create_working_dirs()

        yaml_data = self._parse_yaml(config_yaml)
        self._set_from_yaml(yaml_data)
        self._validate_config()

    def _create_working_dirs(self) -> None:
        """
        Create the working directories for each stage of the fuzzing process.
        """
        if not self.working_dir:
            raise ConfigException("working_dir", "Working directory is not set.")
        if not pathlib.Path(self.working_dir).expanduser().is_dir():
            raise ConfigException("working_dir", f"{self.working_dir} does not exist.")
        self.stage1_wd = os.path.join(self.working_dir, "stage1")  # type: ignore
        self.stage2_wd = os.path.join(self.working_dir, "stage2")  # type: ignore
        self.stage3_wd = os.path.join(self.working_dir, "stage3")  # type: ignore

    def _parse_yaml(self, config_yaml: str) -> Dict:
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

    def _set_from_yaml(self, yaml_data: Dict) -> None:
        """
        Set configuration values from the parsed YAML data.
        :param yaml_data: Parsed configuration data as a dictionary
        """
        model_root = yaml_data.get("model_root", None)
        if model_root is not None:
            self.model_root = model_root

        afl_root = yaml_data.get("afl_root", None)
        if afl_root is not None:
            self.afl_root = afl_root

        afl_seed_dir = yaml_data.get("afl_seed_dir", None)
        if afl_seed_dir is not None:
            self.afl_seed_dir = afl_seed_dir

        # afl_qemu_mode = yaml_data.get("afl_qemu_mode", None)
        # if afl_qemu_mode is not None:
        #     if isinstance(afl_qemu_mode, bool):
        #         self.afl_qemu_mode = afl_qemu_mode
        #     else:
        #         raise ConfigException("afl_qemu_mode", "Expected a boolean value.")

    def _validate_config(self) -> None:
        """
        Validate the configuration values.
        """
        if not pathlib.Path(self.model_root).expanduser().is_dir():
            raise ConfigException("model_root", f"{self.model_root} does not exist.")
        if not pathlib.Path(self.afl_root).expanduser().is_dir():
            raise ConfigException("afl_root", f"{self.afl_root} does not exist.")
        if self.afl_seed_dir is None:
            raise ConfigException("afl_seed_dir", "Seed directory is not set.")
        if not pathlib.Path(self.afl_seed_dir).expanduser().is_dir():
            raise ConfigException("afl_seed_dir", f"{self.afl_seed_dir} does not exist.")
