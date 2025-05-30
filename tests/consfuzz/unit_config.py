"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=protected-access

import os
import tempfile
import shutil
import unittest
from unittest.mock import patch, mock_open
from io import StringIO

import yaml
from consfuzz.config import Config, _ConfigException


class TestConfig(unittest.TestCase):

    # ==============================================================================================
    # Helper methods

    def setUp(self) -> None:
        self._reset_config_instantiation()

        # Create temporary directories for testing
        self.temp_dir = tempfile.mkdtemp()
        self.working_dir = os.path.join(self.temp_dir, "working")
        self.archive_dir = os.path.join(self.temp_dir, "archive")
        self.model_root = os.path.join(self.temp_dir, "model")
        self.afl_root = os.path.join(self.temp_dir, "afl")
        self.afl_seed_dir = os.path.join(self.temp_dir, "seeds")

        # Create the required directories
        os.makedirs(self.working_dir)
        os.makedirs(self.archive_dir)
        os.makedirs(self.model_root)
        os.makedirs(self.afl_root)
        os.makedirs(self.afl_seed_dir)

        # Basic valid config
        self.valid_config = f"""
working_dir: {self.working_dir}
archive_dir: {self.archive_dir}
model_root: {self.model_root}
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""

    def tearDown(self) -> None:
        # Clean up temporary directories
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self._reset_config_instantiation()

    def _reset_config_instantiation(self) -> None:
        # Helper method to reset the Config instantiation flag
        Config._Config__config_instantiated = False  # type: ignore

    # ==============================================================================================
    # Tests

    def test_config_single_instantiation(self) -> None:
        # Test that Config can only be instantiated once
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=self.valid_config)):
                Config("config.yaml", "fuzz")
                with self.assertRaises(RuntimeError):
                    Config("config.yaml", "fuzz")

    def test_config_nonexistent_yaml(self) -> None:
        # Test that missing config file raises SystemExit
        with self.assertRaises(SystemExit):
            Config("nonexistent.yaml", "fuzz")

    def test_config_invalid_yaml(self) -> None:
        # Test that invalid YAML content raises SystemExit
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data="invalid: yaml: content")):
                with self.assertRaises(yaml.scanner.ScannerError):  # type: ignore
                    Config("config.yaml", "fuzz")
            self._reset_config_instantiation()

            with patch("builtins.open", mock_open(read_data="non-dictionary content")):
                with self.assertRaises(SystemExit):
                    Config("config.yaml", "fuzz")

    def test_config_missing_required_fields(self) -> None:
        # Test that missing required fields raises _ConfigException
        with patch("os.path.exists", return_value=True):
            # working_dir
            config_data = "some_other_field: value"
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("working_dir", str(cm.exception))

    def test_config_empty_working_dir(self) -> None:
        # Test configuration with empty working directory
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=self.valid_config)):
                config = Config("config.yaml", "fuzz")
                self.assertEqual(config.working_dir, self.working_dir)
                self.assertTrue(os.path.exists(config.stage1_wd))
                self.assertTrue(os.path.exists(config.stage2_wd))
                self.assertTrue(os.path.exists(config.stage3_wd))

    def test_config_nonexistent_working_dir(self) -> None:
        # Test that nonexistent working directory raises exception
        config_data = f"""
working_dir: /nonexistent/directory
model_root: {self.model_root}
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException):
                    Config("config.yaml", "fuzz")

    @patch('sys.stdout', new_callable=StringIO)
    def test_config_force_overwrite(self, mock_stdout: StringIO) -> None:
        # Test force_working_dir_overwrite functionality
        # Create some files in working directory
        test_file = os.path.join(self.working_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")

        config_data = f"""
working_dir: {self.working_dir}
force_working_dir_overwrite: true
model_root: {self.model_root}
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                Config("config.yaml", "fuzz")
                # Check that the working directory is empty
                self.assertEqual(len(os.listdir(self.working_dir)), 3)  # Only stage dirs

        output = mock_stdout.getvalue()
        self.assertIn("removing", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_config_archive_functionality(self, mock_stdout: StringIO) -> None:
        # Test archiving functionality when working dir is not empty
        # Create a file in working directory
        test_file = os.path.join(self.working_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")

        # We need a functional os.path.exits here, so we cannot mock it
        # Thus, we will create a temporary file for the config.yaml
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write(self.valid_config)
        Config(config_file, "fuzz")

        output = mock_stdout.getvalue()
        self.assertIn("Archived", output)

        # Check that archive was created
        archives = os.listdir(self.archive_dir)
        self.assertEqual(len(archives), 1)
        self.assertTrue(archives[0].endswith(".tar.gz"))

    def test_config_no_archive_no_force(self) -> None:
        # Test that exception is raised when working dir is not empty without archive or force
        # Create a file in working directory
        test_file = os.path.join(self.working_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")

        config_data = f"""
working_dir: {self.working_dir}
model_root: {self.model_root}
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException):
                    Config("config.yaml", "fuzz")

    def test_config_invalid_model_root(self) -> None:
        # Test that invalid model_root raises exception
        config_data = f"""
working_dir: {self.working_dir}
model_root: /nonexistent/model
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("model_root", str(cm.exception))

    def test_config_invalid_afl_root(self) -> None:
        # Test that invalid afl_root raises exception
        config_data = f"""
working_dir: {self.working_dir}
model_root: {self.model_root}
afl_root: /nonexistent/afl
afl_seed_dir: {self.afl_seed_dir}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("afl_root", str(cm.exception))

    def test_config_missing_afl_seed_dir(self) -> None:
        # Test that missing afl_seed_dir raises exception
        config_data = f"""
working_dir: {self.working_dir}
model_root: {self.model_root}
afl_root: {self.afl_root}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("afl_seed_dir", str(cm.exception))

    def test_config_internal_option_rejection(self) -> None:
        # Test that internal options cannot be set via YAML
        config_data = f"""
working_dir: {self.working_dir}
stage1_wd: /some/path
model_root: {self.model_root}
afl_root: {self.afl_root}
afl_seed_dir: {self.afl_seed_dir}
"""
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("internal use only", str(cm.exception))

    def test_config_stage_directories(self) -> None:
        # Test different stage directory behaviors
        # Test stage2 with existing empty directory
        os.makedirs(os.path.join(self.working_dir, "stage2"))

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=self.valid_config)):
                config = Config("config.yaml", "stage2")
                self.assertEqual(os.listdir(config.stage2_wd), [])

        self._reset_config_instantiation()

        # Test pub_gen stage
        # We need a functional os.path.exits here, so we cannot mock it
        # Thus, we will create a temporary file for the config.yaml
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write(self.valid_config)
        config = Config(config_file, "pub_gen")
        self.assertEqual(os.listdir(config.stage1_wd), [])
