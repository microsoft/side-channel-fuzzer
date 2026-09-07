"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # justification: test conventions
# pylint: disable=missing-class-docstring  # justification: test conventions
# pylint: disable=protected-access  # justification: tests inspect internal state
from typing import Dict, Collection

import os
import tempfile
import shutil
import unittest
from unittest.mock import patch, mock_open
from io import StringIO

import yaml
from mcfz.config import Config, _ConfigException


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

        # Create dummy binary files for bin_native and bin_instrumented
        self.bin_native = os.path.join(self.temp_dir, "bin_native")
        self.bin_instrumented = os.path.join(self.temp_dir, "bin_instrumented")
        with open(self.bin_native, "w") as f:
            f.write("dummy")
        with open(self.bin_instrumented, "w") as f:
            f.write("dummy")

        # Basic valid config
        self.valid_config = self._make_config()

    def tearDown(self) -> None:
        # Clean up temporary directories
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self._reset_config_instantiation()

    def _reset_config_instantiation(self) -> None:
        # Helper method to reset the Config instantiation flag
        Config._Config__config_instantiated = False  # type: ignore

    def _make_config(self, *, exclude: Collection[str] = (), **overrides: object) -> str:
        """Build a YAML config string from defaults with optional overrides and field exclusions.

        Use ``exclude`` to remove fields entirely (e.g., exclude=["afl_seed_dir"]).
        Use keyword arguments to override or add fields (e.g., model_root="/other/path").
        """
        defaults: Dict[str, object] = {
            "working_dir": self.working_dir,
            "archive_dir": self.archive_dir,
            "model_root": self.model_root,
            "afl_root": self.afl_root,
            "afl_seed_dir": self.afl_seed_dir,
            "template_cmd": "@# @@ @#_output",
            "bin_native": self.bin_native,
            "bin_instrumented": self.bin_instrumented,
        }
        defaults.update(overrides)
        for key in exclude:
            defaults.pop(key, None)
        return yaml.dump(defaults, default_flow_style=False)

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
            # template_cmd is checked first in _set_from_yaml, before _check_required_opts
            config_data = "some_other_field: value"
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("template_cmd", str(cm.exception))

            self._reset_config_instantiation()

            # working_dir (requires template_cmd to be present so _set_from_yaml succeeds)
            config_data = self._make_config(exclude=["working_dir"])
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
                self.assertTrue(os.path.exists(config.stage4_wd))

    def test_config_nonexistent_working_dir(self) -> None:
        # Test that nonexistent working directory raises exception
        config_data = self._make_config(working_dir="/nonexistent/directory")
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

        config_data = self._make_config(force_working_dir_overwrite=True)
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                Config("config.yaml", "fuzz")
                # Check that the working directory is empty
                self.assertEqual(len(os.listdir(self.working_dir)), 4)  # Only stage dirs

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

        config_data = self._make_config(exclude=["archive_dir"])

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException):
                    Config("config.yaml", "fuzz")

    def _populate_stage_dirs(self) -> Dict[str, str]:
        """Create the stage3/stage4 directories with one leftover file each, as they would look
        after a previous run. Returns the paths of the leftover files."""
        leftovers = {}
        for stage in ("stage3", "stage4"):
            stage_dir = os.path.join(self.working_dir, stage)
            os.makedirs(stage_dir)
            leftover = os.path.join(stage_dir, "leftover")
            with open(leftover, "w") as f:
                f.write("stale")
            leftovers[stage] = leftover
        return leftovers

    @patch('sys.stdout', new_callable=StringIO)
    def test_pipelined_trace_resets_stage4(self, _: StringIO) -> None:
        # In pipelined mode the tracer also writes leak files into stage4, so the trace stage
        # owns that directory too: stale results from a previous run must not survive into
        # the new report
        leftovers = self._populate_stage_dirs()
        config_data = self._make_config(
            force_working_dir_overwrite=True, pipeline_trace_and_detect=True)

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                Config("config.yaml", "trace")

        self.assertFalse(os.path.exists(leftovers["stage3"]))
        self.assertFalse(os.path.exists(leftovers["stage4"]))

    @patch('sys.stdout', new_callable=StringIO)
    def test_pipelined_report_preserves_stage4(self, _: StringIO) -> None:
        # In pipelined mode the leaks were already detected during tracing, so the report stage
        # owns no directory of its own and must preserve the leak files it is about to merge
        leftovers = self._populate_stage_dirs()
        config_data = self._make_config(
            force_working_dir_overwrite=True, pipeline_trace_and_detect=True)

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                Config("config.yaml", "report")

        self.assertTrue(os.path.exists(leftovers["stage4"]))

    @patch('sys.stdout', new_callable=StringIO)
    def test_sequential_report_resets_stage4(self, _: StringIO) -> None:
        # Without pipelining, the report stage produces the leak files itself and therefore
        # still owns - and resets - the stage4 directory
        leftovers = self._populate_stage_dirs()
        config_data = self._make_config(force_working_dir_overwrite=True)

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                Config("config.yaml", "report")

        self.assertFalse(os.path.exists(leftovers["stage4"]))
        self.assertTrue(os.path.exists(leftovers["stage3"]))

    def test_config_invalid_model_root(self) -> None:
        # Test that invalid model_root raises exception
        config_data = self._make_config(model_root="/nonexistent/model")
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("model_root", str(cm.exception))

    def test_config_invalid_afl_root(self) -> None:
        # Test that invalid afl_root raises exception
        config_data = self._make_config(afl_root="/nonexistent/afl")
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("afl_root", str(cm.exception))

    def test_config_missing_afl_seed_dir(self) -> None:
        # Test that missing afl_seed_dir raises exception
        config_data = self._make_config(exclude=["afl_seed_dir"])
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("afl_seed_dir", str(cm.exception))

    def test_config_internal_option_rejection(self) -> None:
        # Test that internal options cannot be set via YAML
        config_data = self._make_config(stage1_wd="/some/path")
        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=config_data)):
                with self.assertRaises(_ConfigException) as cm:
                    Config("config.yaml", "fuzz")
                self.assertIn("internal use only", str(cm.exception))

    def test_config_stage_directories(self) -> None:
        # Test different stage directory behaviors

        # Test boost with existing empty directory
        os.makedirs(os.path.join(self.working_dir, "stage2"))

        with patch("os.path.exists", return_value=True):
            with patch("builtins.open", mock_open(read_data=self.valid_config)):
                config = Config("config.yaml", "boost")
                self.assertEqual(os.listdir(config.stage2_wd), [])

        self._reset_config_instantiation()

        # Test fuzz_gen stage
        # We need a functional os.path.exits here, so we cannot mock it
        # Thus, we will create a temporary file for the config.yaml
        config_file = os.path.join(self.temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write(self.valid_config)
        config = Config(config_file, "fuzz_gen")
        self.assertEqual(os.listdir(config.stage1_wd), [])
