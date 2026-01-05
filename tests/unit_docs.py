"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Dict, List, Union

import unittest
import inspect
import pathlib
from rvzr.config import CONF

FILE_DIR = pathlib.Path(__file__).parent.resolve()
DOC_DIR = FILE_DIR.parent / "docs"

ACTOR_SECTION_HEADER = "## <a name=\"actor\"></a> Actor Configuration"
AVAILABLE_OPTIONS_HEADER = '=== "Available Options"'
DEFAULT_VALUE_PREFIX = ":material-water:"
AUTODETECTED_PREFIX = ":octicons-cpu-24:"


def _is_option_name(line: str) -> bool:
    # format: #### `option_name`
    return line.startswith("#### `") and "`" in line[6:]


def parse_config_options_from_docs(doc_lines: List[str]) -> Dict[str, List[Union[str, List[str]]]]:
    """
    Parse configuration options from the documentation.

    :param doc_lines: Lines from the config.md file
    :return: Dictionary mapping option names to [default_value, [available_options]]
    """
    doc_options: Dict[str, List[Union[str, List[str]]]] = {}
    curr_name: str = ""
    in_actor_section: bool = False
    in_available_options: bool = False

    for line in doc_lines:
        # Detect actor section
        if ACTOR_SECTION_HEADER in line:
            in_actor_section = True
        elif line.startswith("## "):
            in_actor_section = False

        # Parse option name from heading
        if _is_option_name(line):
            end_idx = line.index("`", 6)
            option_name = line[6:end_idx]

            # Add actor_ prefix if in actor section
            if in_actor_section:
                curr_name = f"actor_{option_name}"
            else:
                curr_name = option_name

            doc_options[curr_name] = ["", []]
            in_available_options = False

        # Parse default value (e.g., :material-water: `value`)
        elif curr_name and doc_options[curr_name][0] == "":
            if DEFAULT_VALUE_PREFIX in line and "`" in line:
                # Find backtick-quoted value after :material-water:
                parts = line.split("`")
                for j in range(1, len(parts), 2):
                    if j > 0 and DEFAULT_VALUE_PREFIX in parts[j - 1]:
                        doc_options[curr_name][0] = parts[j]
                        break
            elif AUTODETECTED_PREFIX in line:
                # Auto-detected default value
                doc_options[curr_name][0] = "(auto-detected)"

        # Detect Available Options section
        elif AVAILABLE_OPTIONS_HEADER in line:
            in_available_options = True

        # Parse available options (e.g., `opt1` | `opt2` | `opt3`)
        elif in_available_options and curr_name and "`" in line and "|" in line:
            options_line = line.strip()
            if options_line.startswith("`"):
                # Split by | and extract values between backticks
                parts = options_line.split("|")
                options = []
                for part in parts:
                    part = part.strip()
                    if part.startswith("`") and part.endswith("`"):
                        options.append(part.strip("`"))
                doc_options[curr_name][1] = options
            in_available_options = False

    return doc_options


class DocumentationTest(unittest.TestCase):
    """
    A class for testing if the documentation is up to date.
    """
    longMessage = False

    def test_conf_docs(self) -> None:
        # Test if the documentation contains all the config options.

        # get the text of the config documentation
        with open(DOC_DIR / "ref/config.md", "r") as f:
            doc_text = f.read()

        # get a list of config options
        options = [
            k[0]
            for k in inspect.getmembers(CONF, lambda x: not inspect.isroutine(x))
            if not k[0].startswith("_")
        ]

        # check if each option is in the documentation
        for option in options:
            self.assertTrue(option in doc_text, msg=f"{option} not found in documentation")

    def test_conf_options_docs(self) -> None:
        # Test if the documentation contains all possible values for the config options.

        # get the text of the config documentation
        with open(DOC_DIR / "ref/config.md", "r") as f:
            doc_text = f.readlines()

        # build a map of config options to their possible values in the doc
        doc_options = parse_config_options_from_docs(doc_text)

        # get a list of config options
        options = [
            k for k in inspect.getmembers(CONF, lambda x: not inspect.isroutine(x))
            if not k[0].startswith("_")
        ]
        alternatives = CONF._option_values  # pylint: disable=protected-access

        # check if all alternatives and defaults are documented
        for name, default_ in options:
            doc_default = doc_options[name][0]
            assert isinstance(doc_default, str)
            if not doc_default.startswith("("):
                self.assertEqual(
                    str(default_),
                    doc_default,
                    msg=f"Default for `{name}` is incorrect: {default_} != {doc_default}")

            if doc_options[name][1]:
                doc_values = doc_options[name][1]
                self.assertSetEqual(
                    set(alternatives[name]),
                    set(doc_values),
                    msg=f"Options for `{name}` are incorrect: {alternatives[name]} != {doc_values}")
