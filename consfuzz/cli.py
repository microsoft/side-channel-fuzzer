"""
File: Function definitions for using Contract-based Software Fuzzer (ConSFuzz) as command-line tool
(Note: the actual CLI is accessed via consfuzz.py)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Any
import os
from argparse import ArgumentParser

from typing_extensions import get_args

from .config import Config, FuzzingStages
from .fuzzer import FuzzerCore

CMD_HELP =\
    "Command to execute (e.g., 'openssl enc -e -aes256 -out enc.bin -in @@ -pbkdf2 -pass @#').\n" \
    "NOTE: use '@@' as a placeholder for generated public argument and\n" \
    "'@#' for generated private argument"


def _parse_args() -> Any:  # pylint: disable=r0915
    parser = ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest='subparser_name', help="Subcommand to run")
    subparsers.required = True

    # ==============================================================================================
    # Common arguments
    common_parser = ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=False,
        help="Path to the configuration file (YAML) that will be used during fuzzing.",
    )

    # ==============================================================================================
    # Phase 1: Public input generation (AFL++ interface)
    pub_gen = subparsers.add_parser('pub_gen', add_help=True, parents=[common_parser])
    pub_gen.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Fuzzing timeout, in seconds (default: 10)",
    )
    # TODO: target-cov is not used yet, but it will be used in the future to control the coverage
    # pub_gen.add_argument(
    #     "--target-cov",
    #     type=int,
    #     default=10,
    #     help="Target coverage to achieve, in percentage (default: 10)",
    # )

    # everything after '--' is saved into 'target_cmd' argument
    pub_gen.add_argument(
        "target_cmd",
        nargs="+",
        help=CMD_HELP,
    )

    # ==============================================================================================
    # Phase 2: Secret input generation and collection of contract traces
    stage2 = subparsers.add_parser('stage2', add_help=True, parents=[common_parser])
    stage2.add_argument(
        "-n",
        "--num-sec-inputs",
        type=int,
        default=10,
        help="Number of secret inputs to generate per public input (default: 10)",
    )

    # everything after '--' is saved into 'target_cmd' argument
    stage2.add_argument(
        "target_cmd",
        nargs="+",
        help=CMD_HELP,
    )

    # ==============================================================================================
    # Phase 3: Analysis of traces and reporting of leaks
    report = subparsers.add_parser('report', add_help=True, parents=[common_parser])
    report.add_argument(
        "-b",
        "--target-binary",
        type=str,
        required=True,
        help="Path to the target binary to be fuzzed (e.g., '/usr/bin/openssl')",
    )

    return parser.parse_args()


def _validate_args(args: Any) -> bool:
    """
    Validate the command-line arguments, beyond the basic checks done by argparse.
    :param args: parsed CLI arguments
    :return: True if paths are valid, False otherwise
    """
    if args.subparser_name == 'report':
        # check if target_binary exists
        if not args.target_binary or not os.path.exists(args.target_binary):
            print(f"ERROR: Target binary '{args.target_binary}' not found")
            return False

    return True


def main() -> int:
    """ Main function for the CLI """
    args = _parse_args()
    if not _validate_args(args):
        return 1

    assert args.subparser_name in get_args(FuzzingStages)
    config = Config(args.config, args.subparser_name)
    fuzzer = FuzzerCore(config)

    # Start the fuzzer in the mode requested by the user
    if args.subparser_name == 'pub_gen':
        return fuzzer.generate_public_inputs(
            cmd=args.target_cmd,
            target_cov=0,  # TODO: will be replaced with args.target_cov when implemented
            timeout_s=args.timeout,
        )
    if args.subparser_name == 'stage2':
        return fuzzer.stage2(
            cmd=args.target_cmd,
            num_sec_inputs=args.num_sec_inputs,
        )
    if args.subparser_name == 'report':
        return fuzzer.report(target_binary=args.target_binary)

    print("ERROR: Unknown subcommand")
    return 1
