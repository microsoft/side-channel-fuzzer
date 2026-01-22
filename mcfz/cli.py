"""
File: Function definitions for using Model-based Constant-time Fuzzer (McFuzz) as command-line tool
(Note: the actual CLI is accessed via mcfz.py)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Any
from argparse import ArgumentParser

from typing_extensions import get_args

from .config import Config, TestingStages
from .fuzzer import FuzzerCore

CMD_HELP =\
    "Command to execute (e.g., 'openssl-driver -d @@ -p policy.txt').\n" \
    "NOTE: use '@@' as a placeholder for generated driver input files."


def _parse_args() -> Any:  # pylint: disable=r0915
    parser = ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest='subparser_name', help="Subcommand to run")

    parser.add_argument(
        "--help-config",
        action='store_true',
        help="Print a help message for the configuration file format and defaults.",
    )

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
    # All Phases Together: Fuzzing-based generation, boosting, tracing, and reporting
    all_phases = subparsers.add_parser('fuzz', add_help=True, parents=[common_parser])
    all_phases.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Fuzzing timeout, in seconds (default: 10)",
    )
    all_phases.add_argument(
        "--native-bin",
        type=str,
        required=True,
        help="Path to a native binary; to be used on the tracing stage instead of the AFL build.",
    )
    # everything after '--' is saved into 'target_cmd' argument
    all_phases.add_argument(
        "target_cmd",
        nargs="+",
        help=CMD_HELP,
    )

    # ==============================================================================================
    # Stage 1: Fuzzing-based input generation (AFL++ interface)
    fuzz_gen = subparsers.add_parser('fuzz_gen', add_help=True, parents=[common_parser])
    fuzz_gen.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Fuzzing timeout, in seconds (default: 10)",
    )
    # TODO: target-cov is not used yet, but it will be used in the future to control the coverage
    # fuzz_gen.add_argument(
    #     "--target-cov",
    #     type=int,
    #     default=10,
    #     help="Target coverage to achieve, in percentage (default: 10)",
    # )

    # everything after '--' is saved into 'target_cmd' argument
    fuzz_gen.add_argument(
        "target_cmd",
        nargs="+",
        help=CMD_HELP,
    )

    # ==============================================================================================
    # Stage 2: Boosting - generate public-equivalent variants
    _ = subparsers.add_parser('boost', add_help=True, parents=[common_parser])
    # no arguments for now

    # ==============================================================================================
    # Stage 3: Collection of contract traces
    trace = subparsers.add_parser('trace', add_help=True, parents=[common_parser])

    # everything after '--' is saved into 'target_cmd' argument
    trace.add_argument(
        "target_cmd",
        nargs="+",
        help=CMD_HELP,
    )

    # ==============================================================================================
    # Stage 4: Analysis of traces and reporting of leaks
    _ = subparsers.add_parser('report', add_help=True, parents=[common_parser])
    # no arguments for now

    args = parser.parse_args()

    # Custom check for subparser name
    if not args.subparser_name and not args.help_config:
        parser.print_help()
        return None

    return args


def _validate_args(args: Any) -> bool:
    """
    Validate the command-line arguments, beyond the basic checks done by argparse.
    :param args: parsed CLI arguments
    :return: True if paths are valid, False otherwise
    """
    # placeholder for future validations

    return True


def main() -> int:
    """ Main function for the CLI """

    # pylint: disable=too-many-return-statements,too-many-branches
    # NOTE: disabling is justified here, as this function is the main entry point
    #       and it naturally has many branches due to different subcommands

    args = _parse_args()
    if args is None:
        return 1
    if not _validate_args(args):
        return 1

    # Config help requested
    if args.help_config:
        print(Config.help())
        return 0

    assert args.subparser_name in get_args(TestingStages)
    config = Config(args.config, args.subparser_name)
    fuzzer = FuzzerCore(config)

    # Start the fuzzer in the mode requested by the user
    if args.subparser_name == 'fuzz_gen':
        fuzzer.fuzz_gen(
            cmd=args.target_cmd,
            target_cov=0,  # TODO: will be replaced with args.target_cov when implemented
            timeout_s=args.timeout,
        )
        return 0

    if args.subparser_name == 'boost':
        fuzzer.boost()
        return 0

    if args.subparser_name == 'trace':
        fuzzer.trace(cmd=args.target_cmd)
        return 0

    if args.subparser_name == 'report':
        fuzzer.report()
        return 0

    if args.subparser_name == 'fuzz':
        fuzzer.all(
            cmd=args.target_cmd,
            native_bin=args.native_bin,
            target_cov=0,  # TODO: will be replaced with args.target_cov when implemented
            timeout_s=args.timeout,
        )
        return 0

    print("ERROR: Unknown subcommand")
    return 1
