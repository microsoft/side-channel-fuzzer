#!/usr/bin/env python3
"""
File: Command Line Interface to Model-based Constant-time Fuzzer (McFuzz, or mcfz for short)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import sys
from mcfz.cli import main

if __name__ == '__main__':
    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\nINFO: Interrupted by user", file=sys.stderr)
        exit_code = 130  # 128 + SIGINT
    sys.exit(exit_code)
