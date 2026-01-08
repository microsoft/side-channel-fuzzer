#!/usr/bin/env python3
"""
File: Command Line Interface to Contract-based Software Fuzzer (ConSFuzz)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import sys
from mcfz.cli import main

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
