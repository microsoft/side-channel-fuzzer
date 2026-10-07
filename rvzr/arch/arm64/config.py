"""
File: arm64-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=duplicate-code  # justification: intentionally shared with the x86 config
from typing import List, Dict

_option_values = {
    'actor': [
        'name',
        'mode',
        'privilege_level',
        'data_properties',
        'data_ept_properties',
        'observer',
        'instruction_blocklist',
        'fault_blocklist',
    ],
    "actor_mode": ['host',],
    "actor_privilege_level": ['kernel',],
    "actor_data_properties": [
        'present',
        'writable',
        'user',
        'accessed',
        'dirty',
        'executable',
        'reserved_bit',
        'randomized',
    ],
    "actor_data_ept_properties": [
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        'reserved_bit',
        'randomized',
    ],
    'suppress_known_leaks': [
        # no known-leak groups are defined on arm64
    ],
}

# in contrast to x86, on ARM64, we handle all fault types by default
_handled_faults: List[str] = ["PF", "DE", "DB", "BP", "BR", "UD", "PF", "GP"]

instruction_categories: List[str] = ["general-arithmetic", "general-dataxfer"]
""" instruction_categories: a default list of tested instruction categories """

suppress_known_leaks: List[str] = []
""" suppress_known_leaks: no known-leak groups are defined on arm64 """

# FIXME: this is copied from x86, needs to be adapted for ARM64
_generator_fault_to_fault_name: Dict[str, str] = {
    'div-by-zero': "DE",
    'div-overflow': "DE",
    'opcode-undefined': "UD",
    'breakpoint': "BP",
    'debug-register': "DB",
    'non-canonical-access': "GP",
    'user-to-kernel-access': "PF",
}

_actor_default = {
    'name': "main",
    'mode': "host",
    'privilege_level': "kernel",
    'observer': False,
    'data_properties': {
        'present': True,
        'writable': True,
        'user': False,
        'accessed': True,
        'executable': False,
        'randomized': False,
    },
    'data_ept_properties': {
        'present': True,
        'writable': True,
        'executable': False,
        'accessed': True,
        'user': False,
        'randomized': False,
    },
    'instruction_blocklist': set(),
    'fault_blocklist': set(),
}
