"""
File: x86-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=duplicate-code  # justification: intentionally shared with the arm64 config
from typing import List

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
    "actor_mode": [
        'host',
        'guest',
    ],
    "actor_privilege_level": [
        'kernel',
        'user',
    ],
    "actor_data_properties": [
        'present',
        'writable',
        'user',
        'write-through',
        'cache-disable',
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
        'fpvi',
        'div64',
    ],
}

# by default, we always handle page faults
_handled_faults: List[str] = ["PF"]

x86_executor_enable_prefetcher: bool = False
""" x86_executor_enable_prefetcher: enable all prefetchers"""
x86_executor_enable_ssbp_patch: bool = True
""" x86_executor_enable_ssbp_patch: enable a patch against Speculative Store Bypass"""
x86_enable_hpa_gpa_collisions: bool = False
""" x86_enable_hpa_gpa_collisions: enable collisions between HPA and GPA;
useful for testing Foreshadow-like leaks"""
x86_generator_align_locks: bool = True
""" x86_generator_align_locks: align all generated locks to 8 bytes """

instruction_categories: List[str] = ["BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"]
""" instruction_categories: a default list of tested instruction categories """

suppress_known_leaks: List[str] = ["fpvi", "div64"]
""" suppress_known_leaks: suppress all known-leak groups by default """

_generator_fault_to_fault_name = {
    'div-by-zero': "DE",
    'div-overflow': "DE",
    'opcode-undefined': "UD",
    'breakpoint': "BP",
    'debug-register': "DB",
    'non-canonical-access': "GP",
    'user-to-kernel-access': "PF",
    'page-fault': "PF"
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
        'write-through': False,
        'cache-disable': False,
        'accessed': True,
        'dirty': True,
        'executable': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'data_ept_properties': {
        'present': True,
        'writable': True,
        'executable': False,
        'accessed': True,
        'dirty': True,
        'user': False,
        'reserved_bit': False,
        'randomized': False,
    },
    'instruction_blocklist': set(),
    'fault_blocklist': set(),
}
