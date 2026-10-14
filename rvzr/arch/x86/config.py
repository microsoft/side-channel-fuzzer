"""
File: x86-specific configuration data (pure-data ArchConf instance).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=duplicate-code  # justification: intentionally shared with the arm64 config
from rvzr.arch.arch_conf import ArchConf

ARCH_CONF = ArchConf(
    isa="x86-64",
    instruction_categories=("BASE-BINARY", "BASE-BITBYTE", "BASE-COND_BR"),
    known_leak_groups=("fpvi", "div64"),
    baseline_handled_faults=frozenset({"PF"}),
    fault_class_map={
        "div-by-zero": "DE",
        "div-overflow": "DE",
        "opcode-undefined": "UD",
        "breakpoint": "BP",
        "debug-register": "DB",
        "non-canonical-access": "GP",
        "user-to-kernel-access": "PF",
    },
    actor_modes=("host", "guest"),
    actor_privilege_levels=("kernel", "user"),
    allowed_data_properties=(
        "present",
        "writable",
        "user",
        "write-through",
        "cache-disable",
        "accessed",
        "dirty",
        "executable",
        "reserved_bit",
        "randomized",
    ),
    allowed_data_ept_properties=(
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        "reserved_bit",
        "randomized",
    ),
    data_properties_template={
        "present": True,
        "writable": True,
        "user": False,
        "write-through": False,
        "cache-disable": False,
        "accessed": True,
        "dirty": True,
        "executable": False,
        "reserved_bit": False,
        "randomized": False,
    },
    data_ept_properties_template={
        "present": True,
        "writable": True,
        "executable": False,
        "accessed": True,
        "dirty": True,
        "user": False,
        "reserved_bit": False,
        "randomized": False,
    },
)
