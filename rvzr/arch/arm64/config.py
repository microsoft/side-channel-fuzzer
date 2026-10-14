"""
File: arm64-specific configuration data (pure-data ArchConf instance).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=duplicate-code  # justification: intentionally shared with the x86 config
from rvzr.arch.arch_conf import ArchConf

ARCH_CONF = ArchConf(
    isa="arm64",
    instruction_categories=("general-arithmetic", "general-dataxfer"),
    known_leak_groups=(),  # no known-leak groups are defined on arm64
    # in contrast to x86, on ARM64, we handle all fault types by default
    baseline_handled_faults=frozenset({"PF", "DE", "DB", "BP", "BR", "UD", "GP"}),
    # FIXME: these fault classes mirror x86; the mapping needs to be adapted for ARM64
    fault_class_map={
        "div-by-zero": "DE",
        "div-overflow": "DE",
        "opcode-undefined": "UD",
        "breakpoint": "BP",
        "debug-register": "DB",
        "non-canonical-access": "GP",
        "user-to-kernel-access": "PF",
    },
    actor_modes=("host",),
    actor_privilege_levels=("kernel",),
    allowed_data_properties=(
        "present",
        "writable",
        "user",
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
        "accessed": True,
        "executable": False,
        "randomized": False,
    },
    data_ept_properties_template={
        "present": True,
        "writable": True,
        "executable": False,
        "accessed": True,
        "user": False,
        "randomized": False,
    },
)
