"""
File: arm64-specific ISA constraints: the capability tables of the components (model backends,
executor, generator), the test-case contract, and the config-driven filtering policies.
This is the single per-arch source of truth for built-in constraints; the tables are merged
by factory.get_instruction_pool_constraints() based on the requested backends and config values.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Final

from rvzr.isa_spec import InstructionPoolConstraints, PerArchConstraints

# ==================================================================================================
# Component capabilities
# ==================================================================================================
# Capability constraints of the model backends, keyed by `model_backend` config values;
# `dynamorio` is absent because the DynamoRIO backend does not support arm64
_MODEL_CONSTRAINTS = {
    # categories that the arm64 Unicorn backend emulates correctly
    "unicorn":
        InstructionPoolConstraints(
            supported_categories={
                "general-arithmetic",
                "general-barrier",
                "general-bitwise",
                "general-uncond_branch",
                "general-cond_branch",
                "general-comparison",
                "general-condsel",
                "general-dataxfer",
                "general-misc",
            }),
    "dummy":
        InstructionPoolConstraints.none(),
}

# Capability constraints of the executor (none beyond the test-case contract)
_EXECUTOR_CONSTRAINTS = InstructionPoolConstraints.none()

# Capability constraints of the program generator: the parts of the ISA spec for which it
# cannot generate correct programs or correct sandboxing instrumentation
_GENERATOR_CONSTRAINTS = InstructionPoolConstraints.merge([
    # the random generator cannot produce valid floating-point operand values
    InstructionPoolConstraints(blocked_xtypes={"f64", "f32", "f16", "2f16", "bf16"}),
    # the zero registers cannot be used as general-purpose operands
    InstructionPoolConstraints(blocked_registers={"xzr", "wzr"}),
])

# ==================================================================================================
# Test-case contract
# ==================================================================================================
# Constraints stemming from the test-case contract: the shared input format and harness ABI
# (see executor_km/include/sandbox_constants.h and the harness register conventions).
# These constraints apply to every backend, including `dummy`.
_CONTRACT_CONSTRAINTS = InstructionPoolConstraints(
    blocked_registers={
        # the harness reserves everything above X5 (free: x0 ... x5)
        'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
        'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
        'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31',
        'sp',
        'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
        'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23',
        'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30', 'w31',
        'wsp', 'wpc',
    },
)  # yapf: disable

# ==================================================================================================
# Config-driven policies
# ==================================================================================================
# Known-leak suppression groups, driven by CONF.suppress_known_leaks (none defined on arm64)
_KNOWN_LEAK_GROUPS: dict[str, InstructionPoolConstraints] = {}

# Fault-suppression entries, driven by CONF.faults_allowlist (none defined on arm64)
_FAULT_SUPPRESSION: dict[str, InstructionPoolConstraints] = {}

ARCH_CONSTRAINTS: Final[PerArchConstraints] = PerArchConstraints(
    model=_MODEL_CONSTRAINTS,
    executor=_EXECUTOR_CONSTRAINTS,
    generator=_GENERATOR_CONSTRAINTS,
    contract=_CONTRACT_CONSTRAINTS,
    known_leak_groups=_KNOWN_LEAK_GROUPS,
    fault_suppression=_FAULT_SUPPRESSION,
)
