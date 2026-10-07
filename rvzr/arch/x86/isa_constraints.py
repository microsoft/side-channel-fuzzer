"""
File: x86-specific ISA constraints: the capability tables of the components (model backends,
executor, generator), the test-case contract, and the config-driven filtering policies.
This is the single per-arch source of truth for built-in constraints; the tables are merged
by factory.get_instruction_pool_constraints().

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Final

from rvzr.isa_spec import BlockedInstructionVariant, InstructionPoolConstraints, \
    PerArchConstraints

# ==================================================================================================
# Component capabilities
# ==================================================================================================
# Capabilities of the Unicorn backend: the categories it emulates correctly, minus the
# instructions it does not emulate faithfully
_UNICORN_MODEL_CONSTRAINTS: Final[InstructionPoolConstraints] = InstructionPoolConstraints(
    supported_categories={
        # Base x86 - user instructions
        "BASE-BINARY",
        "BASE-BITBYTE",
        "BASE-CMOV",
        "BASE-COND_BR",
        "BASE-CONVERT",
        "BASE-DATAXFER",
        "BASE-FLAGOP",
        "BASE-LOGICAL",
        "BASE-MISC",
        "BASE-NOP",
        "BASE-POP",
        "BASE-PUSH",
        "BASE-SEMAPHORE",
        "BASE-SETCC",
        "BASE-STRINGOP",
        "BASE-WIDENOP",
        # "BASE-ROTATE",      # Unknown bug in Unicorn - emulated incorrectly
        # "BASE-SHIFT",       # Unknown bug in Unicorn - emulated incorrectly

        # Base x86 - control flow and system instructions; emulated correctly, although
        # most of them are excluded by generator/executor `blocked_categories`
        "BASE-UNCOND_BR",
        "BASE-CALL",
        "BASE-RET",
        "BASE-SEGOP",
        "BASE-IO",
        "BASE-IOSTRINGOP",
        "BASE-SYSCALL",
        "BASE-SYSRET",
        "BASE-INTERRUPT",
        "BASE-SYSTEM",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-SEMAPHORE",
        "LONGMODE-SYSCALL",
        "LONGMODE-SYSRET",

        # SIMD extensions
        "SSE-SSE",
        "SSE-DATAXFER",
        "SSE-MISC",
        "SSE-LOGICAL_FP",
        # "SSE-CONVERT",   # require MMX
        # "SSE-PREFETCH",  # prefetch does not trigger a mem access in unicorn
        "SSE2-SSE",
        "SSE2-DATAXFER",
        "SSE2-MISC",
        "SSE2-LOGICAL_FP",
        "SSE2-LOGICAL",
        # "SSE2-CONVERT",  # require MMX
        # "SSE2-MMX",      # require MMX
        "SSE3-SSE",
        "SSE3-DATAXFER",
        # "SSE4-SSE",      # not tested yet
        "SSE4-LOGICAL",
        "SSE4a-BITBYTE",
        "SSE4a-DATAXFER",

        # Misc
        "CLFLUSHOPT-CLFLUSHOPT",
        "CLFSH-MISC",
        # "MPX-MPX",  # no longer supported
        "SMX-SYSTEM",
        "VTX-VTX",
        "XSAVE-XSAVE",
    },
    blocked_instructions={
        # speculative store bypass is not stopped: sfence is missing from the barrier list
        "sfence",
        # cache effects are not visible to the memory-access hook;
        # also blocked by the DynamoRIO backend (see below)
        "clflush",
        "clflushopt",
        "maskmovdqu",
        "maskmovq",
        "vmaskmovdqu",
        "vmaskmovq",
        # known bug: doesn't execute the mem. access hook
        # https://github.com/unicorn-engine/unicorn/issues/990
        "cmpxchg8b",
        "lock cmpxchg8b",
        "cmpxchg16b",
        "lock cmpxchg16b",
        # false positives: Unicorn may emulate the return value incorrectly
        "cpuid",
        # causes crash; for cmpsd, only the BASE-STRINGOP variant is affected (the SSE2 variants
        # are removed by the generator's FP-xtype constraint on every backend)
        "cmpps",
        "cmpss",
        "cmppd",
        "cmpsd",
        # the model initializes only xmm0-7, while mm0-7 stay uninitialized
        "movq2dq",
        "movdq2q",
        # incorrect emulation
        "rcpps",
        "rcpss",
    },
)  # yapf: disable

# Capabilities of the DynamoRIO backend: the categories it traces correctly. The backend has no
# per-opcode handling of data instructions (memory observation is fully generic, see
# model_dynamorio/backend/dispatcher.cpp), so the list covers everything that executes natively
# and accesses memory through regular operands. The blocked instructions are those whose
# "access" observation by the DR tracer is not verified to match the hardware htrace
# (eviction semantics); they are also blocked by the Unicorn backend (see above).
_DR_MODEL_CONSTRAINTS: Final[InstructionPoolConstraints] = InstructionPoolConstraints(
    supported_categories={
        # Base x86 - user instructions
        "BASE-BINARY",
        "BASE-BITBYTE",
        "BASE-CMOV",
        "BASE-COND_BR",
        "BASE-CONVERT",
        "BASE-DATAXFER",
        "BASE-FLAGOP",
        "BASE-LOGICAL",
        "BASE-MISC",
        "BASE-NOP",
        "BASE-POP",
        "BASE-PUSH",
        "BASE-ROTATE",
        "BASE-SEMAPHORE",
        "BASE-SETCC",
        "BASE-SHIFT",
        "BASE-STRINGOP",
        "BASE-WIDENOP",

        # Base x86 - control flow and system instructions; traced correctly, although
        # most of them are excluded by generator/executor `blocked_categories`
        "BASE-UNCOND_BR",
        "BASE-CALL",
        "BASE-RET",
        "BASE-SEGOP",
        "BASE-IO",
        "BASE-IOSTRINGOP",
        "BASE-SYSCALL",
        "BASE-SYSRET",
        "BASE-INTERRUPT",
        "BASE-SYSTEM",
        "LONGMODE-CONVERT",
        "LONGMODE-DATAXFER",
        "LONGMODE-POP",
        "LONGMODE-PUSH",
        "LONGMODE-SEMAPHORE",
        "LONGMODE-SYSCALL",
        "LONGMODE-SYSRET",

        # SIMD and misc extensions
        "3DNOW_PREFETCH-PREFETCH",
        "ADOX_ADCX-ADOX_ADCX",
        "MMX-MMX",
        "MMX-LOGICAL",
        "MMX-DATAXFER",
        "SSE-CONVERT",
        "SSE-DATAXFER",
        "SSE-LOGICAL_FP",
        "SSE-MISC",
        "SSE-PREFETCH",
        "SSE-SSE",
        "SSE2-CONVERT",
        "SSE2-DATAXFER",
        "SSE2-LOGICAL",
        "SSE2-LOGICAL_FP",
        "SSE2-MISC",
        "SSE2-MMX",
        "SSE2-SSE",
        "SSE3-DATAXFER",
        "SSE3-MMX",
        "SSE3-SSE",
        "SSSE3-MMX",
        "SSSE3-SSE",
        "SSE4-LOGICAL",
        "SSE4-SSE",
        "AVX-AVX",
        "AVX-BROADCAST",
        "AVX-DATAXFER",
        "AVX-LOGICAL",
        "AVX-STTNI",
        "AVX2-AVX2",
        "AVX2-BROADCAST",
        "AVX2-DATAXFER",
        "AVX2-LOGICAL",
        "AES-AES",
        "AVXAES-AES",
        "BMI1-BMI1",
        "BMI2-BMI2",
        "MOVBE-DATAXFER",
        "LZCNT-LZCNT",
        "PCLMULQDQ-PCLMULQDQ",
    },
    blocked_instructions={
        "clflush",
        "clflushopt",
        "maskmovdqu",
        "maskmovq",
        "vmaskmovdqu",
        "vmaskmovq",
    },
)  # yapf: disable

# Capability constraints of the model backends, keyed by `model_backend` config values
_MODEL_CONSTRAINTS = {
    "unicorn": _UNICORN_MODEL_CONSTRAINTS,
    "dynamorio": _DR_MODEL_CONSTRAINTS,
    "dummy": InstructionPoolConstraints.none(),
}

# Capability constraints of the executor (shared by the Intel and AMD variants): the parts of
# the ISA spec that would break the measurement environment
_EXECUTOR_CONSTRAINTS = InstructionPoolConstraints(
    # system instructions are not supported
    blocked_categories={
        "BASE-SEGOP",
        "BASE-IO",
        "BASE-IOSTRINGOP",
        "BASE-SYSCALL",
        "BASE-SYSRET",
    },
    blocked_instructions={
        "int",  # requires support of all possible interrupts
        "encls",  # system management instruction
        "vmxon",  # system management instruction
        "stgi",  # system management instruction
        "skinit",  # system management instruction
        "sti",  # enables interrupts
        "cli",  # disables interrupts; blocked just in case
    },
)

# Capability constraints of the program generator: the parts of the ISA spec for which it
# cannot generate correct programs or correct sandboxing instrumentation
_GENERATOR_CONSTRAINTS = InstructionPoolConstraints.merge([
    # the random generator cannot produce valid floating-point operand values
    InstructionPoolConstraints(blocked_xtypes={"f64", "f32", "f16", "2f16", "bf16"}),
    InstructionPoolConstraints(
        # complex control flow is not supported by the random generator
        blocked_categories={"BASE-UNCOND_BR", "BASE-CALL", "BASE-RET"},
        blocked_instructions={
            "enterw",  # requires complex instrumentation
            "enter",  # requires complex instrumentation
            "leavew",  # requires complex instrumentation
            "leave",  # requires complex instrumentation
            "xlat",  # requires support of segment registers
            "xlatb",  # requires support of segment registers
            # postprocessing assumes that all fences are inserted instrumentation:
            # minimization never removes fence lines, and the fence-insertion pass
            # would conflate organic fences with its own
            "lfence",
            "mfence",
            "pcmpestriq",  # conflicting operand size modifiers
            "pcmpestrmq",  # conflicting operand size modifiers
            "vpcmpestriq",  # conflicting operand size modifiers
            "vpcmpestrmq",  # conflicting operand size modifiers
        },
        # segment register handling is not supported
        blocked_registers={"es", "cs", "ss", "ds", "fs", "gs"},
    ),
])

# ==================================================================================================
# Test-case contract
# ==================================================================================================
# Constraints stemming from the test-case contract: the shared input format and harness ABI
# defined by executor_km/include/sandbox_constants.h and the harness register conventions, and
# implemented by the executor (executor_km/x86/data_loader.c), the DynamoRIO adapter
# (model_dynamorio/adapter/test_case_entry.S), and the Unicorn model alike.
# These constraints apply to every backend, including `dummy`.
_CONTRACT_CONSTRAINTS = InstructionPoolConstraints(
    blocked_instructions={
        # MXCSR state is not isolated between inputs: the executor does not save/restore it,
        # so an ldmxcsr in one run would leak rounding/exception-mask state into the next
        "ldmxcsr",
        "stmxcsr",
    },
    blocked_registers={
        # the harness reserves R8-R15, RSP, and RBP for internal use (free: rax ... rsi)
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rbp',
        'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esp', 'ebp',
        'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'sp', 'bp',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'spl', 'bpl',
        # privileged/system state is not part of the test-case input and is not isolated
        'cr0', 'cr2', 'cr3', 'cr4', 'cr8',
        'dr0', 'dr1', 'dr2', 'dr3', 'dr4', 'dr5', 'dr6', 'dr7',
        'xcr0', 'gdtr', 'ldtr', 'idtr', 'tr', 'fsbase', 'gsbase', 'msrs', 'x87control',
        'tsc', 'tscaux', 'mxcsr',
        # the input format has only 8 SIMD slots, so XMM8-15/YMM8-15 are never
        # input-initialized: stale values on hardware vs. zeros in the models
        'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
        'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15',
    },
)  # yapf: disable

# ==================================================================================================
# Config-driven policies
# ==================================================================================================
# Known-leak suppression groups, driven by CONF.suppress_known_leaks. Transitional policy:
# retire a group once a corresponding contract clause or operand-masking instrumentation
# exists (e.g., an `fpvi` execution clause).
_KNOWN_LEAK_GROUPS = {
    # FP arithmetic triggers FPVI (we have neither a contract nor an instrumentation for it).
    # Currently redundant: the generator's FP-xtype constraint removes all of these on every
    # backend; the group becomes load-bearing once that constraint is narrowed to allow
    # SIMD FP operands.
    "fpvi":
        InstructionPoolConstraints(
            blocked_instructions={
                "divps",
                "divss",
                "divpd",
                "divsd",
                "mulss",
                "mulps",
                "mulpd",
                "mulsd",
                "rsqrtps",
                "rsqrtss",
                "sqrtps",
                "sqrtss",
                "sqrtpd",
                "sqrtsd",
                "addps",
                "addss",
                "addpd",
                "addsd",
                "subps",
                "subss",
                "subpd",
                "subsd",
                "addsubpd",
                "addsubps",
                "haddpd",
                "haddps",
                "hsubpd",
                "hsubps",
            }),  # yapf: disable
    # 64-bit division triggers Zero Division Injection; smaller widths are not affected
    "div64":
        InstructionPoolConstraints(
            blocked_instruction_variants={
                BlockedInstructionVariant("div", 64),
                BlockedInstructionVariant("rex div", 64),
                BlockedInstructionVariant("idiv", 64),
                BlockedInstructionVariant("rex idiv", 64),
            }),
}

# Instructions whose only effect is to trigger a fault; each entry is blocked unless its fault
# is explicitly permitted via CONF.faults_allowlist
_FAULT_SUPPRESSION = {
    "opcode-undefined": InstructionPoolConstraints(blocked_instructions={"ud", "ud2"}),
    "breakpoint": InstructionPoolConstraints(blocked_instructions={"int3"}),
    "debug-register": InstructionPoolConstraints(blocked_instructions={"int1"}),
}

ARCH_CONSTRAINTS: Final[PerArchConstraints] = PerArchConstraints(
    model=_MODEL_CONSTRAINTS,
    executor=_EXECUTOR_CONSTRAINTS,
    generator=_GENERATOR_CONSTRAINTS,
    contract=_CONTRACT_CONSTRAINTS,
    known_leak_groups=_KNOWN_LEAK_GROUPS,
    fault_suppression=_FAULT_SUPPRESSION,
)
