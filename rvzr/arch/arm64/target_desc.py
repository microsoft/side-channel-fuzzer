"""
File: arm64-specific constants and lists

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-few-public-methods
# justification: this is a collection of descriptor classes

from typing import List
import re
import unicorn.arm64_const as ucc  # type: ignore

from rvzr.tc_components.instruction import Instruction
from rvzr.target_desc import TargetDesc, CPUDesc, UnicornTargetDesc


class ARM64TargetDesc(TargetDesc):
    """ Target description for arm64 architecture. """

    register_sizes = {
        "w0": 32, "w1": 32, "w2": 32, "w3": 32, "w4": 32, "w5": 32, "w6": 32, "w7": 32,
        "wsp": 32, "wzr": 32,
        "x0": 64, "x1": 64, "x2": 64, "x3": 64, "x4": 64, "x5": 64, "x6": 64, "x7": 64,
        "sp": 64, "xsp": 64, "xzr": 64,
    }  # yapf: disable

    registers_by_size = {
        32: ["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"],
        64: ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    }  # yapf: disable

    reg_normalized = {
        "w0": "R0", "x0": "R0",
        "w1": "R1", "x1": "R1",
        "w2": "R2", "x2": "R2",
        "w3": "R3", "x3": "R3",
        "w4": "R4", "x4": "R4",
        "w5": "R5", "x5": "R5",
        "w6": "R6", "x6": "R6",
        "w7": "R7", "x7": "R7",
        "w8": "R8", "x8": "R8",
        "w9": "R9", "x9": "R9",
        "w10": "R10", "x10": "R10",
        "w20": "R20", "x20": "R20",
        "w30": "R30", "x30": "R30",
        "CF": "CF", "ZF": "ZF", "SF": "SF", "OF": "OF",
        "pc": "RIP",
        "sp": "RSP", "wsp": "RSP", "xsp": "RSP",
    }  # yapf: disable

    reg_denormalized = {
        "R0": {64: "x0", 32: "w0"},
        "R1": {64: "x1", 32: "w1"},
        "R2": {64: "x2", 32: "w2"},
        "R3": {64: "x3", 32: "w3"},
        "R4": {64: "x4", 32: "w4"},
        "R5": {64: "x5", 32: "w5"},
        "R6": {64: "x6", 32: "w6"},
        "R7": {64: "x7", 32: "w7"},
        "R20": {64: "x20", 32: "w20"},
        "R30": {64: "x30", 32: "w30"},
        "RIP": {64: "pc"},
        "RSP": {64: "sp", 32: "wsp"},
    }  # yapf: disable

    mem_index_registers = ["x0", "x1", "x2", "x3", "x4", "x5"]

    page_property_to_pte_bit_name = {
        "present": ("valid", False),
        "writable": ("non_writable", True),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "executable": ("non_executable", True),
    }

    pte_bits = {
        "valid": (0, True),
        "user": (6, False),
        "non_writable": (7, False),
        "accessed": (10, True),
        "non_executable": (53, True),
    }

    # FIXME: EPTE is not yet supported on ARM64; this is a placeholder
    page_property_to_vm_pte_bit_name = {
        "present": ("valid", False),
        "writable": ("non_writable", True),
        "user": ("user", False),
        "accessed": ("accessed", False),
        "executable": ("non_executable", True),
    }

    # FIXME: EPTE is not yet supported on ARM64; this is a placeholder
    vm_pte_bits = {
        "valid": (0, True),
        "user": (0, False),
        "non_writable": (0, False),
        "accessed": (0, True),
        "non_executable": (0, True),
    }

    branch_conditions = {
        "eq": ["", "", "", "r", "", "", "", "", ""],
        "ne": ["", "", "", "r", "", "", "", "", ""],
        "cs": ["r", "", "", "", "", "", "", "", ""],
        "cc": ["r", "", "", "", "", "", "", "", ""],
        "mi": ["", "", "", "", "r", "", "", "", ""],
        "pl": ["", "", "", "", "r", "", "", "", ""],
        "vs": ["", "", "", "", "", "", "", "", "r"],
        "vc": ["", "", "", "", "", "", "", "", "r"],
        "hi": ["r", "", "", "r", "", "", "", "", ""],
        "ls": ["r", "", "", "r", "", "", "", "", ""],
        "ge": ["", "", "", "", "r", "", "", "", "r"],
        "lt": ["", "", "", "", "r", "", "", "", "r"],
        "gt": ["", "", "", "r", "r", "", "", "", "r"],
        "le": ["", "", "", "r", "r", "", "", "", "r"],
        "al": ["", "", "", "", "", "", "", "", ""]
    }

    def __init__(self) -> None:
        super().__init__()

        # modify/set target parameters based on the CPU under test and the configuration
        self.cpu_desc = self._build_cpu_desc()

        # connect Unicorn TD
        self.uc_target_desc = ARM64UnicornTargetDesc()

    @staticmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        return inst.name == "b"

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        return inst.name == "bl"

    def _build_cpu_desc(self) -> CPUDesc:
        vendor = self.get_vendor()

        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()

            family_match = re.search(r"CPU architecture\s*:\s+(.*)", cpuinfo)
            assert family_match, "Failed to find family in /proc/cpuinfo"
            family = int(family_match.group(1), 16)

            model_match = re.search(r"CPU variant\s+:\s+(.*)", cpuinfo)
            assert model_match, "Failed to find model name in /proc/cpuinfo"
            model = int(model_match.group(1), 16)

            stepping_match = re.search(r"CPU part\s+:\s+(.*)", cpuinfo)
            assert stepping_match, "Failed to find stepping in /proc/cpuinfo"
            stepping = int(stepping_match.group(1), 16)

        return CPUDesc(vendor, model, family, stepping)


class ARM64UnicornTargetDesc(UnicornTargetDesc):
    """ arm64 target description in the context of a Unicorn-based model. """

    usable_registers: List[int] = [
        ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2, ucc.UC_ARM64_REG_X3,
        ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5, ucc.UC_ARM64_REG_NZCV, ucc.UC_ARM64_REG_SP
    ]

    usable_simd128_registers: List[int] = []

    reg_str_to_constant = {
        "x0": ucc.UC_ARM64_REG_X0,
        "x1": ucc.UC_ARM64_REG_X1,
        "x2": ucc.UC_ARM64_REG_X2,
        "x3": ucc.UC_ARM64_REG_X3,
        "x4": ucc.UC_ARM64_REG_X4,
        "x5": ucc.UC_ARM64_REG_X5,
        "x6": ucc.UC_ARM64_REG_X6,
        "x7": ucc.UC_ARM64_REG_X7,
        "x8": ucc.UC_ARM64_REG_X8,
        "x9": ucc.UC_ARM64_REG_X9,
        "x10": ucc.UC_ARM64_REG_X10,
        "x11": ucc.UC_ARM64_REG_X11,
        "x12": ucc.UC_ARM64_REG_X12,
        "x13": ucc.UC_ARM64_REG_X13,
        "x14": ucc.UC_ARM64_REG_X14,
        "x15": ucc.UC_ARM64_REG_X15,
        "x16": ucc.UC_ARM64_REG_X16,
        "x17": ucc.UC_ARM64_REG_X17,
        "x18": ucc.UC_ARM64_REG_X18,
        "x19": ucc.UC_ARM64_REG_X19,
        "x20": ucc.UC_ARM64_REG_X20,
        "x21": ucc.UC_ARM64_REG_X21,
        "x22": ucc.UC_ARM64_REG_X22,
        "x23": ucc.UC_ARM64_REG_X23,
        "x24": ucc.UC_ARM64_REG_X24,
        "x25": ucc.UC_ARM64_REG_X25,
        "x26": ucc.UC_ARM64_REG_X26,
        "x27": ucc.UC_ARM64_REG_X27,
        "x28": ucc.UC_ARM64_REG_X28,
        "x29": ucc.UC_ARM64_REG_X29,
        "x30": ucc.UC_ARM64_REG_X30
    }

    reg_norm_to_constant = {
        "R0": ucc.UC_ARM64_REG_X0,
        "R1": ucc.UC_ARM64_REG_X1,
        "R2": ucc.UC_ARM64_REG_X2,
        "R3": ucc.UC_ARM64_REG_X3,
        "R4": ucc.UC_ARM64_REG_X4,
        "R5": ucc.UC_ARM64_REG_X5,
        "R6": ucc.UC_ARM64_REG_X6,
        "R7": ucc.UC_ARM64_REG_X7,
        "R20": ucc.UC_ARM64_REG_X20,
        "R30": ucc.UC_ARM64_REG_X30,
        "FLAGS": ucc.UC_ARM64_REG_NZCV,
        "SF": ucc.UC_ARM64_REG_NZCV,  # N
        "ZF": ucc.UC_ARM64_REG_NZCV,  # Z
        "CF": ucc.UC_ARM64_REG_NZCV,  # C
        "OF": ucc.UC_ARM64_REG_NZCV,  # V
        "RIP": -1,
        "RSP": -1,
    }

    barriers: List[str] = ['dmb', 'dsb', 'isb']
    flags_register: int = ucc.UC_ARM64_REG_NZCV
    pc_register: int = ucc.UC_ARM64_REG_PC
    sp_register: int = ucc.UC_ARM64_REG_SP
    actor_base_register: int = ucc.UC_ARM64_REG_X20
