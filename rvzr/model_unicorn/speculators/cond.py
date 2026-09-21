"""
File: Speculator for Conditional branch prediction (Spectre v1)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, Tuple, Final, Callable

import unicorn.x86_const as ucc  # type: ignore # no type hints for this library
import unicorn.arm64_const as aucc  # type: ignore # no type hints for this library

from rvzr.model_unicorn.speculator_abc import UnicornSpeculator
from rvzr.config import CONF

if TYPE_CHECKING:
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker
    from rvzr.target_desc import TargetDesc

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_TF = 0b000100000000
FLAGS_IF = 0b001000000000
FLAGS_DF = 0b010000000000
FLAGS_OF = 0b100000000000

FLAGS_N: Final[int] = 1 << 31
FLAGS_Z: Final[int] = 1 << 30
FLAGS_C: Final[int] = 1 << 29
FLAGS_V: Final[int] = 1 << 28

_CondBranchFlipper = Callable[[bytearray, int, int], Tuple[bytearray, bool, bool]]


class X86CondSpeculator(UnicornSpeculator):
    """
    Speculator for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70:
            lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71:
            lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72:
            lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73:
            lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74:
            lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75:
            lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76:
            lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77:
            lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78:
            lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79:
            lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A:
            lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B:
            lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C:
            lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D:
            lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E:
            lambda c, f, r: (
                c[1:],
                f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),
                False,
            ),
        0x7F:
            lambda c, f, r: (
                c[1:],
                f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),
                False,
            ),
        0xE0:
            lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1:
            lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2:
            lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3:
            lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F:
            lambda c, f, r: X86CondSpeculator.multibyte_jmp.get(c[1], (lambda _, __, ___:
                                                                       ([0], False, False)))
            (c, f, r),
    }

    multibyte_jmp: Final[Dict[int, _CondBranchFlipper]] = {
        0x80:
            lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81:
            lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82:
            lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83:
            lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84:
            lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85:
            lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86:
            lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87:
            lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88:
            lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89:
            lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A:
            lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B:
            lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C:
            lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D:
            lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E:
            lambda c, f, r: (
                c[2:],
                f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),
                False,
            ),
        0x8F:
            lambda c, f, r: (
                c[2:],
                f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),
                False,
            ),
    }

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "x86-64"

    def _speculate_instruction(self, address: int, size: int) -> None:
        if self._max_nesting_reached():  # reached max spec. window? skip
            return

        # if the instruction is undefined, Unicorn will return a huge value as size
        # skip those
        if size > 15:  # 15 bytes is max instr size on Intel
            return

        # decode the instruction
        code: bytearray = self._emulator.mem_read(address, size)
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        rcx: int = self._emulator.reg_read(ucc.UC_X86_REG_RCX)  # type: ignore
        target, will_jump, is_loop = self.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            self._emulator.reg_write(ucc.UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        self._checkpoint(next_instr)

        # Simulate misprediction
        if will_jump:
            self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)
        else:
            self._emulator.reg_write(ucc.UC_X86_REG_RIP, address + size + target)

    def decode(self, code: bytearray, flags: int, rcx: int) -> Tuple[int, bool, bool]:
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target, whether it will jump to the target (based
        on the `flags` value), and whether it is a LOOP instruction
        """
        calculate_target = \
            self.jumps.get(code[0], (lambda _, __, ___: ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)  # type: ignore
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little', signed=True), will_jump, is_loop


class ARM64CondSpeculator(UnicornSpeculator):
    """
    Speculator for conditional branch mispredictions on ARM64.
    Forces all cond. branches to speculatively go into a wrong target
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "arm64"

    def _speculate_instruction(self, address: int, size: int) -> None:
        if self._max_nesting_reached():  # reached max spec. window? skip
            return

        # decode the instruction
        code: bytearray = self._emulator.mem_read(address, size)
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        target_offset, will_jump = self.decode(code, flags)

        # not a a cond. jump? ignore
        if not target_offset:
            return

        # ARM64 branch offsets are encoded in units of 4 bytes and are relative to the
        # branch instruction itself
        branch_target = address + (target_offset << 2)
        fall_through = address + size

        # Take a checkpoint
        next_instr = branch_target if will_jump else fall_through
        self._checkpoint(next_instr)

        # Simulate misprediction
        target_addr = fall_through if will_jump else branch_target
        self._emulator.reg_write(self._uc_target_desc.pc_register, target_addr)

    def decode(self, code: bytearray, flags: int) -> Tuple[int, bool]:
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target and whether it will jump to the target (based
        on the `flags` value).
        """
        instruction = int.from_bytes(code, byteorder='little')
        first_byte = instruction >> 24
        if first_byte == 0x54 and instruction & 0x10 == 0:
            # B.cond instruction
            return self._decode_b_cond(instruction, flags)

        if 0xb4 <= first_byte <= 0xb7 or 0x34 <= first_byte <= 0x37:
            # CBZ/CBNZ/TBZ/TBNZ
            return self._decode_cb_tb(instruction, first_byte)
        return (0, False)

    def _decode_b_cond(self, instruction: int, flags: int) -> Tuple[int, bool]:
        target = self._twos_complement(instruction >> 5, 19)
        condition = instruction & 0xf
        n = (flags & FLAGS_N) != 0
        z = (flags & FLAGS_Z) != 0
        c = (flags & FLAGS_C) != 0
        v = (flags & FLAGS_V) != 0
        # table here is useful:
        # https://community.arm.com/arm-community-blogs/b/
        # architectures-and-processors-blog/posts/condition-codes-1-condition-flags-and-codes
        will_jump = [
            z,  # 0 = b.eq "equal"
            not z,  # 1 = b.ne "not equal"
            c,  # 2 = b.cs "carry set"
            not c,  # 3 = b.cc "carry clear"
            n,  # 4 = b.mi "minus"
            not n,  # 5 = b.pl "plus"
            v,  # 6 = b.vs "overflow set"
            not v,  # 7 = b.vc "overflow clear"
            c and not z,  # 8 = b.hi "higher than"
            not c or z,  # 9 = b.ls "lower or same"
            n == v,  # a = b.ge "greater than or equal"
            n != v,  # b = b.lt "less than"
            not z and n == v,  # c = b.gt "greater than"
            z or n != v,  # d = b.le "less than or equal"
            True,  # e = b.al "always"
            False,  # f = b.nv "never"
        ][condition]
        return (target, will_jump)

    def _decode_cb_tb(self, instruction: int, first_byte: int) -> Tuple[int, bool]:
        # CBZ/CBNZ/TBZ/TBNZ
        register_index = instruction & 0x1f
        is_32bit = first_byte >> 4 == 0x3

        register_value: int
        if register_index < 31:
            # for some reason UC_ARM64_REG_X29 != UC_ARM64_REG_X0 + 29
            uc_reg_id = \
                (aucc.UC_ARM64_REG_X0 + register_index) if register_index <= 28 else \
                (aucc.UC_ARM64_REG_X29 + (register_index - 29))

            register_value = self._emulator.reg_read(uc_reg_id)  # type: ignore
        elif register_index == 31:
            # xzr "zero register"
            register_value = 0
        else:
            raise ValueError(f"Invalid register index {register_index} in CBZ/CBNZ/TBZ/TBNZ")

        if is_32bit:
            register_value &= 0xffff_ffff
        if first_byte & 0xf <= 0x5:
            # CBZ/CBNZ
            target = self._twos_complement(instruction >> 5, 19)
            if first_byte & 0xf == 4:
                # CBZ
                will_jump = register_value == 0
            else:
                # CBNZ
                will_jump = register_value != 0
        else:
            target = self._twos_complement(instruction >> 5, 14)
            bit_number = (instruction >> 19) & 0x1f
            if not is_32bit:
                bit_number += 32
            bit = register_value & (1 << bit_number)
            if first_byte & 0xf == 6:
                # TBZ
                will_jump = bit == 0
            else:
                # TBNZ
                will_jump = bit != 0
        return (target, will_jump)

    @staticmethod
    def _twos_complement(n: int, n_bits: int) -> int:
        n &= (1 << n_bits) - 1
        sign_bit = 1 << (n_bits - 1)
        if n & sign_bit:
            return n - 2 * sign_bit
        return n
