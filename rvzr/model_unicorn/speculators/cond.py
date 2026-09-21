"""
File: Speculator for Conditional branch prediction (Spectre v1)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import abstractmethod
from typing import TYPE_CHECKING, Optional, Tuple, Final, Callable

import unicorn.x86_const as ucc  # type: ignore # no type hints for this library
import unicorn.arm64_const as aucc  # type: ignore # no type hints for this library

from rvzr.model_unicorn.speculator_abc import UnicornSpeculator
from rvzr.config import CONF

if TYPE_CHECKING:
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker
    from rvzr.target_desc import TargetDesc

FLAGS_CF: int = 0b000000000001
FLAGS_PF: int = 0b000000000100
FLAGS_AF: int = 0b000000010000
FLAGS_ZF: int = 0b000001000000
FLAGS_SF: int = 0b000010000000
FLAGS_TF: int = 0b000100000000
FLAGS_IF: int = 0b001000000000
FLAGS_DF: int = 0b010000000000
FLAGS_OF: int = 0b100000000000

FLAGS_N: Final[int] = 1 << 31
FLAGS_Z: Final[int] = 1 << 30
FLAGS_C: Final[int] = 1 << 29
FLAGS_V: Final[int] = 1 << 28

_Successors = Tuple[int, int, bool]
""" Branch target, fall-through address, and whether the branch is architecturally taken """

_X86_CONDITIONS: Final[Tuple[Callable[[int], bool], ...]] = (
    lambda f: f & FLAGS_OF != 0,  # 0x0: JO
    lambda f: f & FLAGS_OF == 0,  # 0x1: JNO
    lambda f: f & FLAGS_CF != 0,  # 0x2: JB
    lambda f: f & FLAGS_CF == 0,  # 0x3: JAE
    lambda f: f & FLAGS_ZF != 0,  # 0x4: JE
    lambda f: f & FLAGS_ZF == 0,  # 0x5: JNE
    lambda f: f & (FLAGS_CF | FLAGS_ZF) != 0,  # 0x6: JBE
    lambda f: f & (FLAGS_CF | FLAGS_ZF) == 0,  # 0x7: JA
    lambda f: f & FLAGS_SF != 0,  # 0x8: JS
    lambda f: f & FLAGS_SF == 0,  # 0x9: JNS
    lambda f: f & FLAGS_PF != 0,  # 0xA: JP
    lambda f: f & FLAGS_PF == 0,  # 0xB: JNP
    lambda f: (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),  # 0xC: JL
    lambda f: (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),  # 0xD: JGE
    lambda f: f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0),  # 0xE: JLE
    lambda f: f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0),  # 0xF: JG
)
""" Conditions of x86 Jcc instructions, indexed by the low nibble of the opcode; the nibble is
the same for the short (0x7X) and the near (0x0F 0x8X) encodings """


class _CondSpeculator(UnicornSpeculator):
    """
    Architecture-independent implementation of the always-mispredict semantics: checkpoint the
    architecturally-correct successor of a conditional branch, then redirect execution into the
    other one.
    """

    def _speculate_instruction(self, address: int, size: int) -> None:
        if self._max_nesting_reached():  # reached max spec. window? skip
            return

        successors = self._decode_branch(address, size)
        if successors is None:  # not a cond. branch? ignore
            return
        branch_target, fall_through, will_jump = successors

        self._checkpoint(branch_target if will_jump else fall_through)
        self._emulator.reg_write(self._uc_target_desc.pc_register,
                                 fall_through if will_jump else branch_target)

    @abstractmethod
    def _decode_branch(self, address: int, size: int) -> Optional[_Successors]:
        """
        Decode the instruction at `address` and, if it is a conditional branch, return its
        successors; return None otherwise.
        """


class X86CondSpeculator(_CondSpeculator):
    """
    Leakage model of conditional branch speculation on x86-64.

    Implements the contract for conditional branch prediction by over-approximating the
    branch predictor with always-mispredict semantics: every conditional branch, up to the
    configured nesting and speculation-window bounds, is taken speculatively into the wrong
    direction, and the correct direction is resumed after a rollback. This subsumes the traces
    of any real predictor, at the cost of reporting speculative paths that a concrete predictor
    might never take.
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "x86-64"

    def _decode_branch(self, address: int, size: int) -> Optional[_Successors]:
        # Unicorn reports a huge size for undefined instructions; 15 bytes is the x86 maximum
        if size > 15:
            return None

        code: bytearray = self._emulator.mem_read(address, size)
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        opcode = code[0]

        displacement: bytearray
        condition: Optional[int]
        if 0x70 <= opcode <= 0x7F:  # Jcc rel8
            displacement, condition = code[1:], opcode & 0xF
        elif opcode == 0x0F and 0x80 <= code[1] <= 0x8F:  # Jcc rel32
            displacement, condition = code[2:], code[1] & 0xF
        elif 0xE0 <= opcode <= 0xE3:  # LOOP/LOOPE/LOOPNE/JRCXZ
            displacement, condition = code[1:], None
        else:
            return None

        will_jump = _X86_CONDITIONS[condition](flags) if condition is not None \
            else self._resolve_loop(opcode, flags)

        # x86 branch offsets are relative to the end of the branch instruction
        fall_through = address + size
        offset = int.from_bytes(displacement, byteorder='little', signed=True)
        return (fall_through + offset, fall_through, will_jump)

    def _resolve_loop(self, opcode: int, flags: int) -> bool:
        """
        Evaluate the condition of a LOOP*/JRCXZ instruction and, for LOOP*, apply its decrement of
        RCX; the decrement has to be applied here because the speculator overwrites RIP and thus
        the instruction itself never executes.
        """
        rcx: int = self._emulator.reg_read(ucc.UC_X86_REG_RCX)  # type: ignore
        if opcode == 0xE3:  # JRCXZ
            return rcx == 0

        self._emulator.reg_write(ucc.UC_X86_REG_RCX, rcx - 1)
        counter_nonzero = rcx != 1  # the decremented RCX is zero only if RCX was 1
        if opcode == 0xE0:  # LOOPNE
            return counter_nonzero and flags & FLAGS_ZF == 0
        if opcode == 0xE1:  # LOOPE
            return counter_nonzero and flags & FLAGS_ZF != 0
        return counter_nonzero  # LOOP


class ARM64CondSpeculator(_CondSpeculator):
    """
    Leakage model of conditional branch speculation on ARM64.

    Implements the contract for conditional branch prediction by over-approximating the
    branch predictor with always-mispredict semantics: every conditional branch, up to the
    configured nesting and speculation-window bounds, is taken speculatively into the wrong
    direction, and the correct direction is resumed after a rollback. This subsumes the traces
    of any real predictor, at the cost of reporting speculative paths that a concrete predictor
    might never take.
    """

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        assert CONF.instruction_set == "arm64"

    def _decode_branch(self, address: int, size: int) -> Optional[_Successors]:
        code: bytearray = self._emulator.mem_read(address, size)
        instruction = int.from_bytes(code, byteorder='little')
        first_byte = instruction >> 24

        if first_byte == 0x54 and instruction & 0x10 == 0:  # B.cond
            flags: int = self._emulator.reg_read(
                self._uc_target_desc.flags_register)  # type: ignore
            offset, will_jump = self._decode_b_cond(instruction, flags)
        elif 0xb4 <= first_byte <= 0xb7 or 0x34 <= first_byte <= 0x37:  # CBZ/CBNZ/TBZ/TBNZ
            offset, will_jump = self._decode_cb_tb(instruction, first_byte)
        else:
            return None

        # ARM64 branch offsets are encoded in units of 4 bytes and are relative to the
        # branch instruction itself
        return (address + (offset << 2), address + size, will_jump)

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
            True,  # f = b.nv; in A64, this encoding behaves identically to b.al
        ][condition]
        return (target, will_jump)

    def _decode_cb_tb(self, instruction: int, first_byte: int) -> Tuple[int, bool]:
        # CBZ/CBNZ/TBZ/TBNZ
        register_index = instruction & 0x1f
        is_32bit = first_byte >> 4 == 0x3

        register_value: int
        if register_index == 31:
            # xzr "zero register"
            register_value = 0
        else:
            # for some reason UC_ARM64_REG_X29 != UC_ARM64_REG_X0 + 29
            uc_reg_id = \
                (aucc.UC_ARM64_REG_X0 + register_index) if register_index <= 28 else \
                (aucc.UC_ARM64_REG_X29 + (register_index - 29))

            register_value = self._emulator.reg_read(uc_reg_id)  # type: ignore

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
