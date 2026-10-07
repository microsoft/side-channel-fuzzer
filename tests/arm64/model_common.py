"""
File: Collection of helper classes for arm64 model tests.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, Generator

import os
import tempfile
from pathlib import Path

from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.factory import get_instruction_pool_constraints
from rvzr.isa_spec import InstructionSet
from rvzr.elf_parser import ELFParser
from rvzr.arch.arm64.target_desc import ARM64TargetDesc
from rvzr.arch.arm64.asm_parser import ARM64AsmParser
from rvzr.arch.arm64.generator import ARM64Generator
from rvzr.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_HEADER = """
.section .data.main
"""

# base addresses for calculating expected contract traces
PC0 = 0x8
MEM_BASE = 0x1000000
CODE_BASE = 0x8000
MAIN_OFFSET = 0x1000
FAULTY_OFFSET = 0x2000

MEM_DEFAULT_VALUE = 1
REG_DEFAULT_VALUE = 2
MEM_FAULTY_DEFAULT_VALUE = 3
RSP_DEFAULT_VALUE = FAULTY_OFFSET - 8


class Inst:
    """ Instruction with its size and memory address """
    text: str
    size: int
    mem_address: int
    mem_value: int
    pc_offset: int

    def __init__(self, text: str, size: int, mem_address: int, mem_value: int):
        self.text = text
        self.size = size
        self.mem_address = mem_address
        self.mem_value = mem_value
        self.pc_offset = 0


class InstList:
    """ List of instructions with their memory addresses """
    instructions: List[Inst]

    def __init__(self, instructions: List[Inst]):
        # measurement_end macro is inserted automatically at the end
        instructions.append(Inst(".macro.measurement_end:", 0, 0, 0))

        # set the pc_offset for each instruction
        self.set_offsets(instructions)
        self.instructions = instructions

    def __iter__(self) -> Generator[Inst, None, None]:
        yield from self.instructions

    def __getitem__(self, index: int) -> Inst:
        return self.instructions[index]

    @staticmethod
    def set_offsets(instructions: List[Inst]) -> None:
        """ Set the pc_offset for each instruction in a list """
        pc = 0x8
        for inst in instructions:
            inst.pc_offset = pc
            pc += inst.size

    def to_test_case(self) -> TestCaseProgram:
        """ Load a test case from the assembly string """
        min_arm64_path = test_dir / "min_arm64.json"

        asm_str = ASM_HEADER
        asm_str += "\n".join([x.text for x in self.instructions])
        asm_str += "\n.test_case_exit:\n"

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet(min_arm64_path.absolute().as_posix(), None, constraints)
        target_desc = ARM64TargetDesc()
        elf_parser = ELFParser(target_desc)
        asm_parser = ARM64AsmParser(instruction_set, target_desc)
        generator = ARM64Generator(CONF.program_generator_seed, instruction_set, target_desc,
                                   asm_parser, elf_parser)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w", encoding="utf-8") as f:
            f.write(asm_str)
        tc: TestCaseProgram = asm_parser.parse_file(asm_file.name, generator, elf_parser)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc


def get_default_input() -> InputData:
    input_ = InputData()
    input_[0]['main'][0] = MEM_DEFAULT_VALUE
    input_[0]['main'][1] = MEM_DEFAULT_VALUE
    input_[0]['faulty'][0] = MEM_FAULTY_DEFAULT_VALUE
    input_[0]['faulty'][1] = MEM_FAULTY_DEFAULT_VALUE
    for i in range(0, 7):
        input_[0]['gpr'][i] = REG_DEFAULT_VALUE
    return input_
