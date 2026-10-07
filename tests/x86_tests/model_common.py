"""
File: Collection of helper classes for x86 model tests.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, Generator, Literal
from dataclasses import dataclass

import os
import tempfile
from pathlib import Path

from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.factory import get_instruction_pool_constraints
from rvzr.isa_spec import InstructionSet
from rvzr.elf_parser import ELFParser
from rvzr.arch.x86.target_desc import X86TargetDesc
from rvzr.arch.x86.asm_parser import X86AsmParser
from rvzr.arch.x86.generator import X86Generator
from rvzr.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_HEADER = """
.intel_syntax noprefix
.section .data.main
"""

# Base addresses for calculating expected contract traces
PC0 = 0x8  # Initial program counter offset for Unicorn backend
DATA_BASE = 0x1000000  # Base address for data section in test environment
CODE_BASE = 0x8000  # Base address for code section in test environment
MAIN_OFFSET = 0x1000  # Offset for main actor code section
FAULTY_OFFSET = 0x2000  # Offset for faulty actor code section

# Default values for memory and registers in test inputs
MEM_DEFAULT_VALUE = 1
REG_DEFAULT_VALUE = 2
MEM_FAULTY_DEFAULT_VALUE = 3
RSP_DEFAULT_VALUE = FAULTY_OFFSET - 8

# Register indices for x86-64 (used in test input array indexing)
RAX, RBX, RCX, RDX, RSI, RDI, FLAGS, RSP = 0, 1, 2, 3, 4, 5, 6, 7
NUM_TEST_GPRS = 7  # Number of GPRs initialized in default test inputs

# SIMD register indices
XMM0, XMM1 = 0, 1

Backend = Literal["dr", "uc"]


@dataclass
class Inst:
    """Instruction with its size and memory address."""
    text: str
    size: int
    mem_address: int
    mem_value: int
    pc_offset: int = 0


class InstList:
    """List of instructions with their memory addresses."""
    instructions: List[Inst]

    def __init__(self, instructions: List[Inst], backend: Backend):
        self.backend = backend
        self.start_offset = PC0 if backend == "uc" else 0

        # Wrap instructions with backend-specific macros
        wrapped = self._wrap_instructions_for_backend(instructions)
        self.set_offsets(wrapped)
        self.instructions = wrapped

    def _wrap_instructions_for_backend(self, instructions: List[Inst]) -> List[Inst]:
        if self.backend == "dr":
            return self._wrap_instructions_for_dr(instructions)
        # uc
        return self._wrap_instructions_for_uc(instructions)

    def _wrap_instructions_for_dr(self, instructions: List[Inst]) -> List[Inst]:
        """
        DynamoRIO test cases are wrapped in measurement macros plus a NOP at test_case_exit.
        """
        wrapped = []
        wrapped.append(Inst(".macro.measurement_start:", 8, 0, 0))
        wrapped.extend(instructions)
        wrapped.append(Inst(".macro.measurement_end:", 8, 0, 0))
        wrapped.append(Inst(".test_case_exit:nop", 1, 0, 0))
        return wrapped

    def _wrap_instructions_for_uc(self, instructions: List[Inst]) -> List[Inst]:
        """
        Unicorn test cases have measurement_end macro inserted automatically.
        """
        wrapped = []
        wrapped.extend(instructions)
        wrapped.append(Inst(".macro.measurement_end:", 8, 0, 0))
        wrapped.append(Inst(".test_case_exit:nop", 1, 0, 0))
        return wrapped

    def __iter__(self) -> Generator[Inst, None, None]:
        yield from self.instructions

    def __getitem__(self, index: int) -> Inst:
        return self.instructions[index]

    def set_offsets(self, instructions: List[Inst]) -> None:
        """ Set the pc_offset for each instruction in a list """
        pc = self.start_offset
        for inst in instructions:
            inst.pc_offset = pc
            pc += inst.size

    def to_test_case(self) -> TestCaseProgram:
        """Load a test case from the assembly string.

        :return: Parsed TestCaseProgram object
        """
        min_x86_path = test_dir / "min_x86.json"

        asm_str = ASM_HEADER
        asm_str += "\n".join([x.text for x in self.instructions])

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix(), None, constraints)
        target_desc = X86TargetDesc()
        elf_parser = ELFParser(target_desc)
        asm_parser = X86AsmParser(instruction_set, target_desc)
        generator = X86Generator(CONF.program_generator_seed, instruction_set, target_desc,
                                 asm_parser, elf_parser)

        # Create temp file and parse
        with tempfile.NamedTemporaryFile(
                mode='w', delete=False, suffix='.asm', encoding='utf-8') as f:
            f.write(asm_str)
            temp_path = f.name

        try:
            tc: TestCaseProgram = asm_parser.parse_file(temp_path, generator, elf_parser)
        finally:
            os.unlink(temp_path)

        return tc

    def get_expected_observations(self, execution_order: List[int], observe_pc: bool,
                                  observe_mem: bool, observe_val: bool) -> List[int]:
        """Get expected observations for executed instructions.

        :param execution_order: List of instruction indices in execution order
        :param observe_pc: Whether to observe program counter values
        :param observe_mem: Whether to observe memory addresses
        :param observe_val: Whether to observe memory values
        :return: List of expected observation values
        """
        adjusted_order = self._adjust_execution_order_for_backend(execution_order)
        return self._collect_observations(adjusted_order, observe_pc, observe_mem, observe_val)

    def _adjust_execution_order_for_backend(self, execution_order: List[int]) -> List[int]:
        last_org_id = len(self.instructions) - 3
        last_actual_id = len(self.instructions) - 1

        if self.backend == "dr":
            return self._adjust_order_for_dr(execution_order, last_org_id, last_actual_id)
        # uc
        return self._adjust_order_for_uc(execution_order, last_org_id, last_actual_id)

    def _adjust_order_for_dr(self, execution_order: List[int], last_org_id: int,
                             last_actual_id: int) -> List[int]:
        """Adjust execution order for DynamoRIO backend.
        DynamoRIO includes measurement_start at the beginning, and appends
        measurement_end + NOP at the end.
        """
        updated_order = [0]  # measurement_start
        for idx in execution_order:
            updated_order.append(idx + 1)
            if idx + 1 == last_org_id:
                updated_order.append(last_actual_id - 1)  # measurement_end
                updated_order.append(last_actual_id)  # NOP at test_case_exit
        return updated_order

    def _adjust_order_for_uc(self, execution_order: List[int], last_org_id: int,
                             last_actual_id: int) -> List[int]:
        """Adjust execution order for Unicorn backend.
        Unicorn appends measurement_end at the end. The NOP is not observed.
        """
        updated_order = []
        for idx in execution_order:
            updated_order.append(idx)
            if idx == last_org_id:
                updated_order.append(last_actual_id - 1)  # measurement_end
                # NOP is not observed on UC
        return updated_order

    def _collect_observations(self, execution_order: List[int], observe_pc: bool, observe_mem: bool,
                              observe_val: bool) -> List[int]:
        """Collect observations based on execution order and observation flags.
        """
        observations = []
        for exec_id in execution_order:
            inst = self.instructions[exec_id]
            if inst.size == 0:  # not an actual instruction
                continue
            if observe_pc:
                observations.append(inst.pc_offset)
            if observe_mem and inst.mem_address != 0:
                observations.append(inst.mem_address)
            if observe_val and inst.mem_value != 0:
                observations.append(inst.mem_value)
        return observations


class InputBuilder:
    """Helper class to create InputData for x86 tests."""

    def get_default_input(self) -> InputData:
        """Create default InputData for x86 tests.

        :return: InputData with default values for memory and registers
        """
        input_ = InputData()
        input_[0]['main'][0] = MEM_DEFAULT_VALUE
        input_[0]['main'][1] = MEM_DEFAULT_VALUE
        input_[0]['faulty'][0] = MEM_FAULTY_DEFAULT_VALUE
        input_[0]['faulty'][1] = MEM_FAULTY_DEFAULT_VALUE
        for i in range(NUM_TEST_GPRS):
            input_[0]['gpr'][i] = REG_DEFAULT_VALUE
        return input_

    def get_input_with_zeroed_gprs(self, *gpr_indices: int) -> InputData:
        """Create InputData with specified GPRs set to 0 for taint tracking.

        :param gpr_indices: Register indices to initialize to 0
        :return: InputData with specified registers set to 0
        """
        input_ = InputData()
        for gpr_idx in gpr_indices:
            input_[0]['gpr'][gpr_idx] = 0
        return input_

    def get_input_with_zeroed_memory(self, **memory_regions: int) -> InputData:
        """Create InputData with specified memory regions set to 0 for taint tracking.

        :param memory_regions: Keyword arguments where key is region name (e.g., 'main', 'faulty')
                              and value is the index within that region
        :return: InputData with specified memory regions set to 0
        """
        input_ = InputData()
        for region, idx in memory_regions.items():
            input_[0][region][idx] = 0
        return input_
