"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import unittest
import tempfile
from pathlib import Path

from rvzr.factory import get_asm_parser, get_program_generator, get_instruction_pool_constraints
from rvzr.elf_parser import ELFParser
from rvzr.isa_spec import InstructionSet
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change
from rvzr.arch.x86.target_desc import X86TargetDesc
from rvzr.arch.x86.fuzzer import _create_fenced_test_case

CONF.instruction_set = "x86-64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent


# ==================================================================================================
# Tests
# ==================================================================================================
class X86FuzzerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        CONF.logging_modes = []
        update_logging_after_config_change()

    def test__create_fenced_test_case(self) -> None:
        # Test that the function _create_fenced_test_case adds fences to
        # the assembly file in a correct way

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(), None,
                                         constraints)
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(X86TargetDesc())

        # original_asm = "test.asm"
        # fenced_asm = "fenced_test.asm"
        with tempfile.NamedTemporaryFile(delete=False) as original:
            original_asm = original.name
        with tempfile.NamedTemporaryFile(delete=False) as fenced:
            fenced_asm = fenced.name

        with open(original_asm, 'w') as f:
            f.write("""
            .intel_syntax noprefix
            .section .data.main
            .function_1:
            .macro.measurement_start:

            # This is a comment
            .byte 0x90

            jne .l1
            loopne .l1
            .l1:
            adc rax, rbx
            cmp rbx, rcx

            .test_case_exit:
            """)

        _ = _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)
        fenced_lines = []
        with open(fenced_asm, 'r') as f:
            for line in f:
                fenced_lines.append(line.strip())

        # clean up
        os.unlink(original_asm)
        os.unlink(fenced_asm)

        # Check that the fences are placed in expected places
        self.assertIn("lfence", fenced_lines[8])
        self.assertIn("lfence", fenced_lines[13])
        self.assertIn("lfence", fenced_lines[15])
        self.assertIn("lfence", fenced_lines[17])


if __name__ == '__main__':
    unittest.main()
