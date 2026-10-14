"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import unittest
import tempfile
from pathlib import Path
from typing import Any, List, Tuple
from unittest.mock import MagicMock, patch

from rvzr.factory import get_asm_parser, get_program_generator, get_instruction_pool_constraints
from rvzr.elf_parser import ELFParser
from rvzr.isa_spec import InstructionSet
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change
from rvzr.arch.x86.target_desc import X86TargetDesc
from rvzr.arch.x86.fuzzer import X86Fuzzer, _create_fenced_test_case

CONF.instruction_set = "x86-64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent

TEST_CASE_ASM = """
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
            """

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
        with tempfile.NamedTemporaryFile(suffix=".asm", delete=False) as original:
            original_asm = original.name
        with tempfile.NamedTemporaryFile(suffix=".asm", delete=False) as fenced:
            fenced_asm = fenced.name

        with open(original_asm, 'w') as f:
            f.write(TEST_CASE_ASM)

        _ = _create_fenced_test_case(original_asm, fenced_asm, asm_parser, generator, elf_parser)
        fenced_lines = []
        with open(fenced_asm, 'r') as f:
            for line in f:
                fenced_lines.append(line.strip())

        # clean up, including the files that parse_file derives from the fenced file
        os.unlink(original_asm)
        os.unlink(fenced_asm)
        os.unlink(fenced_asm + ".patched.asm")
        os.unlink(fenced_asm[:-4] + ".o")

        # Check that the fences are placed in expected places
        self.assertIn("lfence", fenced_lines[8])
        self.assertIn("lfence", fenced_lines[13])
        self.assertIn("lfence", fenced_lines[15])
        self.assertIn("lfence", fenced_lines[17])

    def _make_filter_fuzzer(self) -> Tuple[X86Fuzzer, MagicMock]:
        """
        Create an X86Fuzzer with real parsing components and a mocked executor/analyser;
        return the fuzzer and the executor mock
        """
        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(), None,
                                         constraints)
        mock_executor = MagicMock()
        mock_analyser = MagicMock()
        mock_analyser.htraces_are_equivalent.return_value = False

        fuzzer = X86Fuzzer.__new__(X86Fuzzer)  # __new__ bypasses __init__, so no factory is called
        fuzzer.code_gen = get_program_generator(CONF.program_generator_seed, instruction_set)
        fuzzer.asm_parser = get_asm_parser(instruction_set)
        fuzzer.elf_parser = ELFParser(X86TargetDesc())
        fuzzer.executor = mock_executor
        fuzzer.analyser = mock_analyser
        return fuzzer, mock_executor

    def _run_observation_filter(self, fuzzer: X86Fuzzer) -> Tuple[bool, str]:
        """
        Call fuzzer._observation_filter on a minimal test case while capturing the name
        of the fenced temp file it creates; return the filter result and that name
        """
        with tempfile.NamedTemporaryFile("w", suffix=".asm", delete=False) as original:
            original.write(TEST_CASE_ASM)
            original_asm = original.name
        test_case = MagicMock()
        test_case.asm_path.return_value = original_asm

        created: List[str] = []
        real_ntf = tempfile.NamedTemporaryFile

        def capturing_ntf(*args: Any, **kwargs: Any) -> Any:
            file = real_ntf(*args, **kwargs)
            created.append(file.name)
            return file

        old_conf = CONF.enable_observation_filter
        CONF.enable_observation_filter = True
        try:
            with patch(
                    "rvzr.arch.x86.fuzzer.tempfile.NamedTemporaryFile", side_effect=capturing_ntf):
                result = fuzzer._observation_filter(test_case, [MagicMock()], 1, [MagicMock()])
        finally:
            CONF.enable_observation_filter = old_conf
            os.unlink(original_asm)

        self.assertEqual(len(created), 1)
        return result, created[0]

    def _assert_no_leftover_files(self, fenced_name: str) -> None:
        for path in (fenced_name, fenced_name + ".patched.asm", fenced_name[:-4] + ".o"):
            self.assertFalse(os.path.exists(path), f"leftover temp file: {path}")

    def test__observation_filter_removes_temp_files(self) -> None:
        # Test that _observation_filter cleans up the fenced asm file and its derived files
        fuzzer, _ = self._make_filter_fuzzer()
        result, fenced_name = self._run_observation_filter(fuzzer)
        self.assertFalse(result)
        self._assert_no_leftover_files(fenced_name)

    def test__observation_filter_removes_temp_files_on_error(self) -> None:
        # Test that _observation_filter cleans up its temp files on the executor-error path
        fuzzer, mock_executor = self._make_filter_fuzzer()
        mock_executor.trace_test_case.side_effect = IOError()
        result, fenced_name = self._run_observation_filter(fuzzer)
        self.assertTrue(result)
        self._assert_no_leftover_files(fenced_name)


if __name__ == '__main__':
    unittest.main()
