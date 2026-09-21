"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import os
from pathlib import Path
from copy import deepcopy

from rvzr.arch.x86.generator import X86Generator, _X86Printer, _X86PatchUndefinedFlagsPass, \
    _X86PatchOpcodesPass
from rvzr.arch.x86.target_desc import X86TargetDesc
from rvzr.elf_parser import ELFParser
from rvzr.factory import get_program_generator, get_asm_parser
from rvzr.isa_spec import InstructionSet
from rvzr.tc_components.actor import ActorMode
from rvzr.tc_components.test_case_code import TestCaseProgram, Function, BasicBlock
from rvzr.tc_components.test_case_binary import SymbolTableEntry
from rvzr.code_generator import assemble
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change

CONF.instruction_set = "x86-64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_OPCODE = """
.intel_syntax noprefix
.section .data.main
.byte 0x90
.test_case_exit:
"""

_ALL_CATEGORIES = [
    "3DNOW_PREFETCH-PREFETCH", "ADOX_ADCX-ADOX_ADCX", "BASE-BINARY", "BASE-BITBYTE", "BASE-CMOV",
    "BASE-COND_BR", "BASE-CONVERT", "BASE-DATAXFER", "BASE-FLAGOP", "BASE-LOGICAL", "BASE-MISC",
    "BASE-NOP", "BASE-POP", "BASE-PUSH", "BASE-ROTATE", "BASE-SEMAPHORE", "BASE-SETCC",
    "BASE-SHIFT", "BASE-WIDENOP", "LONGMODE-CONVERT", "LONGMODE-DATAXFER", "LONGMODE-POP",
    "LONGMODE-PUSH", "LONGMODE-SEMAPHORE", "MMX-MMX", "MMX-LOGICAL", "MMX-DATAXFER", "SSE2-MMX",
    "SSE3-MMX", "SSSE3-MMX", "SSE-CONVERT", "SSE-DATAXFER", "SSE-MISC", "SSE-PREFETCH", "SSE-SSE",
    "SSE2-CONVERT", "SSE2-DATAXFER", "SSE2-LOGICAL", "SSE2-MISC", "SSE2-SSE", "SSE3-DATAXFER",
    "SSE3-SSE", "SSSE3-SSE", "SSE4-LOGICAL", "SSE4-SSE", "AVX-AVX", "AVX-BROADCAST", "AVX-DATAXFER",
    "AVX-LOGICAL", "AVX-STTNI", "AVX2-AVX2", "AVX2-BROADCAST", "AVX2-DATAXFER", "AVX2-LOGICAL",
    "AES-AES", "AVXAES-AES", "BMI1-BMI1", "BMI2-BMI2", "MOVBE-DATAXFER", "LZCNT-LZCNT",
    "PCLMULQDQ-PCLMULQDQ", "VAES-VAES", "3DNOW-3DNOW", "VPCLMULQDQ-VPCLMULQDQ", "SHA-SHA",
    "SSE4a-BITBYTE", "FMA-VFMA", "MOVDIR-MOVDIR", "GFNI-GFNI", "FMA4-FMA4", "AVX_VNNI-VEX",
    "3DNOW-MMX", "LONGMODE-RET", "BASE-RET", "BASE-CALL", "BASE-UNCOND_BR", "SSE-LOGICAL_FP",
    "AVX-LOGICAL_FP", "SSE2-LOGICAL_FP", "AVX2GATHER-AVX2GATHER", "BASE-STRINGOP",
    "LONGMODE-STRINGOP", "CLDEMOTE-CLDEMOTE", "CLFLUSHOPT-CLFLUSHOPT", "CLFSH-MISC", "CLWB-CLWB",
    "CLZERO-CLZERO", "PREFETCHWT1-PREFETCHWT1", "SERIALIZE-SERIALIZE", "BASE-SYSCALL",
    "BASE-SYSRET", "BASE-SEGOP", "BASE-INTERRUPT", "LONGMODE-SYSRET", "PKU-PKU", "PCONFIG-PCONFIG",
    "BASE-IO", "BASE-IOSTRINGOP", "LONGMODE-SYSCALL", "RDPRU-RDPRU", "RDPID-RDPID", "SMAP-SMAP",
    "UINTR-UINTR, MCOMMIT-MISC", "PTWRITE-PTWRITE", "TBM-TBM", "AVX512EVEX-LOGICAL",
    "AVX512EVEX-GFNI", "AVX512EVEX-EXPAND", "AVX512EVEX-DATAXFER", "AVX512EVEX-VFMA",
    "AVX512EVEX-LOGICAL_FP", "AVX512EVEX-VBMI2", "AVX512EVEX-IFMA", "AVX512EVEX-FP16",
    "AVX512EVEX-BROADCAST", "AVX512EVEX-COMPRESS", "AVX512EVEX-AVX512_VBMI", "AVX512EVEX-CONFLICT",
    "AVX512EVEX-VAES", "AVX512EVEX-VPCLMULQDQ", "AVX512EVEX-AVX512", "AVX512EVEX-BLEND",
    "AVX512EVEX-CONVERT", "AVX512EVEX-AVX512_4FMAPS", "RDRAND-RDRAND", "RDSEED-RDSEED"
]


class X86GeneratorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        CONF.logging_modes = []
        update_logging_after_config_change()

    @staticmethod
    def load_tc(asm_str: str) -> TestCaseProgram:

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(X86TargetDesc())

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCaseProgram = asm_parser.parse_file(asm_file.name, generator, elf_parser)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def test_x86_configuration(self) -> None:
        CONF.generator = "random"
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        gen = get_program_generator(CONF.program_generator_seed, instruction_set)
        self.assertEqual(gen.__class__, X86Generator)

    def _test_all_instructions(self, instruction_set: InstructionSet) -> None:
        asm_file = tempfile.NamedTemporaryFile("w", delete=False)
        obj_file = tempfile.NamedTemporaryFile("w", delete=False)

        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        tc = TestCaseProgram(asm_file.name)
        tc.assign_obj(obj_file.name)

        func = generator._function_generator\
            .generate_empty(".function_0", tc.find_section(name="main"))
        tc.find_section(name="main").append(func)
        printer = _X86Printer(X86TargetDesc())
        all_instructions = ['.intel_syntax noprefix\n']

        # try generating instruction strings
        for bb in func:
            for instruction_spec in instruction_set.non_control_flow_specs:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)

        # rewrite the mnemonics that the assembler does not accept into raw opcodes, the same
        # way the generator's pass pipeline does
        _X86PatchOpcodesPass().run_on_test_case(tc)

        for bb in func:
            for instr in bb:
                instr_str = printer._instruction_to_str(instr)
                self.assertTrue(instr_str, f'Instruction {instr} was not generated.')
                all_instructions.append(instr_str + "\n")

        for i in all_instructions:
            asm_file.write(i)
        asm_file.flush()

        # check if the generated instructions are valid
        try:
            assemble(tc)  # terminates with SystemExit if `as` rejects the input
        except SystemExit:
            self.fail("Generated invalid instruction(s)")
        else:
            obj_file.close()
        finally:
            asm_file.close()
            os.unlink(asm_file.name)

    def test_x86_all_instructions_reduced(self) -> None:
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         _ALL_CATEGORIES)
        self._test_all_instructions(instruction_set)

    def test_x86_all_instructions_full(self) -> None:
        if not (test_dir / "../../base.json").exists():
            self.skipTest("base.json not available; skipping test.")

        instruction_set = InstructionSet((test_dir / "../../base.json").absolute().as_posix(),
                                         _ALL_CATEGORIES)
        self._test_all_instructions(instruction_set)

    def test_x86_asm_parsing_basic(self) -> None:
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(X86TargetDesc())

        asm_name = (test_dir / "asm/asm_basic.asm").absolute().as_posix()
        tc: TestCaseProgram = asm_parser.parse_file(asm_name, generator, elf_parser)
        section = tc[0]
        functions = list(section)

        self.assertEqual(len(functions), 2)

        main = functions[0]
        self.assertEqual(main.name, ".function_0")

        self.assertEqual(len(main), 3)

        bb0 = main[1]
        bb1 = main[2]
        exit_ = main.get_exit_bb()

        self.assertEqual(bb0.successors[0], bb1)
        self.assertEqual(bb1.successors[0], exit_)

        self.assertEqual(functions[1].name, ".function_end")

    def test_x86_asm_parsing_opcode(self) -> None:

        tc = self.load_tc(ASM_OPCODE)
        functions = list(tc[0])

        main_iter = iter(functions[0])
        bb0 = next(main_iter)
        insts = list(bb0)
        self.assertEqual(insts[0].name, "macro")
        self.assertEqual(insts[1].name, "opcode")

    def test_x86_asm_parsing_section(self) -> None:
        prev_actors = deepcopy(CONF.get_actors_conf())
        CONF.get_actors_conf()["guest_1"] = deepcopy(CONF._actor_default)
        CONF.get_actors_conf()["guest_1"]["name"] = "guest_1"
        CONF.get_actors_conf()["guest_1"]["mode"] = "guest"
        CONF.get_actors_conf()["guest_1"]["privilege_level"] = "kernel"

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(X86TargetDesc())
        name = (test_dir / "asm/asm_multiactor.asm").absolute().as_posix()
        tc: TestCaseProgram = asm_parser.parse_file(name, generator, elf_parser)

        self.assertEqual(tc.n_actors(), 2)
        self.assertEqual(tc.find_actor(name="main").mode, ActorMode.HOST)
        self.assertEqual(tc.find_actor(name="main").get_id(), 0)
        self.assertEqual(tc.find_actor(name="guest_1").mode, ActorMode.GUEST)
        self.assertEqual(tc.find_actor(name="guest_1").get_id(), 1)

        self.assertEqual(len(tc), 2)

        sec1 = tc[0]
        self.assertEqual(len(sec1), 3)
        self.assertEqual(sec1.owner.get_id(), 0)
        self.assertTrue(sec1.owner.is_main)

        f1 = sec1[0]
        self.assertEqual(f1.name, ".function_0")
        self.assertEqual(len(f1[0]), 3)

        f2 = sec1[1]
        self.assertEqual(f2.name, ".function_2")
        self.assertEqual(len(f2[0]), 1)

        sec2 = tc[1]
        self.assertEqual(len(sec2), 1)
        self.assertEqual(sec2.owner.get_id(), 1)
        self.assertFalse(sec2.owner.is_main)

        f1 = sec2[0]
        self.assertEqual(f1.name, ".function_1")
        self.assertEqual(len(f1[0]), 1)

        CONF._actors = prev_actors

    def test_x86_asm_parsing_symbols(self) -> None:
        prev_actors = deepcopy(CONF.get_actors_conf())
        CONF.get_actors_conf()["guest_1"] = deepcopy(CONF._actor_default)
        CONF.get_actors_conf()["guest_1"]["name"] = "guest_1"
        CONF.get_actors_conf()["guest_1"]["mode"] = "guest"
        CONF.get_actors_conf()["guest_1"]["privilege_level"] = "kernel"

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())

        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(X86TargetDesc())
        name = (test_dir / "asm/asm_symbol.asm").absolute().as_posix()
        tc: TestCaseProgram = asm_parser.parse_file(name, generator, elf_parser)
        obj = tc.get_obj()
        symbol_table = obj.symbol_table()

        self.assertEqual(symbol_table[0], SymbolTableEntry(0, 0, 0, 0))  # function_0
        self.assertEqual(symbol_table[1], SymbolTableEntry(0, 0, 1, 0))
        self.assertEqual(symbol_table[2], SymbolTableEntry(0, 9, 2, 0))
        self.assertEqual(symbol_table[3], SymbolTableEntry(0, 20, 0, 1))  # function_1
        self.assertEqual(symbol_table[4], SymbolTableEntry(1, 0, 0, 2))  # function_2

        CONF._actors = prev_actors

    def test_x86_undef_flag_patch(self) -> None:
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories + ["BASE-FLAGOP"])
        undef_instr_spec = list(filter(lambda x: x.name == 'bsf', instruction_set.instructions))[0]
        read_instr_spec = list(filter(lambda x: x.name == 'lahf', instruction_set.instructions))[0]

        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        undef_instr = generator.generate_instruction(undef_instr_spec)
        read_instr = generator.generate_instruction(read_instr_spec)

        test_case = TestCaseProgram("")
        sec = test_case[0]
        func = Function(".function_0", sec)
        sec.append(func)
        bb = BasicBlock(".bb0", func)
        func.append(bb)
        bb.insert_after(bb.get_last(), undef_instr)
        bb.insert_after(bb.get_last(), read_instr)

        _X86PatchUndefinedFlagsPass(instruction_set, generator).run_on_test_case(test_case)
        self.assertEqual(len(bb), 3)
