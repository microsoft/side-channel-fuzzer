"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import subprocess
import os
from pathlib import Path
from copy import deepcopy

from rvzr.arch.arm64.generator import ARM64Generator, _ARM64Printer
from rvzr.arch.arm64.target_desc import ARM64TargetDesc
from rvzr.elf_parser import ELFParser
from rvzr.factory import get_program_generator, get_asm_parser, get_instruction_pool_constraints
from rvzr.isa_spec import InstructionSet
from rvzr.tc_components.actor import ActorMode
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_binary import SymbolTableEntry
from rvzr.code_generator import assemble
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change

CONF.instruction_set = "arm64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_OPCODE = """
.section .data.main
.long 0xd503201f
.test_case_exit:
"""


class ARM64GeneratorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        CONF.logging_modes = []
        update_logging_after_config_change()

    @staticmethod
    def load_tc(asm_str: str) -> TestCaseProgram:

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(), None,
                                         constraints)
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(ARM64TargetDesc())

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCaseProgram = asm_parser.parse_file(asm_file.name, generator, elf_parser)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def test_arm64_configuration(self) -> None:
        CONF.generator = "random"
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(),
                                         CONF.instruction_categories,
                                         get_instruction_pool_constraints())
        gen = get_program_generator(CONF.program_generator_seed, instruction_set)
        self.assertEqual(gen.__class__, ARM64Generator)

    def test_arm64_all_instructions(self) -> None:
        asm_file = tempfile.NamedTemporaryFile("w", delete=False)
        obj_file = tempfile.NamedTemporaryFile("w", delete=False)

        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(), None,
                                         get_instruction_pool_constraints())
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        tc = TestCaseProgram(asm_file.name)
        tc.assign_obj(obj_file.name)

        func = generator._function_generator\
            .generate_empty(".function_0", tc.find_section(name="main"))
        tc.find_section(name="main").append(func)
        printer = _ARM64Printer(ARM64TargetDesc())
        all_instructions = ['']

        # try generating instruction strings
        for bb in func:
            for instruction_spec in instruction_set.non_control_flow_specs:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)

            for instr in bb:
                instr_str = printer._instruction_to_str(instr)
                self.assertTrue(instr_str, f'Instruction {instr} was not generated.')
                all_instructions.append(instr_str + "\n")

        # apply generator passes
        for p in generator._passes:
            p.run_on_test_case(tc)

        # write the instructions to the asm file
        generator._printer.print(tc)

        # check if the generated instructions are valid
        try:
            assemble(tc)
        except subprocess.CalledProcessError:
            self.fail("Generated invalid instruction(s)")
        else:
            obj_file.close()
            os.unlink(obj_file.name)
        finally:
            os.unlink(asm_file.name)

    def test_arm64_asm_parsing_basic(self) -> None:
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(), None,
                                         get_instruction_pool_constraints())
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(ARM64TargetDesc())

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

    def test_arm64_asm_parsing_opcode(self) -> None:

        tc = self.load_tc(ASM_OPCODE)
        functions = list(tc[0])

        main_iter = iter(functions[0])
        bb0 = next(main_iter)
        insts = list(bb0)
        self.assertEqual(insts[0].name, "macro")
        self.assertEqual(insts[1].name, "opcode")

    def test_arm64_asm_parsing_section(self) -> None:
        prev_actors = deepcopy(CONF.get_actors_conf())
        CONF.get_actors_conf()["guest_1"] = deepcopy(CONF._actor_default)
        CONF.get_actors_conf()["guest_1"]["name"] = "guest_1"
        CONF.get_actors_conf()["guest_1"]["mode"] = "guest"
        CONF.get_actors_conf()["guest_1"]["privilege_level"] = "kernel"

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(), None,
                                         constraints)
        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(ARM64TargetDesc())
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

    def test_arm64_asm_parsing_symbols(self) -> None:
        prev_actors = deepcopy(CONF.get_actors_conf())
        CONF.get_actors_conf()["guest_1"] = deepcopy(CONF._actor_default)
        CONF.get_actors_conf()["guest_1"]["name"] = "guest_1"
        CONF.get_actors_conf()["guest_1"]["mode"] = "guest"
        CONF.get_actors_conf()["guest_1"]["privilege_level"] = "kernel"

        constraints = get_instruction_pool_constraints()
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(), None,
                                         constraints)

        generator = get_program_generator(CONF.program_generator_seed, instruction_set)
        asm_parser = get_asm_parser(instruction_set)
        elf_parser = ELFParser(ARM64TargetDesc())
        name = (test_dir / "asm/asm_symbol.asm").absolute().as_posix()
        tc: TestCaseProgram = asm_parser.parse_file(name, generator, elf_parser)
        obj = tc.get_obj()
        symbol_table = obj.symbol_table()

        self.assertEqual(symbol_table[0], SymbolTableEntry(0, 0, 0, 0))  # function_0
        self.assertEqual(symbol_table[1], SymbolTableEntry(0, 0, 1, 0))  # measurement_start
        self.assertEqual(symbol_table[2], SymbolTableEntry(0, 0x10, 2, 0))  # measurement_end
        self.assertEqual(symbol_table[3], SymbolTableEntry(0, 0x20, 0, 1))  # function_1
        self.assertEqual(symbol_table[4], SymbolTableEntry(1, 0, 0, 2))  # function_2

        CONF._actors = prev_actors
