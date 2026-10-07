"""
File: arm64 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import math
import random
from typing import List, Dict, TYPE_CHECKING, Tuple, Callable, Literal

from rvzr.code_generator import CodeGenerator, Pass, Printer
from rvzr.sandbox import SandboxLayout, DataArea
from rvzr.instruction_spec import InstructionSpec
from rvzr.tc_components.instruction import Instruction, Operand, RegisterOp, FlagsOp, \
    MemoryOp, ImmediateOp, AgenOp, CondOp
from rvzr.tc_components.test_case_code import TestCaseProgram, BasicBlock, InstructionNode

from .target_desc import ARM64TargetDesc

if TYPE_CHECKING:
    from rvzr.elf_parser import ELFParser
    from rvzr.asm_parser import AsmParser
    from rvzr.isa_spec import InstructionSet
    from rvzr.tc_components.instruction import RegSize
    from rvzr.target_desc import TargetDesc, RegName


# ==================================================================================================
# Private: Assembly Printing
# ==================================================================================================
class _ARM64Printer(Printer):

    def __init__(self, target_desc: ARM64TargetDesc) -> None:
        super().__init__(target_desc)
        self.prologue_template = [""]
        self.epilogue_template = [
            ".section .data.main\n",
            ".test_case_exit:nop\n",
        ]

    def _instruction_to_str(self, inst: Instruction) -> str:
        """
        Override to handle ARM64 conditional operands.
        """
        if inst.name == "macro":
            return self._macro_to_str(inst)

        # Handle conditional operands specially for ARM64
        cond_op_str = ""
        operands = list(inst.operands)
        if operands and isinstance(operands[0], CondOp):
            cond_op_str = operands[0].value
            operands = operands[1:]

        operands_str = ", ".join([self._operand_to_str(op) for op in operands])
        if inst.is_instrumentation:
            comment = "// instrumentation"
        elif inst.is_noremove:
            comment = "// noremove"
        else:
            comment = ""
        return f"{inst.name}{cond_op_str} {operands_str} {comment}"

    def _operand_to_str(self, op: Operand) -> str:
        if isinstance(op, (MemoryOp, AgenOp)):
            return f"[{op.value}]"
        if isinstance(op, ImmediateOp):
            if self._is_digit_extended(op.value):
                return f"#{op.value}"
            return f"{op.value}"

        return op.value

    def _macro_to_str(self, inst: Instruction) -> str:
        macro_placeholder = "nop; nop; nop"
        if inst.operands[1].value.lower() == ".noarg":
            return f".macro{inst.operands[0].value}: {macro_placeholder}"
        return f".macro{inst.operands[0].value}{inst.operands[1].value}: {macro_placeholder}"

    @staticmethod
    def _is_digit_extended(s: str) -> bool:
        """
        An extended version of the is_digit function. The difference is that is_digit
        handles only decimal numbers, while this function can handle hex and binary
        numbers as well.
        """
        try:
            base = 10
            if s.startswith("0x"):
                base = 16
            if s.startswith("0b"):
                base = 2
            int(s, base)
            return True
        except ValueError:
            return False


# ==================================================================================================
# Private: Collection of Instrumentation Passes
# ==================================================================================================

_DispatcherKey = Literal["memory"]
_SandboxDispatcher = Dict[_DispatcherKey, Tuple[List[InstructionNode],
                                                Callable[[InstructionNode, BasicBlock], None]]]


class _ARM64SandboxPass(Pass):
    """
    A pass that instruments the test case to prevent certain types of faults,
    including:
    - out-of-sandbox memory accesses
    - ... (more to be added in the future)

    NOTE: in contrast to x86, arm64 does not fault on div by zero, so no need to
    sandbox division instructions
    """

    # pylint: disable=R0801
    # justification: there's an overlap between this class and it's equivalent in x86/generator.py
    # This is acceptable for now as functions are different enough so that deduplication
    # would hurt readability

    def __init__(self, target_desc: TargetDesc) -> None:
        super().__init__()
        self.target_desc = target_desc

        size_of_directly_accessible_memory = SandboxLayout.data_area_size(DataArea.MAIN) \
            + SandboxLayout.data_area_size(DataArea.FAULTY)
        mask_width = int(math.log(size_of_directly_accessible_memory, 2))
        self.sandbox_address_mask = "#0b" + "1" * mask_width

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        dispatcher: _SandboxDispatcher = {
            "memory": ([], self._sandbox_memory_access),
        }

        for bb in test_case.iter_basic_blocks():
            dispatcher["memory"][0].clear()

            # collect all instructions that require sandboxing
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue

                if inst.has_mem_operand(True):
                    dispatcher["memory"][0].append(node)

            # sandbox them
            for _, (nodes, sandbox_func) in dispatcher.items():
                for node in nodes:
                    sandbox_func(node, bb)

    def _sandbox_memory_access(self, node: InstructionNode, parent: BasicBlock) -> None:
        """ Force the memory accesses into the page starting from x20 """

        instr = node.instruction

        # if implicit_mem_operands:
        #     raise GeneratorException("Implicit memory accesses are not supported")

        # raise GeneratorException("Attempt to sandbox an instruction without memory operands")

        mem_operands = instr.get_mem_operands(True)
        implicit_mem_operands = \
            instr.get_mem_operands(include_explicit=False, include_implicit=True)
        mask = self.sandbox_address_mask

        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, False, True)) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, False)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "", "", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)
            add_base = Instruction("add", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, False, True)) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, False)) \
                .add_op(RegisterOp("x20", 64, True, False)) \
                .add_op(FlagsOp(("w", "", "", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, add_base)
            return

        raise NotImplementedError("Implicit memory accesses are not yet supported")

    @staticmethod
    def requires_sandbox(inst: InstructionSpec) -> bool:
        """ Check if the instruction requires instrumentation to prevent faults """
        if inst.has_mem_operand:
            return True
        return False


class _ARM64PatchUndefinedLoadsPass(Pass):

    def __init__(self, target_desc: TargetDesc,
                 usable_registers_by_size: Dict[RegSize, List[RegName]]) -> None:
        super().__init__()
        self.target_desc = target_desc
        self.usable_registers_by_size = usable_registers_by_size

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        for bb in test_case.iter_basic_blocks():
            to_patch: List[Instruction] = []

            for node in bb.iter_nodes():
                inst = node.instruction

                if inst.is_instrumentation or inst.is_from_template:
                    continue

                # check if it's a load with post-index
                if self._is_post_index(inst):
                    to_patch.append(inst)

            # fix operands
            for inst in to_patch:
                org_dest = inst.operands[0]
                assert isinstance(org_dest, RegisterOp)
                assert org_dest.width in self.usable_registers_by_size
                options = self.usable_registers_by_size[org_dest.width]
                options = [i for i in options if i != org_dest.value]
                new_value = random.choice(options)
                inst.operands[0].value = new_value

    def _is_post_index(self, inst: Instruction) -> bool:
        if "ldr" not in inst.name and "str" not in inst.name:
            return False
        if inst.get_imm_operands() == []:
            return False

        ops = inst.operands
        assert isinstance(ops[0], RegisterOp)
        assert isinstance(ops[1], MemoryOp)
        normalized_dest = self.target_desc.reg_normalized[ops[0].value]
        normalized_dest = self.target_desc.reg_denormalized[normalized_dest][64]
        if normalized_dest in ops[1].value:
            return True
        return False


# ==================================================================================================
# Public Interface
# ==================================================================================================
class ARM64Generator(CodeGenerator):
    """ arm64-specific implementation of the test case program generator """

    def __init__(self, seed: int, instruction_set: InstructionSet, target_desc: TargetDesc,
                 asm_parser: AsmParser, elf_parser: ELFParser) -> None:
        super().__init__(seed, instruction_set, target_desc, asm_parser, elf_parser)
        assert isinstance(self._target_desc, ARM64TargetDesc)

        usable_registers = self._get_usable_registers()

        # configure instrumentation passes
        self._passes = [
            _ARM64SandboxPass(self._target_desc),
            _ARM64PatchUndefinedLoadsPass(self._target_desc, usable_registers),
        ]
        self._printer = _ARM64Printer(self._target_desc)
