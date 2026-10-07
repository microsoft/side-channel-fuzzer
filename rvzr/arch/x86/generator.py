"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import math
import re
import random
from copy import deepcopy
from dataclasses import dataclass
from typing import List, Dict, Set, TYPE_CHECKING, Union, Final, Tuple, Callable, Literal
from typing_extensions import assert_never

from rvzr.code_generator import CodeGenerator, Pass, Printer
from rvzr.config import CONF
from rvzr.sandbox import SandboxLayout, DataArea, PAGE_SIZE
from rvzr.instruction_spec import OT, InstructionSpec
from rvzr.tc_components.actor import ActorPL, ActorID
from rvzr.tc_components.instruction import Instruction, Operand, RegisterOp, FlagsOp, \
    MemoryOp, ImmediateOp, AgenOp, copy_op_with_flow_modification, \
    copy_inst_with_modification
from rvzr.tc_components.test_case_code import TestCaseProgram, BasicBlock, InstructionNode

from .target_desc import X86TargetDesc

if TYPE_CHECKING:
    from rvzr.elf_parser import ELFParser
    from rvzr.asm_parser import AsmParser
    from rvzr.isa_spec import InstructionSet
    from rvzr.tc_components.instruction import RegSize
    from rvzr.target_desc import TargetDesc, RegName


# ==================================================================================================
# Private: Fault Type Identification
# ==================================================================================================
@dataclass
class _FaultFilter:
    """ Local service class that identifies which faults are allowed in test cases. """

    def __init__(self) -> None:
        self.div_by_zero: bool = 'div-by-zero' in CONF.faults_allowlist
        self.div_overflow: bool = 'div-overflow' in CONF.faults_allowlist
        self.non_canonical_access: bool = 'non-canonical-access' in CONF.faults_allowlist
        self.u2k_access: bool = 'user-to-kernel-access' in CONF.faults_allowlist


# ==================================================================================================
# Private: Assembly Printing
# ==================================================================================================
class _X86Printer(Printer):
    target_desc: X86TargetDesc

    def __init__(self, target_desc: X86TargetDesc) -> None:
        super().__init__(target_desc)
        self.prologue_template = [".intel_syntax noprefix\n"]
        self.epilogue_template = [
            ".section .data.main\n",
            ".test_case_exit:nop\n",
        ]

    def _instruction_to_str(self, inst: Instruction) -> str:
        if inst.name == "macro":
            return self._macro_to_str(inst)

        operands = ", ".join([self._operand_to_str(op) for op in inst.operands])
        if inst.is_instrumentation:
            comment = "# instrumentation"
        elif inst.is_noremove:
            comment = "# noremove"
        else:
            comment = ""
        return f"{inst.name} {operands} {comment}"

    def _operand_to_str(self, op: Operand) -> str:
        if isinstance(op, (MemoryOp, AgenOp)):
            prefix = self.target_desc.memory_addr_prefixes[op.width]
            return f"{prefix} [{op.value}]"

        return op.value

    def _macro_to_str(self, inst: Instruction) -> str:
        macro_placeholder = "nop qword ptr [rax + 0xff]"
        if inst.operands[1].value.lower() == ".noarg":
            return f".macro{inst.operands[0].value}: {macro_placeholder}"
        return f".macro{inst.operands[0].value}{inst.operands[1].value}: {macro_placeholder}"


# ==================================================================================================
# Private: Collection of Instrumentation Passes
# ==================================================================================================
class _X86NonCanonicalAddressPass(Pass):
    """
    A pass that selects a random memory access instruction and replaces it with an access to a
    non-canonical address.
    """
    _target_desc: X86TargetDesc

    def __init__(self, target_desc: X86TargetDesc) -> None:
        super().__init__()
        self._target_desc = target_desc

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        for bb in test_case.iter_basic_blocks():
            memory_instructions = []
            for node in bb.iter_nodes():
                instr = node.instruction
                if instr.is_instrumentation or instr.is_from_template:
                    continue
                if instr.name in ["div", "idiv"]:
                    # Instrumentation is difficult to combine
                    continue
                if instr.has_mem_operand(True):
                    memory_instructions.append(node)

            # instrument random memory access instructions
            for node in memory_instructions:
                n = len(memory_instructions)
                rand_bool = random.randint(0, n) == 0
                if not rand_bool:
                    continue
                self._instrument(node, bb)

                # Make sure #GP happens only once. Otherwise Unicorn keeps raising an exception
                # when rolling back to the end of the code
                return

    def _instrument(self, node: InstructionNode, parent: BasicBlock) -> None:
        """ Instrument a selected memory access instruction to make the access non-canonical. """
        # pylint: disable = too-many-locals
        # justification: It's a fairly complex instrumentation, so the number of locals is justified
        instr = node.instruction

        # Collect src operands
        src_operands = []
        for o in instr.get_src_operands():
            if isinstance(o, RegisterOp):
                src_operands.append(o)

        # Check if the instrumentation is possible
        mem_operands = instr.get_mem_operands(include_explicit=True)
        implicit_mem_operands = \
            instr.get_mem_operands(include_explicit=False, include_implicit=True)
        if not mem_operands or implicit_mem_operands:
            return  # this instruction is hard to instrument; skip

        # Find registers suitable for the instrumentation
        assert len(mem_operands) == 1, f"Unexpected instruction format {instr.name}"
        mem_operand: Operand = mem_operands[0]
        mask_reg = self._find_mask_register(src_operands)
        offset_reg = self._find_offset_register(instr)

        # Generate a random mask to make the address non-canonical
        mask = hex((random.getrandbits(16) << 48))

        # Add the instrumentation sequence:
        #  lea offset_reg, [mem_operand]
        #  mov mask_reg, mask
        #  xor offset_reg, mask_reg
        lea = Instruction("lea", is_instrumentation=True) \
            .add_op(RegisterOp(offset_reg, 64, False, True)) \
            .add_op(MemoryOp(mem_operand.value, 64, True, False))
        parent.insert_before(node, lea)
        mov = Instruction("mov", is_instrumentation=True) \
            .add_op(RegisterOp(mask_reg, 64, True, True)) \
            .add_op(ImmediateOp(mask, 64))
        parent.insert_before(node, mov)
        mask_inst = Instruction("xor", is_instrumentation=True) \
            .add_op(RegisterOp(offset_reg, 64, True, True)) \
            .add_op(RegisterOp(mask_reg, 64, True, False))
        parent.insert_before(node, mask_inst)

        # Update the memory operand
        for idx, op in enumerate(instr.operands):
            if op == mem_operand:
                old_op = instr.operands[idx]
                assert isinstance(old_op, MemoryOp)
                addr_op = MemoryOp(offset_reg, old_op.width, old_op.src, old_op.dest)
                instr.operands[idx] = addr_op

    def _find_mask_register(self, src_operands: List[RegisterOp]) -> str:
        # Do not overwrite offset register with mask
        candidate_list = ["rax", "rbx"]
        mask_reg = candidate_list[0]
        for operands in src_operands:
            op_regs = re.split(r'\+|-|\*| ', operands.value)
            for reg in op_regs:
                if self._target_desc.reg_normalized[mask_reg] == \
                   self._target_desc.reg_normalized[reg]:
                    mask_reg = candidate_list[1]
        return mask_reg

    def _find_offset_register(self, inst: Instruction) -> str:
        # Do not reuse destination register
        candidate_list = ["rcx", "rdx"]
        offset_reg = candidate_list[0]
        for op in inst.get_all_operands():
            if not isinstance(op, RegisterOp):
                continue
            if self._target_desc.reg_normalized[offset_reg] == \
               self._target_desc.reg_normalized[op.value]:
                offset_reg = candidate_list[1]
        return offset_reg


class _X86U2KAccessPass(Pass):
    """
    User-to-Kernel Access Instrumentation Pass.

    This pass instruments user-privilege actors to perform memory accesses targeting
    the kernel actor's (actor 0) FAULTY data area. This creates cross-privilege-level
    memory access patterns useful for detecting CPU vulnerabilities like Meltdown.

    The pass randomly selects memory access instructions in user actors and modifies
    their memory operands to access kernel memory by calculating and applying a fixed
    offset based on the sandbox memory layout.

    IMPORTANT: This pass must run after _X86SandboxPass because it modifies the
    sandboxing instrumentation to ensure memory accesses target a single page.
    """

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Identify and instrument memory accesses in user-privilege actors.

        :param test_case: The test case to process
        """
        # Use enumeration order as actor ID
        # FIXME: This is potentially fragile as it assumes that the sections in the binary
        # will be ordered the same way as the actors were defined in the test case, which
        # may not always hold true. However, we cannot get the actual section ID here because
        # the assembly is not yet generated, so there is nothing to assemble. It's a chicken-and-egg
        # problem. Thus, for now, we have to rely on this assumption.
        for sec_id, sec in enumerate(test_case):
            owner = sec.owner
            # Only instrument user-privilege actors (kernel accesses don't trigger Meltdown)
            if owner.privilege_level != ActorPL.USER:
                continue

            for func in sec:
                to_instrument: List[InstructionNode] = []
                for bb in func:
                    for node in bb.iter_nodes():
                        instr = node.instruction
                        # Skip instrumentation code and template code
                        if instr.is_instrumentation or instr.is_from_template:
                            continue
                        # Skip div/idiv as instrumentation interferes with their operand constraints
                        if instr.name in ["div", "idiv"]:
                            continue
                        if instr.has_mem_operand(False):
                            to_instrument.append(node)

                    for node in to_instrument:
                        # Randomly select instructions based on avg_mem_accesses config
                        probability = 1 / CONF.avg_mem_accesses
                        if random.random() > probability:
                            continue

                        self._instrument(node, bb, sec_id)

    def _instrument(self, node: InstructionNode, _: BasicBlock, owner_id: ActorID) -> None:
        """
        Modify a memory access instruction to target kernel memory instead of user memory.
        :param node: The instruction node to instrument
        :param _: The parent basic block (unused)
        :param owner_id: The actor ID of the instruction's owner (used for offset calculation)
        """
        instr = node.instruction

        # Calculate the memory offset from user's MAIN area to kernel's FAULTY area.
        # We use a dummy SandboxLayout with base (0,0) to compute the relative offset
        # between the two memory regions based on their positions in the sandbox layout.
        layout = SandboxLayout((0, 0), owner_id)
        user_main_start = layout.get_data_addr(DataArea.MAIN, owner_id)
        kernel_faulty_start = layout.get_data_addr(DataArea.FAULTY, 0)
        offset = user_main_start - kernel_faulty_start

        # Select which memory operand to modify (random if instruction has multiple)
        mem_operands: List[MemoryOp] = instr.get_mem_operands(True)
        if len(mem_operands) == 1:
            mem_operand = mem_operands[0]
        else:
            mem_operand = random.choice(mem_operands)

        # Redirect the memory access to kernel memory by subtracting the offset
        mem_operand.value += " - " + str(offset)

        # Adjust sandboxing masks added by X86SandboxPass to target a single page.
        # X86SandboxPass adds AND instructions to mask memory addresses to stay within
        # the actor's data sandbox. We need to reduce these masks to PAGE_SIZE to ensure
        # the cross-privilege access targets only the kernel's FAULTY page.
        previous_node = node.previous
        while previous_node and previous_node.instruction.is_instrumentation:
            for op in previous_node.instruction.operands:
                if not isinstance(op, ImmediateOp):
                    continue
                mask_value = int(op.value, base=0)
                if mask_value > PAGE_SIZE:
                    mask_value %= PAGE_SIZE
                op.value = bin(mask_value)
            previous_node = previous_node.previous


_DispatcherKey = Literal["memory", "division", "bit_test", "repeated", "corrupted_cf", "enclu"]
_SandboxDispatcher = Dict[_DispatcherKey, Tuple[List[InstructionNode],
                                                Callable[[InstructionNode, BasicBlock], None]]]


class _X86SandboxPass(Pass):
    """
    A pass that instruments the test case to prevent certain types of faults,
    including:
    - division by zero
    - division overflow
    - out-of-sandbox memory accesses
    - CF corruption
    - invalid ENCLU operands
    """

    mask_3bits = "0b111"
    bit_test_names = ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]

    def __init__(self, target_desc: TargetDesc, faults: _FaultFilter,
                 usable_registers_by_size: Dict[RegSize, List[RegName]]) -> None:
        super().__init__()
        self.target_desc = target_desc
        self.faults = faults
        self.usable_registers_by_size = usable_registers_by_size

        size_of_directly_accessible_memory = SandboxLayout.data_area_size(DataArea.MAIN) \
            + SandboxLayout.data_area_size(DataArea.FAULTY)
        mask_width = int(math.log(size_of_directly_accessible_memory, 2))
        self.sandbox_address_mask = "0b" + "1" * mask_width

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        dispatcher: _SandboxDispatcher = {
            "memory": ([], self._sandbox_memory_access),
            "division": ([], self._sandbox_division),
            "bit_test": ([], self._sandbox_bit_test),
            "repeated": ([], self._sandbox_repeated_instruction),
            "corrupted_cf": ([], self._sandbox_corrupted_cf),
            "enclu": ([], self._sandbox_enclu),
        }

        for bb in test_case.iter_basic_blocks():
            dispatcher["memory"][0].clear()
            dispatcher["division"][0].clear()
            dispatcher["bit_test"][0].clear()
            dispatcher["repeated"][0].clear()
            dispatcher["corrupted_cf"][0].clear()
            dispatcher["enclu"][0].clear()

            # collect all instructions that require sandboxing
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue

                if inst.has_mem_operand(True):
                    dispatcher["memory"][0].append(node)
                if inst.name in ["div", "rex div", "idiv", "rex idiv"]:
                    dispatcher["division"][0].append(node)
                elif inst.name in self.bit_test_names:
                    dispatcher["bit_test"][0].append(node)
                elif "rep" in inst.name:
                    dispatcher["repeated"][0].append(node)
                elif inst.category in ["BASE-ROTATE", "BASE-SHIFT"]:
                    dispatcher["corrupted_cf"][0].append(node)
                elif inst.name == "enclu":
                    dispatcher["enclu"][0].append(node)

            # sandbox them
            for _, (nodes, sandbox_func) in dispatcher.items():
                for node in nodes:
                    sandbox_func(node, bb)

    def _sandbox_memory_access(self, node: InstructionNode, parent: BasicBlock) -> None:
        """ Force the memory accesses into the page starting from R14 """
        instr = node.instruction

        mem_operands = instr.get_mem_operands(True)
        implicit_mem_operands = instr.get_mem_operands(
            include_explicit=False, include_implicit=True)

        mask = self.sandbox_address_mask
        if any(op.width >= 256 for op in mem_operands):
            mask = mask[:-5] + "0" * 5
        elif any(op.width >= 128 for op in mem_operands):
            mask = mask[:-4] + "0" * 4

        if getattr(CONF, 'x86_generator_align_locks'):
            if "lock" in instr.name or instr.name == "xchg":
                mask = mask[:-3] + "0" * 3

        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, 64, True, True)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)
            instr.get_mem_operands(True)[0].value = "r14 + " + address_reg
            return

        mem_operands = implicit_mem_operands
        assert mem_operands, "Attempt to sandbox an instruction without memory operands"

        # deduplicate operands
        uniq_operands: Dict[str, MemoryOp] = {}
        for o in mem_operands:
            if o.value not in uniq_operands:
                uniq_operands[o.value] = o

        # instrument each operand to sandbox the memory accesses
        for address_reg, mem_operand in uniq_operands.items():
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            assert address_reg in self.usable_registers_by_size[64], \
                f"Unexpected address register {address_reg} used in {instr}"
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOp(mask, imm_width)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)

            add_base = Instruction("add", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOp("r14", 64, True, False)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, add_base)

            # restore the original register value
            remove_base = Instruction("sub", is_instrumentation=True) \
                .add_op(RegisterOp(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOp("r14", 64, True, False)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_after(node, remove_base)

    def _sandbox_division(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        In the experiments where division errors are not permitted, we prevent them
        through code instrumentation.
        Specifically, we may need to prevent two types of faults:
        - division by zero
        - division overflow (i.e., quotient is larger than the destination register)

        To prevent div by zero we OR the divider with a non-zero value:
            divisor = divisor | 1

        The mechanism for preventing div overflows depends on the division type:
        * for unsigned division, we first mask the upper half of the dividend with the divisor,
        which makes the quotient at most one bit larger then the destination, and then shift
        the result by one, thus compensating for the last one overflow bit.
            D = (D & divisor) >> 1
        * for signed division, we make set its lower bits to 0b10000, which ensures that
        all positive divider values are larger or equal to 15, and all negative values
        are smaller or equal to -15.
            divisor[0:3] = 0b1000
        We further constraint the division by clearing the sign bit of the dividend.
        Under these two constraints, an overflow is possible only when the dividend
        is larger  or equal to (15 << div_size, e.g., for 32-bit division 15 * (2 ** 32)).
        Since, the dividend is a combination of two registers (D << div_size + A),
        an overflow happens when D is larger or equal to 15. We ensure that it does not
        happen by masking the upper bits of D:
            D = D & 0b11

        There are also two corner cases:
            1) The divisor is D. This case is impossible to resolve, as far as I can tell,
            because our instrumentation would have to modify both the divisor and the dividend
            at the same time. We just give up in this case and delete the instruction.
            2) 8-bit division, when the divisor is the AX register alone.
            Here the instrumentation becomes too complicated, so we simply set AX to 1.

        This instrumentation has a side effect of reducing the entropy of the division operands:
        For unsigned division:
            * entropy of the divisor is reduced by 1 bit
            * entropy of D is reduced by (divisor_value_size + 1) bits
        For signed division:
            * entropy of the divisor is reduced by 4 bits
            * entropy of D is reduced by (division_size - 2) bits (i.e., the resulting
              entropy of D is 2 bits, with the sign bit cleared)
        """
        # pylint: disable = too-many-locals
        # justification: FIXME - pending

        inst = node.instruction

        # Determine what type of fault is allowed
        owner_name = parent.get_owner().name
        actor_blocklist = CONF.get_actors_conf()[owner_name]["fault_blocklist"]
        enable_div_by_zero = self.faults.div_by_zero & ("div-by-zero" not in actor_blocklist)
        enable_div_overflow = self.faults.div_overflow & ("div-overflow" not in actor_blocklist)

        # Copy div source operand and label it as a destination; we may need to modify it
        operand = inst.operands[0]
        assert isinstance(operand, (RegisterOp, MemoryOp)), \
               f"Unexpected operand type {operand}"
        divisor = copy_op_with_flow_modification(operand, dest=True)
        size = divisor.width

        # Prevent div by zero
        if not enable_div_by_zero:
            if "idiv" not in inst.name or enable_div_overflow:
                # for unsigned division and signed divisions with overflow permitted,
                # it is sufficient to OR the divisor with 1 to prevent div by zero
                instrumentation = Instruction("or", is_instrumentation=True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOp("1", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)
            else:
                # for signed divisions with overflows forbidden,
                # we need to modify the divisor to make it both non-zero
                # and large enough to avoid overflows.
                # We have two cases here, positive and negative divider values:

                # For positive dividers, we OR the divisor with 0b10000 to make sure
                # that the divider is at least 15
                # (the value 15 comes from the instrumentation below, where
                # we make the dividend at most `4 << div_size - 1`)
                instrumentation = Instruction("or", is_instrumentation=True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOp("0b1000", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)

                # For negative dividers, we clear the lower 4 bits of the divider,
                # thus making the value at most -15. To this end, we AND
                # the lower 8 bits of the divider bit a bit mask 0b11110000
                divider_8_bit: Union[RegisterOp, MemoryOp]
                if isinstance(divisor, MemoryOp):
                    divider_8_bit = MemoryOp(divisor.value, 8, divisor.src, divisor.dest)
                elif isinstance(divisor, RegisterOp):
                    reg_normalized = self.target_desc.reg_normalized[divisor.value]
                    reg_8_bit = self.target_desc.reg_denormalized[reg_normalized][8]
                    divider_8_bit = RegisterOp(reg_8_bit, 8, divisor.src, divisor.dest)
                else:
                    assert_never(divisor)

                instrumentation = Instruction("and", is_instrumentation=True) \
                    .add_op(divider_8_bit) \
                    .add_op(ImmediateOp("0b11111000", 8)) \
                    .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
                parent.insert_before(node, instrumentation)

        if enable_div_overflow:
            return
        # Prevent div overflows:

        # Check for the cases that are impossible to instrument:
        # - division by D register
        # - division by a memory value with the RDX offset
        # - division where AX is both the dividend and the offset in memory
        if divisor.value in ["rdx", "edx", "dx", "dh", "dl"] \
           or "rdx" in divisor.value \
           or ("rax" in divisor.value and size == 8):
            parent.delete(node)
            return

        # Special case: dividend in AX
        # instrumentation: ax = 1
        if size == 8:
            instrumentation = Instruction("mov", is_instrumentation=True).\
                add_op(RegisterOp("ax", 16, False, True)).\
                add_op(ImmediateOp("1", 16))
            parent.insert_before(node, instrumentation)
            return

        # Normal case
        d_register = {64: "rdx", 32: "edx", 16: "dx"}[size]

        # signed div
        if "idiv" in inst.name:
            # it's extremely hard to prevent overflows with large signed divisions
            # that's why we simplify the case by assigning zero to the upper bits of the dividend
            # instrumentation, thus making the dividend at most `4 << div_size - 1`
            # D = D & 3
            instrumentation = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(ImmediateOp("0b11", 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, instrumentation)

        # unsigned div
        else:
            # instrumentation:
            # D = (D & divisor) >> 1  # ensure that D is always smaller than the divisor
            instrumentation = Instruction("and", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(divisor) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, instrumentation)

            instrumentation = Instruction("shr", is_instrumentation=True) \
                .add_op(RegisterOp(d_register, size, True, True)) \
                .add_op(ImmediateOp("1", 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "undef")), True)
            parent.insert_before(node, instrumentation)

    def _sandbox_bit_test(self, node: InstructionNode, parent: BasicBlock) -> None:
        """
        The address accessed by a BT* instruction is based on both of its operands.
        `sandbox_memory_access` take care of the first operand.
        This function ensures that the offset is always within a byte.
        """
        inst = node.instruction

        address = inst.operands[0]
        if isinstance(address, RegisterOp):
            # this is a version that does not access memory
            # no need for sandboxing
            return

        offset = inst.operands[1]
        if isinstance(offset, ImmediateOp):
            # The offset is an immediate
            # Simply replace it with a smaller value
            offset.value = str(random.randint(0, 7))
            return

        # The offset is in a register
        assert isinstance(offset, RegisterOp)

        # Mask its upper bits to reduce the stored value to at most 7
        if address.value != offset.value:
            new_offset = copy_op_with_flow_modification(offset, dest=True)
            apply_mask = Instruction("and", is_instrumentation=True) \
                .add_op(new_offset) \
                .add_op(ImmediateOp(self.mask_3bits, 8)) \
                .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
            parent.insert_before(node, apply_mask)
            return

        # Special case: offset and address use the same register
        # Sandboxing is impossible. Give up
        parent.delete(node)

    def _sandbox_repeated_instruction(self, node: InstructionNode, parent: BasicBlock) -> None:
        apply_mask = Instruction("and", is_instrumentation=True) \
            .add_op(RegisterOp("rcx", 64, True, True)) \
            .add_op(ImmediateOp("0xff", 8)) \
            .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
        add_base = Instruction("add", is_instrumentation=True) \
            .add_op(RegisterOp("rcx", 64, True, True)) \
            .add_op(ImmediateOp("1", 1)) \
            .add_op(FlagsOp(("w", "w", "w", "w", "w", "", "", "", "w")), True)
        parent.insert_before(node, apply_mask)
        parent.insert_before(node, add_base)

    def _sandbox_corrupted_cf(self, node: InstructionNode, parent: BasicBlock) -> None:
        # FIXME: This should be a separate pass

        set_cf = Instruction("stc", is_instrumentation=True) \
            .add_op(FlagsOp(("w", "", "", "", "", "", "", "", "")), True)
        parent.insert_after(node, set_cf)

    def _sandbox_enclu(self, node: InstructionNode, parent: BasicBlock) -> None:
        # FIXME: This should be a separate pass
        options = [
            "0",  # ereport
            "1",  # egetkey
            "4",  # eexit
            "5",  # eaccept
            "6",  # emodpe
            "7",  # eacceptcopy
        ]
        set_rax = Instruction("mov", is_instrumentation=True) \
            .add_op(RegisterOp("eax", 32, True, True)) \
            .add_op(ImmediateOp(random.choice(options), 1))
        parent.insert_before(node, set_rax)

    @staticmethod
    def requires_sandbox(inst: InstructionSpec) -> bool:
        """ Check if the instruction requires instrumentation to prevent faults """
        if inst.has_mem_operand:
            return True
        if inst.name in ["div", "rex div"]:
            return True
        if inst.name in ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]:
            return True
        if inst.category in ["BASE-SHIFT", "BASE-ROTATE"]:
            return True
        return False


class _X86PatchUndefinedFlagsPass(Pass):
    """
    Some instructions have undefined effect on FLAGS (e.g., SHL may or may not overwrite OF).
    This causes a mismatch between Model execution and Executor, if the undefined behavior
    is implemented differently. It leads to false positives.
    To prevent them, we analyse the test cases in search for the cases where an instruction
    with undefined flags is followed by an instruction that uses this flag. We then
    insert another random instruction in-between, such that this
    instruction overwrites the undefined flag.

    I.e., we replace
        SHL eax, eax  // undefined OF
        JNO .label    // uses OF
    with
        SHL eax, eax
        ADD ebx, ecx  // random instruction that overwrites OF
        JNO .label
    """
    patch_candidates: List[InstructionSpec]

    def __init__(self, instruction_set: InstructionSet, generator: CodeGenerator) -> None:
        super().__init__()
        self.instruction_set = instruction_set
        self.generator = generator

        self.patch_candidates = []
        for instruction_spec in instruction_set.instructions:
            # we don't want to change the control flow
            if instruction_spec.is_control_flow:
                continue

            # check if the instruction is safe to use on its own
            if _X86SandboxPass.requires_sandbox(instruction_spec):
                continue

            # check if it overwrites flags and if creates new dependencies
            has_read = False
            has_write = False
            for op in instruction_spec.operands + instruction_spec.implicit_operands:
                if op.type == OT.FLAGS:
                    for f in op.values:
                        if f in ['r', 'r/w', 'r/cw']:
                            has_read = True
                        elif f in ['w']:
                            has_write = True
            if not has_read and has_write:
                self.patch_candidates.append(instruction_spec)

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        for bb in test_case.iter_basic_blocks():
            self._patch_flags_in_bb(bb)

    def _patch_flags_in_bb(self, bb: BasicBlock) -> None:
        # pylint: disable = too-many-branches
        # justification: FIXME - his function was written in a hurry and needs to be refactored

        # get a list of all instruction nodes in the BB
        all_instructions: List[InstructionNode] = []
        for node in bb.iter_nodes():
            all_instructions.append(node)

        # Initialize a list used to track the flags that have to be set
        flags_to_set: Set[str] = set()

        # Collect the flags read by the terminators (conditional jumps)
        # Note: we assume that terminators do not modify flags
        # and hence no patching is needed at this point
        for term in bb.terminators:
            flags = term.get_flags_operand()
            if flags:
                for f in flags.get_flags_by_type('read'):
                    flags_to_set.add(f)

        # Walk the instruction list in the reverse order
        # During the walk, track flags have undefined values and overwrite them by adding
        # extra instructions in-between
        while all_instructions:
            node = all_instructions.pop()
            inst = node.instruction
            flags = inst.get_flags_operand()

            # skip template instructions and instructions that do not read/write flags
            if inst.is_from_template or not flags:
                continue

            # fix undefined flags by adding another instruction in-between
            undef_flags = [i for i in flags.get_flags_by_type('undef') if i in flags_to_set]
            if undef_flags:
                patches = self._find_flags_patch(undef_flags, flags_to_set)
                for patch in patches:
                    bb.insert_after(node, patch)
                    # remove the flags overwritten by the patch
                    for f in patch.get_flags_operand().get_flags_by_type('write'):  # type: ignore
                        flags_to_set.discard(f)

            # remove the flags overwritten by the instruction
            for f in flags.get_flags_by_type('write'):
                flags_to_set.discard(f)

            # add new flag dependencies
            for f in flags.get_flags_by_type('read'):
                flags_to_set.add(f)

        # make sure that we do not have undefined flags when we enter the BB
        if flags_to_set:
            # find a place to insert the patches
            entry_node = bb.get_first(exclude_macros=True)
            if not entry_node:
                raise ValueError("X86PatchUndefinedFlagsPass: No place to insert a patch")

            patches = self._find_flags_patch(list(flags_to_set), flags_to_set)
            for patch in patches:
                bb.insert_before(entry_node, patch)

    def _find_flags_patch(self, undef_flags: List[str],
                          flags_to_set: Set[str]) -> List[Instruction]:
        """
        Find an instruction sequence that would overwrite a list of flags
        :param undef_flags: list of undefined flags that have to be overwritten
            by the patch instructions
        :param flags_to_set: list of flags that will be read by one of the following instructions,
            and thus should not be set to the undef state by the patch. This should be always
            a superset of or the same as undef_flags.
        :return: list of instructions that overwrite the undefined flags
        """
        org_undef = deepcopy(undef_flags)
        patches: List[Instruction] = []
        for instruction_spec in self.patch_candidates:
            patch = self.generator.generate_instruction(instruction_spec, True)
            patch_flags = patch.get_flags_operand()
            assert patch_flags
            new_undef_flags = [
                i for i in patch_flags.get_flags_by_type('undef')
                if i not in undef_flags and i in flags_to_set
            ]
            not_patched_flags = [
                i for i in undef_flags if i not in patch_flags.get_flags_by_type('write')
            ]

            if not new_undef_flags and not_patched_flags != undef_flags:
                patches.append(patch)
                undef_flags = not_patched_flags
                if not undef_flags:
                    break

        if undef_flags:
            raise ValueError("Could not find an instruction to patch flags.\n"
                             f"  Initial flags to be patched: {org_undef}\n"
                             f"  Flags for which a patch was not found: {undef_flags}")

        return patches


class _X86PatchUndefinedResultPass(Pass):
    """
    Some instructions have undefined results when the source operand is zero.
    This pass patches such instructions to avoid undefined behavior.
    """

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        # call _patch_bit_scan on all bit scan instructions
        for bb in test_case.iter_basic_blocks():
            bit_scan = []
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue
                if inst.name in ["bsf", "bsr"]:
                    bit_scan.append(node)
            for node in bit_scan:
                self._patch_bit_scan(node, bb)

    @staticmethod
    def _patch_bit_scan(node: InstructionNode, parent: BasicBlock) -> None:
        """
        Bit Scan instructions give an undefined result when the source operand is zero.
        To avoid it, set the most significant bit.
        """
        inst = node.instruction

        # get the source operand
        src_operand = inst.operands[1]
        assert isinstance(src_operand, (RegisterOp, MemoryOp)), \
               f"Unexpected operand type {src_operand}"

        # copy because we may modify it
        source = copy_op_with_flow_modification(src_operand, dest=True)

        mask = bin(1 << (source.width - 1))
        mask_size = source.width
        if source.width in [64, 32]:
            mask = "0b1000000000000000000000000000000"
            mask_size = 32
        apply_mask = Instruction("or", is_instrumentation=True) \
            .add_op(source) \
            .add_op(ImmediateOp(mask, mask_size)) \
            .add_op(FlagsOp(("w", "w", "undef", "w", "w", "", "", "", "w")), True)
        parent.insert_before(node, apply_mask)


class _X86PatchOpcodesPass(Pass):
    """
    Replaces assembly instructions with their opcodes.
    This is necessary to test instruction with multiple opcodes and
    the instruction that are not supported/not permitted by the standard
    assembler.
    """
    _OPCODES: Final[Dict[str, List[str]]] = {
        "ud2": [
            "0x0f, 0x0b",  # UD2 instruction
            # invalid in 64-bit mode;
            # all the following opcodes are padded
            # with NOP to prevent misinterpretation by objdump
            "0x06, 0x90",  # 32-bit encoding of PUSH
            "0x07, 0x90",  # 32-bit encoding of POP
            "0x0e, 0x90",  # alternative 32-bit encoding of PUSH
            "0x16, 0x90",  # alternative 32-bit encoding of PUSH
            "0x17, 0x90",  # alternative 32-bit encoding of POP
            "0x1e, 0x90",  # alternative 32-bit encoding of PUSH
            "0x1f, 0x90",  # alternative 32-bit encoding of POP
            "0x27, 0x90",  # DAA
            "0x2f, 0x90",  # DAS
            "0x37, 0x90",  # AAA
            "0x3f, 0x90",  # AAS
            "0x60, 0x90",  # PUSHA
            "0x61, 0x90",  # POPA
            "0x62, 0x90",  # BOUND
            "0x82, 0x90",  # 32-bit aliases for logical instructions
            "0x9a, 0x90",  # 32-bit encoding of CALLF
            "0xc4, 0x90",  # LES
            "0xd4, 0x90",  # AAM
            "0xd5, 0x90",  # AAD
            "0xd6, 0x90",  # reserved
            "0xea, 0x90",  # 32-bit encoding of JMPF
        ],
        "int1": ["0xf1"]
    }

    def run_on_test_case(self, test_case: TestCaseProgram) -> None:
        for bb in test_case.iter_basic_blocks():
            # collect all UD instructions
            to_patch = []
            for node in bb.iter_nodes():
                inst = node.instruction
                if inst.is_instrumentation or inst.is_from_template:
                    continue
                if inst.name in self._OPCODES:
                    to_patch.append(node)

            # patch them
            for node in to_patch:
                self._instrument(node, bb)

    def _instrument(self, node: InstructionNode, parent: BasicBlock) -> None:
        inst = node.instruction
        opcode_options = self._OPCODES[inst.name]
        opcode = random.choice(opcode_options)
        new_inst = copy_inst_with_modification(inst, name=".byte " + opcode)
        parent.insert_before(node, new_inst)
        parent.delete(node)


# ==================================================================================================
# Public Interface
# ==================================================================================================
class X86Generator(CodeGenerator):
    """ x86-specific implementation of the test case program generator """

    _faults: _FaultFilter

    def __init__(self, seed: int, instruction_set: InstructionSet, target_desc: TargetDesc,
                 asm_parser: AsmParser, elf_parser: ELFParser) -> None:
        super().__init__(seed, instruction_set, target_desc, asm_parser, elf_parser)
        assert isinstance(self._target_desc, X86TargetDesc)

        self._faults = _FaultFilter()
        usable_registers: Dict[RegSize, List[RegName]] = self._get_usable_registers()

        # configure instrumentation passes
        self._passes = [
            _X86PatchUndefinedFlagsPass(self._instruction_set, self),
            _X86SandboxPass(self._target_desc, self._faults, usable_registers),
            _X86PatchUndefinedResultPass(),
        ]
        if self._faults.non_canonical_access:
            self._passes.append(_X86NonCanonicalAddressPass(self._target_desc))
        if self._faults.u2k_access:
            self._passes.append(_X86U2KAccessPass())  # must be after X86SandboxPass
        self._passes.append(_X86PatchOpcodesPass())
        self._printer = _X86Printer(self._target_desc)
