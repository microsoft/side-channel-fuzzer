"""
File: Loading, filtering, and categorization of ISA specifications.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import AbstractSet, Dict, List, NamedTuple, Optional, Any, get_args

from .instruction_spec import OT, XOT, OperandSpec, InstructionSpec
from .config import CONF, ConfigException
from .logs import ISALogger, warning

_OT_STR_TO_ENUM = {
    "REG": OT.REG,
    "MEM": OT.MEM,
    "IMM": OT.IMM,
    "LABEL": OT.LABEL,
    "AGEN": OT.AGEN,
    "FLAGS": OT.FLAGS,
    "COND": OT.COND,
}


# ==================================================================================================
# Constraints on the instruction pool usable by the code generators
# ==================================================================================================
class BlockedInstructionVariant(NamedTuple):
    """ Matches specs with the given name whose first explicit operand has the given width. """

    name: str
    width: int


@dataclass(frozen=True)
class InstructionPoolConstraints:
    """
    Constraints on ISA elements eligible for use in generated programs.

    An instance may represent component capabilities, test-case contract requirements, or
    generation policy. Instances from independent sources can be merged into their combined
    constraints.

    Invariants (not enforced by the type itself):

    - Precedence: a category may legitimately appear both in `supported_categories` and in
            `blocked_categories`. Blocked wins.
    - Merge directions: `supported_categories` is an allowlist, so merging intersects it
            (every source must support a category for it to be usable); the `blocked_*` fields are
            blocklists, so merging unions them (a single source suffices to block an entry).
    - Default posture for a category newly added to the spec file: denied by default by models
      (absent from their allowlists) but allowed by default through generator/executor
      (absent from their blocklists).
    """

    supported_categories: Optional[AbstractSet[str]] = None
    """ Allowlist of supported instruction categories; None means unrestricted (no category
    constraint; e.g., the dummy model). Note that None and an empty set differ: an empty set
    means that no category is supported at all. """

    blocked_categories: AbstractSet[str] = frozenset()
    """ Category exclusions; used by components that cannot reasonably maintain a full
    allowlist of supported categories (generator, executor). """

    blocked_instructions: AbstractSet[str] = frozenset()
    """ Names of blocked instructions (all variants). """

    blocked_instruction_variants: AbstractSet[BlockedInstructionVariant] = frozenset()
    """ Width-qualified instruction variants to block (see BlockedInstructionVariant). """

    blocked_registers: AbstractSet[str] = frozenset()
    """ Names of registers that must not appear in generated programs. """

    blocked_xtypes: AbstractSet[str] = frozenset()
    """ Extended operand types (XOT) that must not appear in generated programs. """

    def __post_init__(self) -> None:
        """ Freeze all sets to ensure immutability. """
        for name in (
                "supported_categories",
                "blocked_categories",
                "blocked_instructions",
                "blocked_instruction_variants",
                "blocked_registers",
                "blocked_xtypes",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, frozenset(value))

    @staticmethod
    def none() -> InstructionPoolConstraints:
        """ Return a constraints object that does not constrain anything. """
        return InstructionPoolConstraints()

    @staticmethod
    def merge(constraints: List[InstructionPoolConstraints]) -> InstructionPoolConstraints:
        """
        Merge a list of constraints into a single object: intersection of the
        supported-category sets (ignoring None entries), union of everything else.
        """
        supported: Optional[AbstractSet[str]] = None
        for c in constraints:
            if c.supported_categories is None:
                continue
            if supported is None:
                supported = set(c.supported_categories)
            else:
                supported &= c.supported_categories
        return InstructionPoolConstraints(
            supported_categories=supported,
            blocked_categories=set().union(*(c.blocked_categories for c in constraints)),
            blocked_instructions=set().union(*(c.blocked_instructions for c in constraints)),
            blocked_instruction_variants=set().union(
                *(c.blocked_instruction_variants for c in constraints)),
            blocked_registers=set().union(*(c.blocked_registers for c in constraints)),
            blocked_xtypes=set().union(*(c.blocked_xtypes for c in constraints)),
        )


@dataclass(frozen=True)
class PerArchConstraints:
    """
    A collection class that holds the constraints for all components for a given architecture.
    Meant to be used a public interface with which per-arch ISA constraints modules communicate
    the constraints of various components.
    """
    model: Dict[str, InstructionPoolConstraints]
    executor: InstructionPoolConstraints
    generator: InstructionPoolConstraints
    contract: InstructionPoolConstraints
    known_leak_groups: Dict[str, InstructionPoolConstraints]
    fault_suppression: Dict[str, InstructionPoolConstraints]


# ==================================================================================================
# Representation of the instruction set under test and its categorization
# ==================================================================================================
class InstructionSet:
    """
    Class representing an instruction set of a given architecture.
    Contains a list of InstructionSpec objects as well as type-based lists of instructions.
    """

    instructions: List[InstructionSpec]
    instructions_unfiltered: List[InstructionSpec]
    constraints: InstructionPoolConstraints
    logger: ISALogger

    has_unconditional_branch: bool = False
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False
    has_reads: bool = False
    has_writes: bool = False

    control_flow_specs: List[InstructionSpec]
    non_control_flow_specs: List[InstructionSpec]
    non_memory_access_specs: List[InstructionSpec]
    load_instruction: List[InstructionSpec]
    store_instructions: List[InstructionSpec]
    cond_branches: List[InstructionSpec]

    def __init__(self, filename: str, include_categories: Optional[List[str]],
                 constraints: InstructionPoolConstraints):
        self.constraints = constraints
        _validate_categories(include_categories, constraints)
        self.instructions = []
        _read_json_spec(self, filename)
        self.instructions_unfiltered = deepcopy(self.instructions)
        _reduce(self, include_categories)
        _warn_about_empty_categories(self, include_categories)
        _set_isa_properties(self)
        _dedup(self)
        _set_categories(self)

    def get_return_spec(self) -> InstructionSpec:
        """ Return the instruction spec for the RET instruction on the given architecture """
        if CONF.instruction_set == "x86-64":
            return InstructionSpec("ret", "BASE-RET", is_control_flow=True)
        if CONF.instruction_set == "arm64":
            return InstructionSpec("ret", "general-ret", is_control_flow=True)
        raise NotImplementedError(f"Unsupported instruction set: {CONF.instruction_set}")

    def get_unconditional_jump_spec(self) -> InstructionSpec:
        """
        Return the instruction spec for the unconditional jump instruction
        on the given architecture
        """
        if CONF.instruction_set == "x86-64":
            spec = InstructionSpec("jmp", "BASE-UNCOND_BR", is_control_flow=True)
            spec.operands.append(OperandSpec([], OT.LABEL, src=True, dest=False, width=64))
            return spec
        if CONF.instruction_set == "arm64":
            spec = InstructionSpec("b", "general-uncond_branch", is_control_flow=True)
            spec.operands.append(OperandSpec([], OT.LABEL, src=True, dest=False, width=64))
            return spec
        raise NotImplementedError(f"Unsupported instruction set: {CONF.instruction_set}")


# ==================================================================================================
# Local service functions that post-process the instruction set
# ==================================================================================================
def _read_json_spec(isa: InstructionSet, filename: str) -> None:
    with open(filename, "r") as f:
        root = json.load(f)
    for instruction_node in root:
        instruction = InstructionSpec(instruction_node["name"], instruction_node["category"],
                                      instruction_node["is_control_flow"])

        for op_node in instruction_node["operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.operands.append(op)
            if op.has_magic_value:
                instruction.has_magic_value = True

        for op_node in instruction_node["implicit_operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.implicit_operands.append(op)

        isa.instructions.append(instruction)


def _parse_json_operand(op: Dict[str, Any], parent: InstructionSpec) -> OperandSpec:
    op_type = _OT_STR_TO_ENUM[op["type_"]]
    op_values = op.get("values", [])
    if op_type == OT.REG:
        op_values = sorted(op_values)

    spec = OperandSpec(
        values=op_values,
        type_=op_type,
        src=op["src"],
        dest=op["dest"],
        width=op["width"],
        is_signed=op.get("is_signed", True),
        xtype=op.get("xtype", None),
    )

    if op_type == OT.MEM:
        parent.has_mem_operand = True
        if spec.dest:
            parent.has_write = True

    return spec


def _validate_categories(include_categories: Optional[List[str]],
                         constraints: InstructionPoolConstraints) -> None:
    """ Check that all requested categories are supported by the selected model backend """
    if not include_categories or constraints.supported_categories is None:
        return
    unsupported = sorted(set(include_categories) - constraints.supported_categories)
    if unsupported:
        supported = sorted(constraints.supported_categories)
        raise ConfigException(
            f"instruction_categories: {unsupported} not supported by model backend "
            f"'{CONF.model_backend}' ({CONF.instruction_set}). Supported: {supported}")


def _warn_about_empty_categories(isa: InstructionSet,
                                 include_categories: Optional[List[str]]) -> None:
    """ Warn when a requested category contributes no instructions """
    if not include_categories or not CONF.is_generation_enabled():
        return
    present_categories = {inst.category for inst in isa.instructions}
    for category in include_categories:
        if category not in present_categories:
            warning(
                "isa_spec", f"Requested instruction category '{category}' contributes no "
                "instructions: it is either absent from the spec file or all of its "
                "instructions are filtered out")


def _reduce(isa: InstructionSet, include_categories: Optional[List[str]]) -> None:
    """ Remove unsupported instructions and operand values """

    def is_supported(spec: InstructionSpec) -> bool:
        # pylint: disable=too-many-return-statements, too-many-branches
        # justification: this is a filtering function

        if not CONF.is_generation_enabled():
            # if we use an existing test case, then instruction filtering is irrelevant
            return True

        # user allowlist has priority over categories, blocklists, and component constraints
        if spec.name in CONF.instruction_allowlist:
            return True

        if include_categories and spec.category not in include_categories:
            logger.dbg_dump_filtering_reason(spec, "category not in include_categories")
            return False

        if spec.category in constraints.blocked_categories:
            logger.dbg_dump_filtering_reason(spec, "category is blocked")
            return False

        if spec.name in constraints.blocked_instructions:
            logger.dbg_dump_filtering_reason(spec, "instruction is blocked")
            return False

        if spec.operands and BlockedInstructionVariant(spec.name, spec.operands[0].width) \
                in constraints.blocked_instruction_variants:
            logger.dbg_dump_filtering_reason(spec, "instruction variant is blocked")
            return False

        if spec.name in CONF.instruction_blocklist:
            logger.dbg_dump_filtering_reason(spec, "in instruction_blocklist")
            return False

        for operand in spec.operands:
            if operand.type == OT.MEM and operand.values \
                    and operand.values[0] in constraints.blocked_registers:
                logger.dbg_dump_filtering_reason(spec, "mem operand uses blocked register")
                return False

        for operand in spec.operands:
            if operand.type != OT.REG or operand.xtype is None:
                continue
            assert operand.xtype in get_args(XOT), f"Unknown xtype value: {operand.xtype}"
            if operand.xtype in constraints.blocked_xtypes:
                logger.dbg_dump_filtering_reason(spec, "operand xtype is blocked")
                return False

        for implicit_operand in spec.implicit_operands:
            assert implicit_operand.type != OT.LABEL  # I know no such instructions
            if implicit_operand.type == OT.MEM \
                    and implicit_operand.values[0] in constraints.blocked_registers:
                logger.dbg_dump_filtering_reason(spec, "implicit mem operand uses blocked register")
                return False

            if implicit_operand.type == OT.REG \
                    and implicit_operand.values[0] in constraints.blocked_registers:
                assert len(implicit_operand.values) == 1
                logger.dbg_dump_filtering_reason(spec, "implicit reg operand uses blocked register")
                return False
        return True

    logger = ISALogger()
    constraints = isa.constraints

    # Remove unsupported instructions
    skip_list = []
    for s in isa.instructions:
        if not is_supported(s):
            skip_list.append(s)
    for s in skip_list:
        isa.instructions.remove(s)

    # Remove unsupported operand values from operand specs;
    # If all operand values are unsupported, remove the instruction
    skip_list = []
    for s in isa.instructions:
        operands = list(s.operands)  # make a copy
        for op_id, op in enumerate(operands):
            # filtering applies only to registers
            if op.type != OT.REG:
                continue

            # identify supported registers
            op_values = sorted(set(op.values) - constraints.blocked_registers)

            # FIXME: temporary disabled generation of higher reg. bytes for x86
            for i, reg in enumerate(op_values):
                if reg[-1] == 'h':
                    op_values[i] = reg.replace('h', 'l')

            # no supported values -> skip this instruction
            if not op_values:
                skip_list.append(s)
                break

            # otherwise, update the operand
            s.operands[op_id] = OperandSpec(op_values, op.type, op.src, op.dest, op.width,
                                            op.is_signed, op.has_magic_value, op.xtype)
    for s in skip_list:
        isa.instructions.remove(s)


def _set_isa_properties(isa: InstructionSet) -> None:
    """
    Set properties of the instruction set that are used in the generation process.
    """
    for inst in isa.instructions:
        if inst.is_control_flow:
            if inst.category in ["BASE-UNCOND_BR", "general-uncond_branch"]:
                isa.has_unconditional_branch = True
            else:
                isa.has_conditional_branch = True
        elif inst.has_mem_operand:
            if inst.has_write:
                isa.has_writes = True
            else:
                isa.has_reads = True


def _dedup(isa: InstructionSet) -> None:
    """
    Instruction set spec may contain several copies of the same instruction.
    Remove them.
    """
    skip_list = set()
    n_instructions = len(isa.instructions)
    for i in range(n_instructions):
        for j in range(i + 1, n_instructions):
            inst1 = isa.instructions[i]
            inst2 = isa.instructions[j]
            if inst1.name == inst2.name and len(inst1.operands) == len(inst2.operands):
                match = True
                for k, op1 in enumerate(inst1.operands):
                    op2 = inst2.operands[k]

                    if op1.type != op2.type:
                        match = False
                        continue

                    if op1.values != op2.values:
                        match = False
                        continue

                    if op1.width != op2.width and op1.type != OT.IMM:
                        match = False
                        continue

                    # assert op1.src == op2.src
                    # assert op1.dest == op2.dest

                if match:
                    skip_list.add(inst1)

    for s in skip_list:
        isa.instructions.remove(s)


def _set_categories(isa: InstructionSet) -> None:
    isa.control_flow_specs = [i for i in isa.instructions if i.is_control_flow]
    # adjust the config to the available instruction set
    if len(isa.control_flow_specs) == 0:
        CONF.min_successors_per_bb = 1
        CONF.max_successors_per_bb = 1

    isa.non_control_flow_specs = [i for i in isa.instructions if not i.is_control_flow]
    assert isa.non_control_flow_specs, \
        "The instruction set is insufficient to generate a test case"

    isa.non_memory_access_specs = \
        [i for i in isa.non_control_flow_specs if not i.has_mem_operand]
    if CONF.avg_mem_accesses != 0:
        memory_access_instructions = \
            [i for i in isa.non_control_flow_specs if i.has_mem_operand]
        isa.load_instruction = [i for i in memory_access_instructions if not i.has_write]
        isa.store_instructions = [i for i in memory_access_instructions if i.has_write]
        assert isa.load_instruction or isa.store_instructions, \
               "The instruction set does not have memory accesses while `avg_mem_accesses > 0`"
    else:
        isa.load_instruction = []
        isa.store_instructions = []

    uncond_name = isa.get_unconditional_jump_spec().name.lower()
    isa.cond_branches = \
        [i for i in isa.control_flow_specs if i.name.lower() != uncond_name]
