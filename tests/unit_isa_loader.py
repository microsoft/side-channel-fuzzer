"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

import io
import os
import tempfile
from contextlib import redirect_stdout
from typing import List, Optional

from rvzr import factory
from rvzr.config import CONF, ConfigException
from rvzr.isa_spec import InstructionSet, InstructionPoolConstraints, BlockedInstructionVariant
from rvzr.instruction_spec import OT, InstructionSpec

basic = """
[
{"name": "test", "category": "CATEGORY", "is_control_flow": true,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16},
    {"type_": "REG", "values": ["ax"], "src": true, "dest": false, "width": 16}
  ],
  "implicit_operands": [
    {"type_": "FLAGS", "values": ["w", "r", "undef", "w", "w", "", "", "", "w"],
     "src": false, "dest": false, "width": 0}
  ]
},
{"name": "test2", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
}
]
"""

duplicate = """
[
{"name": "test", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
},
{"name": "test", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
}
]
"""

# three variants of the same instruction (widths 16/32/64) plus an FP instruction,
# used by the constraint-filtering tests
variants = """
[
{"name": "vdiv", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "REG", "values": ["ax"], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
},
{"name": "vdiv", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "REG", "values": ["eax"], "src": true, "dest": true, "width": 32}
  ],
  "implicit_operands": []
},
{"name": "vdiv", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "REG", "values": ["rax", "rbx"], "src": true, "dest": true, "width": 64}
  ],
  "implicit_operands": []
},
{"name": "vsqrt", "category": "CATEGORY_FP", "is_control_flow": false,
  "operands": [
    {"type_": "REG", "values": ["xmm0"], "src": true, "dest": true, "width": 128,
     "xtype": "f64"}
  ],
  "implicit_operands": []
},
{"name": "vmov", "category": "CATEGORY", "is_control_flow": false,
  "operands": [
    {"type_": "REG", "values": ["rax"], "src": true, "dest": true, "width": 64}
  ],
  "implicit_operands": []
}
]
"""


def _load_isa(spec: str, categories: Optional[List[str]],
              constraints: InstructionPoolConstraints) -> InstructionSet:
    """ Load an InstructionSet from a JSON string """
    spec_file = tempfile.NamedTemporaryFile("w", delete=False)
    with open(spec_file.name, "w") as f:
        f.write(spec)
    try:
        return InstructionSet(spec_file.name, categories, constraints)
    finally:
        spec_file.close()
        os.unlink(spec_file.name)


class InstructionSetParserTest(unittest.TestCase):

    def test_parsing(self) -> None:
        spec_file = tempfile.NamedTemporaryFile("w", delete=False)
        with open(spec_file.name, "w") as f:
            f.write(basic)

        instruction_set = InstructionSet(spec_file.name, None, InstructionPoolConstraints.none())
        spec_file.close()
        os.unlink(spec_file.name)

        spec: InstructionSpec = instruction_set.instructions[0]
        self.assertEqual(spec.name, "test")
        self.assertEqual(spec.category, "CATEGORY")
        self.assertEqual(spec.has_mem_operand, True)
        self.assertEqual(spec.has_write, True)
        self.assertEqual(spec.is_control_flow, True)

        self.assertEqual(len(spec.operands), 2)
        op1 = spec.operands[0]
        self.assertEqual(op1.type, OT.MEM)
        self.assertEqual(op1.width, 16)
        self.assertEqual(op1.src, True)
        self.assertEqual(op1.dest, True)

        op2 = spec.operands[1]
        self.assertEqual(op2.type, OT.REG)
        self.assertEqual(op2.values, ("ax",))
        self.assertEqual(op2.src, True)
        self.assertEqual(op2.dest, False)

        self.assertEqual(len(spec.implicit_operands), 1)
        flags = spec.implicit_operands[0]
        self.assertEqual(flags.type, OT.FLAGS)
        self.assertEqual(flags.values, ('w', 'r', 'undef', 'w', 'w', '', '', '', 'w'))

    def test_dedup_identical(self) -> None:
        spec_file = tempfile.NamedTemporaryFile("w", delete=False)
        with open(spec_file.name, "w") as f:
            f.write(duplicate)

        instruction_set = InstructionSet(spec_file.name, None, InstructionPoolConstraints.none())
        spec_file.close()
        os.unlink(spec_file.name)

        self.assertEqual(len(instruction_set.instructions), 1, "No deduplication")


class InstructionPoolConstraintsTest(unittest.TestCase):

    def test_merge_supported_categories(self) -> None:
        unrestricted = InstructionPoolConstraints.none()
        allows_ab = InstructionPoolConstraints(supported_categories={"A", "B"})
        allows_bc = InstructionPoolConstraints(supported_categories={"B", "C"})
        allows_nothing = InstructionPoolConstraints(supported_categories=set())

        # None means unrestricted and is ignored by the intersection
        self.assertIsNone(
            InstructionPoolConstraints.merge([unrestricted, unrestricted]).supported_categories)
        self.assertEqual(
            InstructionPoolConstraints.merge([unrestricted, allows_ab]).supported_categories,
            {"A", "B"})

        # non-None sets intersect; an empty set means nothing is supported
        self.assertEqual(
            InstructionPoolConstraints.merge([allows_ab, allows_bc]).supported_categories, {"B"})
        self.assertEqual(
            InstructionPoolConstraints.merge([allows_ab, allows_nothing]).supported_categories,
            set())

    def test_merge_unions_blocked_sets(self) -> None:
        first = InstructionPoolConstraints(
            blocked_categories={"CAT1"},
            blocked_instructions={"inst1"},
            blocked_instruction_variants={BlockedInstructionVariant("var1", 64)},
            blocked_registers={"reg1"},
            blocked_xtypes={"f32"},
        )
        second = InstructionPoolConstraints(
            blocked_categories={"CAT2"},
            blocked_instructions={"inst2"},
            blocked_instruction_variants={BlockedInstructionVariant("var2", 32)},
            blocked_registers={"reg2"},
            blocked_xtypes={"f64"},
        )
        merged = InstructionPoolConstraints.merge([first, second])
        self.assertEqual(merged.blocked_categories, {"CAT1", "CAT2"})
        self.assertEqual(merged.blocked_instructions, {"inst1", "inst2"})
        self.assertEqual(
            merged.blocked_instruction_variants,
            {BlockedInstructionVariant("var1", 64),
             BlockedInstructionVariant("var2", 32)})
        self.assertEqual(merged.blocked_registers, {"reg1", "reg2"})
        self.assertEqual(merged.blocked_xtypes, {"f32", "f64"})


class InstructionSetFilteringTest(unittest.TestCase):
    """ Tests of constraint application in InstructionSet """

    def setUp(self) -> None:
        self.prev_allowlist = CONF.instruction_allowlist
        self.prev_blocklist = CONF.instruction_blocklist
        self.prev_avg_mem_accesses = CONF.avg_mem_accesses
        self.prev_min_successors = CONF.min_successors_per_bb
        self.prev_max_successors = CONF.max_successors_per_bb
        CONF.instruction_allowlist = []
        CONF.instruction_blocklist = []
        CONF.avg_mem_accesses = 0  # the test fixture has no memory-access instructions

    def tearDown(self) -> None:
        CONF.instruction_allowlist = self.prev_allowlist
        CONF.instruction_blocklist = self.prev_blocklist
        CONF.avg_mem_accesses = self.prev_avg_mem_accesses
        CONF.min_successors_per_bb = self.prev_min_successors
        CONF.max_successors_per_bb = self.prev_max_successors

    def test_unsupported_categories_rejected(self) -> None:
        # an empty supported set rejects every requested category, and the error lists all
        # offending categories at once
        constraints = InstructionPoolConstraints(supported_categories=set())
        with self.assertRaises(ConfigException) as cm:
            _load_isa(variants, ["CATEGORY", "CATEGORY_FP"], constraints)
        self.assertIn("CATEGORY", str(cm.exception))
        self.assertIn("CATEGORY_FP", str(cm.exception))

    def test_unrestricted_categories_accepted(self) -> None:
        # supported_categories=None disables the validation entirely
        isa = _load_isa(variants, ["CATEGORY", "CATEGORY_FP"], InstructionPoolConstraints.none())
        self.assertTrue(isa.instructions)

    def test_blocked_category_beats_supported(self) -> None:
        constraints = InstructionPoolConstraints(
            supported_categories={"CATEGORY", "CATEGORY_FP"},
            blocked_categories={"CATEGORY_FP"},
        )
        with io.StringIO() as buf, redirect_stdout(buf):  # silence the empty-category warning
            isa = _load_isa(variants, ["CATEGORY", "CATEGORY_FP"], constraints)
        categories = {i.category for i in isa.instructions}
        self.assertEqual(categories, {"CATEGORY"})

    def test_blocked_instruction_variants(self) -> None:
        constraints = InstructionPoolConstraints(
            blocked_instruction_variants={BlockedInstructionVariant("vdiv", 64)})
        isa = _load_isa(variants, None, constraints)
        widths = {i.operands[0].width for i in isa.instructions if i.name == "vdiv"}
        self.assertEqual(widths, {16, 32})

    def test_blocked_xtypes(self) -> None:
        constraints = InstructionPoolConstraints(blocked_xtypes={"f64"})
        isa = _load_isa(variants, None, constraints)
        names = {i.name for i in isa.instructions}
        self.assertNotIn("vsqrt", names)
        self.assertIn("vdiv", names)

    def test_blocked_registers_removed_from_operands(self) -> None:
        constraints = InstructionPoolConstraints(blocked_registers={"rbx", "eax"})
        isa = _load_isa(variants, None, constraints)
        by_width = {i.operands[0].width: i for i in isa.instructions if i.name == "vdiv"}
        self.assertEqual(by_width[64].operands[0].values, ("rax",))
        self.assertNotIn(32, by_width)  # all of its operand values are blocked

    def test_user_blocklist_does_not_drop_component_constraints(self) -> None:
        # setting instruction_blocklist must not disable the built-in constraints
        CONF.instruction_blocklist = ["vsqrt"]
        constraints = InstructionPoolConstraints(blocked_instructions={"vdiv"})
        isa = _load_isa(variants, None, constraints)
        names = {i.name for i in isa.instructions}
        self.assertEqual(names, {"vmov"})

    def test_user_allowlist_overrides_component_constraints(self) -> None:
        CONF.instruction_allowlist = ["vdiv"]
        constraints = InstructionPoolConstraints(blocked_instructions={"vdiv"})
        with io.StringIO() as buf, redirect_stdout(buf):  # silence the empty-category warning
            isa = _load_isa(variants, ["NONEXISTENT"], constraints)
        self.assertIn("vdiv", {i.name for i in isa.instructions})

    def test_empty_category_warning(self) -> None:
        with io.StringIO() as buf, redirect_stdout(buf):
            _load_isa(variants, ["CATEGORY", "MISSING"], InstructionPoolConstraints.none())
            output = buf.getvalue()
        self.assertIn("WARNING", output)
        self.assertIn("MISSING", output)
        self.assertNotIn("'CATEGORY'", output)
