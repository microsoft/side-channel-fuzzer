"""
File: Collection of unit tests for rvzr/traces.py

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import unittest
import unittest.mock
import xxhash
import numpy as np

from rvzr.traces import CTraceEntry, CTrace, HTrace, RawHTraceSample, HardwareEqClass, \
    TraceBundle, ContractEqClass, Violation
from rvzr.tc_components.test_case_data import InputData, InputID
from rvzr.tc_components.test_case_code import TestCaseProgram


class TestCTrace(unittest.TestCase):
    """ Unit tests for CTrace and related classes """

    def test_empty_constructor(self) -> None:
        # Test `empty_trace` interface
        trace = CTrace.empty_trace()
        self.assertIsInstance(trace, CTrace)
        self.assertTrue(trace.is_empty())
        self.assertEqual(trace, CTrace([]))

    def test_str(self) -> None:
        # Test `__str__` interface
        # 1. Normal case
        values = [0x0, 0x100]
        entries = [CTraceEntry("val", i) for i in values]
        trace = CTrace(entries)
        hash_ = xxhash.xxh64(str(values).encode(), seed=0).intdigest()
        self.assertEqual(str(trace), str(hash_))

        # 2. Special case - L1D map
        trace.set_printed_as_l1d(True)
        l1d_map = '^...^...........................................................'
        self.assertEqual(str(trace), l1d_map)

    def test_full_str(self) -> None:
        # Test `full_str` interface
        entries = [
            CTraceEntry("mem", 0),
            CTraceEntry("pc", 0),
            CTraceEntry("ind", 0),
            CTraceEntry("val", 0),
            CTraceEntry("reg", 0),
        ]
        trace = CTrace(entries)
        m_col, pc_col, val_col, reset_col = "m|", "p|", "v|", "r|"

        # 1. Normal case
        expected_x86 = "[mem: m|0x0r|, pc: p|0x0r|, indcall: p|0x0r|, val: v|0x0r|, rsi: 0x0r|]"
        expected_arm = "[mem: m|0x0r|, pc: p|0x0r|, indcall: p|0x0r|, val: v|0x0r|, x4: 0x0r|]"
        self.assertIn(
            trace.full_str(m_col, pc_col, val_col, reset_col), [expected_x86, expected_arm])

        # 2. Default colors
        expected_x86 = "[mem: 0x0, pc: 0x0, indcall: 0x0, val: 0x0, rsi: 0x0]"
        expected_arm = "[mem: 0x0, pc: 0x0, indcall: 0x0, val: 0x0, x4: 0x0]"
        self.assertIn(trace.full_str(), [expected_x86, expected_arm])

        # 3. Invalid color combination
        with self.assertRaises(AssertionError):
            trace.full_str("m|", "p|", "v|")

    def test_default_methods(self) -> None:
        # Test default methods: `__eq__`, `__lt__`, `__gt__`, `__len__`, `__hash__`
        entries = [CTraceEntry("val", i) for i in range(5)]
        trace1 = CTrace(entries)
        trace2 = CTrace(entries)
        trace3 = CTrace([CTraceEntry("val", 10)])

        # __eq__
        self.assertEqual(trace1, trace2)
        self.assertNotEqual(trace1, trace3)
        with self.assertRaises(NotImplementedError):
            _ = trace1 == "not a trace"

        # __lt__ and __gt__
        self.assertFalse(trace1 < trace2)
        self.assertFalse(trace1 > trace2)

        # __len__
        self.assertEqual(len(trace1), 5)

        # __hash__
        self.assertEqual(hash(trace1), hash(trace2))
        self.assertNotEqual(hash(trace1), hash(trace3))

    def test_accessors(self) -> None:
        # Test accessors: `get_untyped`, `get_typed`, `is_empty`
        entries = [CTraceEntry("val", i) for i in range(5)]
        trace = CTrace(entries)

        # get_untyped
        untyped = trace.get_untyped()
        self.assertEqual(untyped, [0, 1, 2, 3, 4])

        # get_typed
        typed = trace.get_typed()
        self.assertEqual(typed, entries)

        # is_empty
        self.assertFalse(trace.is_empty())
        empty_trace = CTrace.empty_trace()
        self.assertTrue(empty_trace.is_empty())


class TestHTrace(unittest.TestCase):
    """ Unit tests for HTrace and related classes """

    def test_empty_constructor(self) -> None:
        # Test `empty_trace` interface
        trace = HTrace.empty_trace()
        self.assertIsInstance(trace, HTrace)
        self.assertTrue(trace.is_empty())
        self.assertEqual(trace, HTrace(np.ndarray(0, dtype=RawHTraceSample)))

    def test_invalid_constructor(self) -> None:
        # Test `invalid_trace` interface
        trace = HTrace.invalid_trace()
        self.assertIsInstance(trace, HTrace)
        self.assertTrue(trace.is_corrupted_or_ignored())

    def test_printers(self) -> None:
        # Test `__str__`, `full_str` interfaces
        # __str__
        entries = np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample)
        trace = HTrace(entries)
        hash_ = xxhash.xxh64(str(entries['trace']).encode(), seed=0).intdigest()
        self.assertEqual(str(trace), str(hash_))

        # full_str: empty trace
        empty_trace = HTrace.empty_trace()
        self.assertEqual(empty_trace.full_str(), "")

        # full_str: cache trace
        trace = HTrace(np.array([(0b10001, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        expected = "...........................................................^...^ [1]\n"
        self.assertEqual(trace.full_str(), expected)

        # full_str: TSC trace
        trace = HTrace(np.array([(256, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "tsc")
        expected = "00000256 [1]\n"
        self.assertEqual(trace.full_str(), expected)

        # full_str: architectural trace
        trace = HTrace(np.array([(0x1, 0x2, 0x3, 0x4, 0x5, 0x6)], dtype=RawHTraceSample), "reg")
        expected_x86 = "[rax: 0x1, rbx: 0x2, rcx: 0x3, rdx: 0x4, rsi: 0x5, rdi: 0x6]"
        expected_arm = "[x0: 0x1, x1: 0x2, x2: 0x3, x3: 0x4, x4: 0x5, x5: 0x6]"
        self.assertIn(trace.full_str(), [expected_x86, expected_arm])

    def test_pair_printers(self) -> None:
        # Test `full_pair_str` interface
        # cache traces
        trace1 = HTrace(np.array([(0b10001, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        trace2 = HTrace(np.array([(0b10010, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        expected = \
            "...........................................................^...^" \
            " | 1      | 0     |\n" \
            "...........................................................^..^." \
            " | 0      | 1     |\n"
        self.assertEqual(trace1.full_pair_str(trace2), expected)

        # TSC traces
        trace1 = HTrace(np.array([(256, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "tsc")
        trace2 = HTrace(np.array([(512, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "tsc")
        expected = "00000256 | 1      | 0      |\n"\
                   "00000512 | 0      | 1      |\n"
        self.assertEqual(trace1.full_pair_str(trace2), expected)

        # architectural traces
        trace1 = HTrace(np.array([(0x1, 0x2, 0x3, 0x4, 0x5, 0x6)], dtype=RawHTraceSample), "reg")
        trace2 = HTrace(np.array([(0x7, 0x8, 0x9, 0xa, 0xb, 0xc)], dtype=RawHTraceSample), "reg")
        # FIXME: the below assert is nonsensical, and it exists only to satisfy the coverage tool
        with self.assertRaises(NotImplementedError):
            trace1.full_pair_str(trace2)

    def test_default_methods(self) -> None:
        # Test default methods: `__eq__`, `__len__`, `__hash__`
        trace1 = HTrace(np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        trace2 = HTrace(np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        trace3 = HTrace(np.array([(0x200, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")

        # __eq__
        self.assertEqual(trace1, trace2)
        self.assertNotEqual(trace1, trace3)

        # __len__
        self.assertEqual(len(trace1), 1)
        self.assertEqual(len(trace3), 1)
        self.assertEqual(len(HTrace.empty_trace()), 0)

        # __hash__
        self.assertEqual(hash(trace1), hash(trace2))
        self.assertNotEqual(hash(trace1), hash(trace3))

    def test_merge(self) -> None:
        # Test `merge` method
        trace1 = HTrace(np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        trace2 = HTrace(np.array([(0x200, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache")
        merged_trace = trace1.merge(trace2)

        self.assertEqual(len(merged_trace), 2)
        self.assertEqual(merged_trace.get_raw_traces().tolist(), [0x100, 0x200])

    def test_accessors(self) -> None:
        # Test accessors: `get_raw_readings`, `get_raw_traces`, `sample_size`, `get_max_pfc`
        entries = np.array([(0x100, 1, 2, 3, 4, 5)], dtype=RawHTraceSample)
        trace = HTrace(entries)

        # get_raw_readings
        raw_readings = trace.get_raw_readings()
        self.assertTrue(np.array_equal(raw_readings, entries))

        # get_raw_traces
        raw_traces = trace.get_raw_traces()
        self.assertTrue(np.array_equal(raw_traces, entries['trace']))

        # sample_size
        self.assertEqual(trace.sample_size(), 1)
        self.assertEqual(HTrace.empty_trace().sample_size(), 0)

        # get_max_pfc
        self.assertEqual(trace.get_max_pfc(), (1, 2, 3, 4, 5))


def _get_bundle_set() -> list[TraceBundle]:
    trace_bundle1 = TraceBundle(
        input_id=InputID(1),
        input_=InputData(),
        ctrace=CTrace([CTraceEntry("val", 0)]),
        htrace=HTrace(np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache"))
    trace_bundle2 = TraceBundle(
        input_id=InputID(2),
        input_=InputData(),
        ctrace=CTrace([CTraceEntry("val", 0)]),
        htrace=HTrace(np.array([(0x100, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache"))
    trace_bundle3 = TraceBundle(
        input_id=InputID(3),
        input_=InputData(),
        ctrace=CTrace([CTraceEntry("val", 1)]),
        htrace=HTrace(np.array([(0x200, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache"))
    trace_bundle4 = TraceBundle(
        input_id=InputID(3),
        input_=InputData(),
        ctrace=CTrace([CTraceEntry("val", 1)]),
        htrace=HTrace(np.array([(0x300, 0, 0, 0, 0, 0)], dtype=RawHTraceSample), "cache"))
    return [trace_bundle1, trace_bundle2, trace_bundle3, trace_bundle4]


class TestHardwareEqClass(unittest.TestCase):
    """ Unit tests for HardwareEqClass"""

    def test_hw_class_builder(self) -> None:
        # Test `build_hw_classes`
        # Create hardware equivalence classes
        trace_bundles = _get_bundle_set()
        hw_classes = HardwareEqClass.build_hw_classes(trace_bundles)

        # Test grouping
        self.assertEqual(len(hw_classes), 3)
        self.assertEqual(hw_classes[0].htrace, trace_bundles[0].htrace)
        self.assertEqual(hw_classes[1].htrace, trace_bundles[2].htrace)
        self.assertEqual(hw_classes[0].measurements, [trace_bundles[0], trace_bundles[1]])
        self.assertEqual(hw_classes[1].measurements, [trace_bundles[2]])

    def test_default_methods(self) -> None:
        # Test default methods
        trace_bundles = _get_bundle_set()
        hw_classes = HardwareEqClass.build_hw_classes(trace_bundles)

        # __len__
        self.assertEqual(len(hw_classes[0]), 2)

        # __iter__
        for i, bundle in enumerate(hw_classes[0]):
            self.assertEqual(bundle, trace_bundles[i])

        # __getitem__
        self.assertEqual(hw_classes[0][0], trace_bundles[0])

        # __eq__
        self.assertNotEqual(hw_classes[0], hw_classes[1])
        with self.assertRaises(NotImplementedError):
            _ = hw_classes[0] == "not a HardwareEqClass"


class TestContractEqClass(unittest.TestCase):
    """ Unit tests for ContractEqClass """

    def test_contract_class_builder(self) -> None:
        # Test `build_contract_classes`
        trace_bundles = _get_bundle_set()
        contract_classes = ContractEqClass.build_contract_classes(trace_bundles)

        # Test grouping
        self.assertEqual(len(contract_classes), 2)
        self.assertEqual(contract_classes[0].ctrace, trace_bundles[0].ctrace)
        self.assertEqual(len(contract_classes[0]), 2)
        self.assertEqual(contract_classes[0].measurements, trace_bundles[:2])
        self.assertEqual(contract_classes[1].ctrace, trace_bundles[2].ctrace)
        self.assertEqual(contract_classes[1].measurements, trace_bundles[2:])

    def test_accessors(self) -> None:
        # Test accessors: `set_hw_classes`, `set_trivial_hw_classes`, `get_hw_classes`
        trace_bundles = _get_bundle_set()
        contract_classes = ContractEqClass.build_contract_classes(trace_bundles)

        # get_hw_classes - failing case
        with self.assertRaises(AssertionError):
            _ = contract_classes[0].get_hw_classes()

        # set_hw_classes
        hw_classes = HardwareEqClass.build_hw_classes(trace_bundles)
        contract_classes[0].set_hw_classes(hw_classes)
        self.assertEqual(contract_classes[0].get_hw_classes(), hw_classes)
        with self.assertRaises(AssertionError):  # repeated setting forbidden
            contract_classes[0].set_hw_classes([])

        # set_trivial_hw_classes
        with self.assertRaises(AssertionError):
            contract_classes[0].set_trivial_hw_classes()
        contract_classes = ContractEqClass.build_contract_classes(trace_bundles)
        contract_classes[0].set_trivial_hw_classes()
        self.assertEqual(contract_classes[0].get_hw_classes()[0].htrace, hw_classes[0].htrace)
        self.assertEqual(contract_classes[0].get_hw_classes()[0], hw_classes[0])


class TestViolation(unittest.TestCase):
    """ Unit tests for Violation class """

    def test_constructors(self) -> None:
        # __init__
        measurements = _get_bundle_set()[2:]
        input_sequence = [m.input_ for m in measurements]
        test_case_code = unittest.mock.MagicMock(spec=TestCaseProgram)
        violation = Violation(measurements, input_sequence, test_case_code)
        violation.set_trivial_hw_classes()
        self.assertEqual(violation.input_sequence, input_sequence)
        self.assertEqual(violation.test_case_code, test_case_code)

        # from_contract_eq_class
        contract_class = ContractEqClass.build_contract_classes(measurements)[0]
        contract_class.set_trivial_hw_classes()
        violation_from_class = Violation.from_contract_eq_class(contract_class, input_sequence,
                                                                test_case_code)
        self.assertEqual(violation_from_class.input_sequence, input_sequence)
        self.assertEqual(violation_from_class.test_case_code, test_case_code)
        self.assertListEqual(violation_from_class.measurements, violation.measurements)
        self.assertEqual(violation_from_class.input_sequence, input_sequence)

        # pseudo_violation_from_inputs
        pseudo_violation = Violation.pseudo_violation_from_inputs(input_sequence, test_case_code)
        self.assertEqual(pseudo_violation.input_sequence, input_sequence)
        self.assertEqual(pseudo_violation.test_case_code, test_case_code)
        self.assertTrue(pseudo_violation.measurements[0].ctrace.is_empty())
        self.assertTrue(pseudo_violation.measurements[0].htrace.is_empty())
