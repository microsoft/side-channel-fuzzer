"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # justification: test conventions
# pylint: disable=missing-class-docstring  # justification: test conventions

import unittest
from unittest.mock import patch

import numpy as np
import numpy.typing as npt

from mcfz.driller import Driller, TracedInstructionDType, _LeakInfo, _extract_instructions
from rvzr.model_dynamorio.trace_decoder import TraceEntryDType, TraceEntryType


def _extract_from(raw_trace: npt.NDArray[np.void]) -> npt.NDArray[np.void]:
    with patch('mcfz.driller.TraceDecoder.decode_trace_file', return_value=raw_trace):
        return _extract_instructions('001.trace')


class TestInstructionExtraction(unittest.TestCase):

    def test_preserves_pc_order_levels_and_raw_indices(self) -> None:
        entries = [
            (0x100, 1, 0, TraceEntryType.ENTRY_PC),
            (0x200, 8, 0, TraceEntryType.ENTRY_READ),
            (0x300, 8, 0, TraceEntryType.ENTRY_WRITE),
            (0x110, 1, 1, TraceEntryType.ENTRY_PC),
            (0x400, 8, 1, TraceEntryType.ENTRY_READ),
            (0x100, 1, 2, TraceEntryType.ENTRY_PC),
            (0, 0, 0, TraceEntryType.ENTRY_EOT),
        ]
        raw_trace = np.array(entries, dtype=TraceEntryDType)

        instructions = _extract_from(raw_trace)

        self.assertEqual(instructions.dtype, TracedInstructionDType)
        self.assertEqual(instructions.tolist(), [(0x100, 0, 0), (0x110, 1, 3), (0x100, 2, 5)])

    def test_empty_trace(self) -> None:
        instructions = _extract_from(np.zeros(0, dtype=TraceEntryDType))

        self.assertEqual(instructions.dtype, TracedInstructionDType)
        self.assertEqual(instructions.shape, (0,))

    def test_trace_without_pc_entries(self) -> None:
        raw_trace = np.array([(0x200, 8, 0, TraceEntryType.ENTRY_READ),
                              (0, 0, 0, TraceEntryType.ENTRY_EOT)],
                             dtype=TraceEntryDType)

        self.assertEqual(_extract_from(raw_trace).shape, (0,))


class TestSpeculationWindows(unittest.TestCase):

    def test_architectural_occurrences_exclude_speculation_and_non_pc_entries(self) -> None:
        entries = [
            (0x100, 1, 0, TraceEntryType.ENTRY_PC),
            (0x100, 8, 0, TraceEntryType.ENTRY_READ),
            (0x110, 1, 0, TraceEntryType.ENTRY_PC),
            (0x100, 1, 1, TraceEntryType.ENTRY_PC),
            (0x100, 1, 0, TraceEntryType.ENTRY_PC),
            (0, 0, 0, TraceEntryType.ENTRY_EOT),
        ]
        raw_trace = np.array(entries, dtype=TraceEntryDType)
        driller = object.__new__(Driller)

        for target_line, occurrences in [(0, 0), (4, 1)]:
            with self.subTest(target_line=target_line):
                leak = _LeakInfo('seq', 'D', 'test.c:1', '0x100', '001.trace', target_line)
                with patch('mcfz.driller.TraceDecoder.decode_trace_file', return_value=raw_trace):
                    windows = driller._find_spec_windows(leak)

                self.assertEqual(
                    [(w.start_pc, w.pc, w.trace_line_id, w.pc_occurrence) for w in windows],
                    [(0x100, 0x100, target_line, occurrences)])

    def test_rejects_report_trace_mismatches(self) -> None:
        entries = [
            (0x100, 1, 0, TraceEntryType.ENTRY_PC),
            (0x110, 1, 1, TraceEntryType.ENTRY_PC),
            (0x200, 8, 1, TraceEntryType.ENTRY_READ),
        ]
        raw_trace = np.array(entries, dtype=TraceEntryDType)
        driller = object.__new__(Driller)
        cases = [
            ('seq', '0x200', 0, 'out of sync'),
            ('cond', '0x200', 2, 'out of sync'),
            ('seq', '0x100', 3, 'out of sync'),
            ('cond', '0x100', 0, 'contradicts'),
            ('seq', '0x110', 1, 'contradicts'),
        ]
        for clause, pc, line, message in cases:
            with self.subTest(clause=clause, pc=pc, line=line):
                leak = _LeakInfo(clause, 'D', 'test.c:1', pc, '001.trace', line)
                with patch('mcfz.driller.TraceDecoder.decode_trace_file', return_value=raw_trace):
                    with self.assertRaisesRegex(AssertionError, message):
                        driller._find_spec_windows(leak)

    def test_nested_windows_preserve_raw_locations_and_occurrences(self) -> None:
        entries = [
            (0x100, 1, 0, TraceEntryType.ENTRY_PC),
            (0x200, 8, 0, TraceEntryType.ENTRY_READ),
            (0x110, 1, 0, TraceEntryType.ENTRY_PC),
            (0x120, 1, 1, TraceEntryType.ENTRY_PC),
            (0x130, 1, 1, TraceEntryType.ENTRY_PC),
            (0x140, 1, 2, TraceEntryType.ENTRY_PC),
            (0x200, 8, 2, TraceEntryType.ENTRY_READ),
            (0x140, 1, 2, TraceEntryType.ENTRY_PC),
            (0, 0, 0, TraceEntryType.ENTRY_EOT),
        ]
        raw_trace = np.array(entries, dtype=TraceEntryDType)
        leak = _LeakInfo('cond', 'D', 'test.c:1', '0x140', '001.trace', 7)
        driller = object.__new__(Driller)

        with patch('mcfz.driller.TraceDecoder.decode_trace_file', return_value=raw_trace):
            windows = driller._find_spec_windows(leak)

        self.assertEqual([(w.start_pc, w.pc, w.trace_line_id, w.pc_occurrence) for w in windows],
                         [(0x100, 0x110, 2, 0), (0x120, 0x130, 4, 0), (0x140, 0x140, 7, 1)])
