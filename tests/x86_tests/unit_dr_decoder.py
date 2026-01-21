"""
File: Collection of unit tests for DynamoRIO backend adaptor.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-arguments
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-public-methods
# pylint: disable=protected-access
# pylint: disable=missing-function-docstring

import unittest
import struct
import os
# from unittest.mock import MagicMock
from tempfile import NamedTemporaryFile
from typing import Any, List, Dict

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType
from rvzr.model_dynamorio.trace_decoder import DebugTraceEntryType

# ------------------------------------------------------------------------------
# Leakage trace representation
# ------------------------------------------------------------------------------
# Content of the test trace
TEST_TRACE: List[Dict[str, Any]] = [
    {
        "addr": 0x0,
        "size": 8,
        "type": TraceEntryType.ENTRY_PC
    },
    {
        "addr": 0xdeadbeef,
        "size": 4,
        "type": TraceEntryType.ENTRY_READ
    },
    {
        "addr": 0xcafecafe,
        "size": 8,
        "type": TraceEntryType.ENTRY_WRITE
    },
    {
        "addr": 11,
        "size": 0,
        "type": TraceEntryType.ENTRY_EXCEPTION
    },
    {
        "addr": 0x0,
        "size": 0x0,
        "type": TraceEntryType.ENTRY_EOT
    },
]
# Format string to parse a trace entry
TRACE_FMT = "<QHB"

# ------------------------------------------------------------------------------
# Debug trace representation
# ------------------------------------------------------------------------------
# Contents of the debug test trace
TEST_DBG_TRACE: List[Dict[str, Any]] = [
    {
        "type": DebugTraceEntryType.ENTRY_REG_DUMP.value,
        "spec": 0,
        "xax": 0xaaaaaaaa,
        "xbx": 0xbbbbbbbb,
        "xcx": 0xcccccccc,
        "xdx": 0xdddddddd,
        "xsi": 0xeeeeeeee,
        "xdi": 0xffffffff,
        "pc": 0xdeadbeef,
    },
    {
        "type": DebugTraceEntryType.ENTRY_LOC.value,
        "spec": 0,
        "offset": 0xABCD,
        "module_name": "/usr/lib/test.so" + ("\x00" * 32),
    },
    {
        "type": DebugTraceEntryType.ENTRY_READ.value,
        "spec": 0,
        "address": 0xcafecafe,
        "value": 0xabababab,
        "size": 0xf,
    },
    {
        "type": DebugTraceEntryType.ENTRY_WRITE.value,
        "spec": 0,
        "address": 0xcdcdcdcd,
        "value": 0xcafecafe,
        "size": 8,
    },
    {
        "type": DebugTraceEntryType.ENTRY_CHECKPOINT.value,
        "spec": 1,
        "rollback_pc": 0xdeadbeef,
        "cur_window_size": 1,
        "cur_store_log_size": 1,
    },
    {
        "type": DebugTraceEntryType.ENTRY_ROLLBACK_STORE.value,
        "spec": 1,
        "addr": 0xcdcdcdcd,
        "val": 0xcafecafe,
        "size": 0xf,
        "nesting_level": 1,
    },
    {
        "type": DebugTraceEntryType.ENTRY_ROLLBACK.value,
        "spec": 1,
        "nesting": 1,
        "rollback_pc": 0xdeadbeef,
    },
    {
        "type": DebugTraceEntryType.ENTRY_EXCEPTION.value,
        "spec": 0,
        "signal": 11,
        "address": 0xcdcdcdcd,
    },
    {
        "type": DebugTraceEntryType.ENTRY_EOT.value,
        "spec": 0,
    },
]
# Shared fields for debug entries
DBG_TRACE_PREFIX = '<BB' + ('x' * 6)
# Fields specific to each entry type
DBG_TRACE_FMT = {
    DebugTraceEntryType.ENTRY_EOT: DBG_TRACE_PREFIX,
    DebugTraceEntryType.ENTRY_REG_DUMP: DBG_TRACE_PREFIX + ('Q' * 7),
    DebugTraceEntryType.ENTRY_READ: DBG_TRACE_PREFIX + 'QQQ',
    DebugTraceEntryType.ENTRY_WRITE: DBG_TRACE_PREFIX + 'QQQ',
    DebugTraceEntryType.ENTRY_LOC: DBG_TRACE_PREFIX + 'Q' + ('c' * 48),
    DebugTraceEntryType.ENTRY_EXCEPTION: DBG_TRACE_PREFIX + 'ixxxxQ',
    DebugTraceEntryType.ENTRY_CHECKPOINT: DBG_TRACE_PREFIX + 'QQI',
    DebugTraceEntryType.ENTRY_ROLLBACK: DBG_TRACE_PREFIX + 'IxxxxQ',
    DebugTraceEntryType.ENTRY_ROLLBACK_STORE: DBG_TRACE_PREFIX + 'QQIxxxxQ',
}

# ------------------------------------------------------------------------------
# Testsuite
# ------------------------------------------------------------------------------


class DRTraceDecodeTest(unittest.TestCase):
    """
    Suite of tests for the DR trace decoder
    """

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------
    def _find_entry_of_type(self, t: int) -> dict[str, Any]:
        for e in TEST_TRACE:
            if e["type"] == t:
                return e

        raise ValueError(f"No entry for type {t}")

    def _encode_from_dict(self, entry: dict[str, Any]) -> bytes:
        return struct.pack(TRACE_FMT, entry["addr"], entry["size"], entry["type"])

    def _check_trace_equivalence(self, expected: dict[str, Any], decoded: Any) -> None:
        self.assertEqual(expected["addr"], decoded['addr'])
        self.assertEqual(expected["size"], decoded['size'])
        self.assertEqual(expected["type"], decoded['type'])

    # --------------------------------------------------------------------------
    # Test cases
    # --------------------------------------------------------------------------
    def test_trace_decoding(self) -> None:
        decoder = TraceDecoder()

        # Encode the special marker
        packed_trace = struct.pack("c", "T".encode('utf-8'))
        packed_trace += b'\x00' * 7  # Padding to ensure the marker is 8 bytes long

        # Encode all entries
        for test_entry in TEST_TRACE:
            packed_trace += self._encode_from_dict(test_entry)

        with NamedTemporaryFile("wb", delete=False) as f:
            # Write encoded entries to file
            f.write(packed_trace)
            f.close()
            # Decode the file
            parsed_traces = decoder.decode_trace_file(f.name)
            self.assertEqual(len(parsed_traces), len(TEST_TRACE))
            # Check decoded entries
            for idx, decoded in enumerate(parsed_traces):
                self._check_trace_equivalence(TEST_TRACE[idx], decoded)

    def test_is_corrupted(self) -> None:
        decoder = TraceDecoder()

        # Encode the special marker
        marker = struct.pack("c", "T".encode('utf-8'))
        marker += b'\x00' * 7  # Padding to ensure the marker is 8 bytes long
        pc = self._encode_from_dict(self._find_entry_of_type(TraceEntryType.ENTRY_PC))
        xcpt = self._encode_from_dict(self._find_entry_of_type(TraceEntryType.ENTRY_EXCEPTION))
        eot = self._encode_from_dict(self._find_entry_of_type(TraceEntryType.ENTRY_EOT))

        # Only EOT is valid at the end of the trace
        traces = [(pc, True), (pc + xcpt, True), (pc + eot, False), (pc + xcpt + eot, False)]

        for t in traces:
            with NamedTemporaryFile("wb", delete=False) as f:
                # Write encoded entries to file
                f.write(marker + t[0])
                f.close()

            # Check if the file is corrupted
            is_corrupted = decoder.is_trace_corrupted(f.name)
            if t[1]:
                self.assertTrue(is_corrupted)
            else:
                self.assertFalse(is_corrupted)

            os.remove(f.name)


class DRDebugTraceDecodeTest(unittest.TestCase):
    """
    Suite of tests for the DR trace decoder for debug traces
    """

    # --------------------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------------------
    def _find_entry_of_type(self, t: DebugTraceEntryType) -> dict[str, Any]:
        for e in TEST_DBG_TRACE:
            if e["type"] == t.value:
                return e

        raise ValueError(f"No debug entry for type {t}")

    def _encode_from_dict(self, entry: dict[str, Any]) -> bytes:
        # Get format string depending on the entry type
        fmt = DBG_TRACE_FMT[DebugTraceEntryType(entry["type"])]
        # Add padding if needed
        if struct.calcsize(fmt) < 64:
            fmt += 'x' * (64 - struct.calcsize(fmt))

        # Get the values to encode
        vals = list(entry.values())
        to_pack = []
        for v in vals:
            if isinstance(v, str):
                # Encode strings as char arrays
                to_pack.extend([x.encode('utf-8') for x in list(v)])
            else:
                # Otherwise just use the value in the map
                to_pack.append(v)

        return struct.pack(fmt, *to_pack)

    def _check_dbg_trace_equivalence(self, expected: dict[str, Any], decoded: Any) -> None:
        type_ = DebugTraceEntryType(decoded.type)

        if type_ == DebugTraceEntryType.ENTRY_REG_DUMP:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["xax"], decoded.regs.xax)
            self.assertEqual(expected["xbx"], decoded.regs.xbx)
            self.assertEqual(expected["xcx"], decoded.regs.xcx)
            self.assertEqual(expected["xdx"], decoded.regs.xdx)
            self.assertEqual(expected["xsi"], decoded.regs.xsi)
            self.assertEqual(expected["xdi"], decoded.regs.xdi)
            self.assertEqual(expected["pc"], decoded.regs.pc)
        elif type_ == DebugTraceEntryType.ENTRY_LOC:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["offset"], decoded.loc.offset)
            self.assertEqual(expected["module_name"],
                             (b''.join(decoded.loc.module_name)).decode('utf-8'))
        elif type_ == DebugTraceEntryType.ENTRY_READ:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["address"], decoded.mem.address)
            self.assertEqual(expected["value"], decoded.mem.value)
            self.assertEqual(expected["size"], decoded.mem.size)
        elif type_ == DebugTraceEntryType.ENTRY_WRITE:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["address"], decoded.mem.address)
            self.assertEqual(expected["value"], decoded.mem.value)
            self.assertEqual(expected["size"], decoded.mem.size)
        elif type_ == DebugTraceEntryType.ENTRY_CHECKPOINT:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["rollback_pc"], decoded.checkpoint.rollback_pc)
            self.assertEqual(expected["cur_window_size"], decoded.checkpoint.cur_window_size)
            self.assertEqual(expected["cur_store_log_size"], decoded.checkpoint.cur_store_log_size)
        elif type_ == DebugTraceEntryType.ENTRY_ROLLBACK_STORE:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["addr"], decoded.rollback_store.addr)
            self.assertEqual(expected["val"], decoded.rollback_store.val)
            self.assertEqual(expected["size"], decoded.rollback_store.size)
            self.assertEqual(expected["nesting_level"], decoded.rollback_store.nesting_level)
        elif type_ == DebugTraceEntryType.ENTRY_ROLLBACK:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["nesting"], decoded.rollback.nesting)
            self.assertEqual(expected["rollback_pc"], decoded.rollback.rollback_pc)
        elif type_ == DebugTraceEntryType.ENTRY_EXCEPTION:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
            self.assertEqual(expected["signal"], decoded.xcpt.signal)
            self.assertEqual(expected["address"], decoded.xcpt.address)
        elif type_ == DebugTraceEntryType.ENTRY_EOT:
            self.assertEqual(expected["type"], type_.value)
            self.assertEqual(expected["spec"], decoded.nesting_level)
        else:
            raise ValueError("Unknown debug trace type")

    # --------------------------------------------------------------------------
    # Test cases
    # --------------------------------------------------------------------------
    def test_debug_entry_decoding(self) -> None:
        decoder = TraceDecoder()

        for original in TEST_DBG_TRACE:
            # Encode entry to a bytes array
            encoded = self._encode_from_dict(original)
            # Decode it as an object
            decoded = decoder._decode_debug_trace_entry(encoded)
            # Test the decoded output
            self._check_dbg_trace_equivalence(original, decoded)

    def test_debug_trace_decoding(self) -> None:
        decoder = TraceDecoder()

        # Encode the special marker
        packed_trace = struct.pack("c", "D".encode('utf-8'))
        packed_trace += b'\x00' * 7  # Padding to ensure the marker is 8 bytes long

        # Encode all entries
        for test_entry in TEST_DBG_TRACE:
            packed_trace += self._encode_from_dict(test_entry)

        with NamedTemporaryFile("wb", delete=False) as f:
            # Write encoded entries to a file
            f.write(packed_trace)
            f.close()
            # Decode the file
            parsed_dbg_traces = decoder.decode_debug_trace_file(f.name)
            self.assertEqual(len(parsed_dbg_traces), 1)
            # Check decoded entries
            for idx, decoded in enumerate(parsed_dbg_traces[0]):
                self._check_dbg_trace_equivalence(TEST_DBG_TRACE[idx], decoded)

    def test_is_corrupted(self) -> None:
        decoder = TraceDecoder()

        # Encode the special marker
        marker = struct.pack("c", "D".encode('utf-8'))
        marker += b'\x00' * 7  # Padding to ensure the marker is 8 bytes long
        pc = self._encode_from_dict(self._find_entry_of_type(DebugTraceEntryType.ENTRY_REG_DUMP))
        xcpt = self._encode_from_dict(self._find_entry_of_type(DebugTraceEntryType.ENTRY_EXCEPTION))
        eot = self._encode_from_dict(self._find_entry_of_type(DebugTraceEntryType.ENTRY_EOT))

        # Only EOT is valid at the end of the trace
        traces = [(pc, True), (pc + xcpt, True), (pc + eot, False), (pc + xcpt + eot, False)]

        for t in traces:
            with NamedTemporaryFile("wb", delete=False) as f:
                # Write encoded entries to file
                f.write(marker + t[0])
                f.close()

            # Decode the file
            if t[1]:
                with self.assertRaises(ValueError):
                    decoder.decode_debug_trace_file(f.name)
            else:
                parsed_traces = decoder.decode_debug_trace_file(f.name)
                self.assertEqual(len(parsed_traces), 1)

            os.remove(f.name)
