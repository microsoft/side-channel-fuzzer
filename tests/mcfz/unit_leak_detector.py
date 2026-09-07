"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # justification: test conventions
# pylint: disable=missing-class-docstring  # justification: test conventions

import os
import struct
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

from mcfz.config import Config
from mcfz.leak_detector import LeakDetector, LeakageMap, PC

# Trace entry types, mirroring trace_entry_type_t in
# rvzr/model_dynamorio/backend/include/types/trace.hpp
ENTRY_EOT = 0
ENTRY_PC = 1
ENTRY_READ = 2
ENTRY_WRITE = 3

# Size of a single leak record, mirroring the packed leak_t struct in
# rvzr/model_dynamorio/leak_detector/leak.h (pc:u64, type:u8, spec_level:u8, ref_idx:u64,
# tgt_idx:u64)
LEAK_RECORD_SIZE = 26

# A trace entry is (addr, size, spec_level, type).
TraceEntry = Tuple[int, int, int, int]

# Location of the pre-built C++ leak detector binaries (built by `make -C
# rvzr/model_dynamorio leak-detector`). The tests that need them skip if absent.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_BIN_DIR = _REPO_ROOT / "rvzr" / "model_dynamorio" / "leak_detector" / "build"


def _make_min_config(stage3_wd: str, stage4_wd: str, model_root: str) -> Config:
    """Build a bare Config with only the attributes the leak-detection pipeline reads,
    bypassing the YAML/singleton machinery."""
    config = object.__new__(Config)
    config.stage3_wd = stage3_wd
    config.stage4_wd = stage4_wd
    config.model_root = model_root
    config.num_workers_detector = 1
    config.keep_stage4_files = False
    config.compression_tool = "none"
    config.pipeline_trace_and_detect = False
    return config


def _write_trace(path: str, entries: List[TraceEntry]) -> None:
    """Serialize trace entries to the on-disk DR trace format: an 8-byte marker followed
    by packed trace_entry_t records (addr:u64, size:u8, spec_level:u8, type:u8)."""
    data = b"T" + b"\x00" * 7  # 8-byte marker
    for addr, size, spec_level, entry_type in entries:
        data += struct.pack("<QBBB", addr, size, spec_level, entry_type)
    with open(path, "wb") as f:
        f.write(data)


class TestLeakDetectorValidation(unittest.TestCase):

    def setUp(self) -> None:
        self._temp_dir = tempfile.mkdtemp()
        self._stage3_wd = os.path.join(self._temp_dir, "stage3")
        self._stage4_wd = os.path.join(self._temp_dir, "stage4")
        self._model_root = os.path.join(self._temp_dir, "model")
        os.makedirs(self._stage4_wd)
        os.makedirs(self._model_root)

    def tearDown(self) -> None:
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _config(self) -> Config:
        return _make_min_config(self._stage3_wd, self._stage4_wd, self._model_root)

    def test_missing_stage3_dir(self) -> None:
        # stage3_wd was never created
        with self.assertRaises(FileNotFoundError):
            LeakDetector(self._config()).build_leakage_map(self._stage3_wd, 0)

    def test_empty_stage3_dir(self) -> None:
        os.makedirs(self._stage3_wd)
        with self.assertRaises(FileNotFoundError):
            LeakDetector(self._config()).build_leakage_map(self._stage3_wd, 0)

    def test_construction_before_tracing(self) -> None:
        # Constructing a detector must not require a populated stage3 directory: when tracing and
        # leak detection are pipelined, the detector is created before any trace is collected
        LeakDetector(self._config())  # must not raise


@unittest.skipUnless((_BIN_DIR / "leak_detector").is_file() and (_BIN_DIR / "merger").is_file(),
                     "C++ leak detector binaries not built "
                     "(run `make -C rvzr/model_dynamorio leak-detector`)")
class TestBuildLeakageMap(unittest.TestCase):

    def setUp(self) -> None:
        self._temp_dir = tempfile.mkdtemp()
        self._stage3_wd = os.path.join(self._temp_dir, "stage3")
        self._stage4_wd = os.path.join(self._temp_dir, "stage4")
        self._group_dir = os.path.join(self._stage3_wd, "grp")
        os.makedirs(self._group_dir)
        os.makedirs(self._stage4_wd)

    def tearDown(self) -> None:
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _run(self, reference: List[TraceEntry], target: List[TraceEntry]) -> LeakageMap:
        _write_trace(os.path.join(self._group_dir, "000.trace"), reference)
        _write_trace(os.path.join(self._group_dir, "001.trace"), target)
        config = _make_min_config(self._stage3_wd, self._stage4_wd, str(_BIN_DIR))
        detector = LeakDetector(config)
        return detector.build_leakage_map(self._stage3_wd, 0)

    def test_i_leak(self) -> None:
        # Same first two instructions, then a control-flow divergence at the architectural
        # level. The detector blames the preceding branch (PC 0x2000).
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x3000, 1, 0, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x4000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x2000), result["seq"]["I"])
        witness = result["seq"]["I"][PC(0x2000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (1, 1))
        self.assertEqual(result["seq"]["D"], {})
        self.assertEqual(result["cond"], {})

    def test_i_leak_at_trace_start(self) -> None:
        # Control-flow divergence at the second instruction: the blamed branch is the very
        # first instruction (trace index 0).
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x3000, 1, 0, ENTRY_PC), (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x1000), result["seq"]["I"])
        witness = result["seq"]["I"][PC(0x1000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (0, 0))
        self.assertEqual(result["seq"]["D"], {})
        self.assertEqual(result["cond"], {})

    def test_i_leak_with_shifted_target_index(self) -> None:
        # The reference trace contains a speculative instruction (PC 0x9000, spec_level 1) that the
        # target trace does not, so the same architectural instruction sits at different indices in
        # the two traces. The witness must report the index within the target trace it names
        # (`line`), and the reference index separately (`ref_line`).
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x9000, 1, 1, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC),
                     (0x3000, 1, 0, ENTRY_PC), (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x4000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x2000), result["seq"]["I"])
        witness = result["seq"]["I"][PC(0x2000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (1, 2))

    def test_d_leak(self) -> None:
        # Same PCs, but the first instruction reads different addresses.
        reference = [(0x1000, 1, 0, ENTRY_PC), (0xAAAA, 8, 0, ENTRY_READ), (0x2000, 1, 0, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0xBBBB, 8, 0, ENTRY_READ), (0x2000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x1000), result["seq"]["D"])
        witness = result["seq"]["D"][PC(0x1000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (0, 0))
        self.assertEqual(result["seq"]["I"], {})
        self.assertEqual(result["cond"], {})

    def test_cond_i_leak(self) -> None:
        # Both traces enter the same speculation window (spec_level 1) at PC 0x2000, then diverge
        # in control flow *within* that window (0x3000 vs 0x4000). Because the divergence is
        # speculative, the leak is attributed to the "cond" clause (not "seq"), and blamed to the
        # preceding speculative branch (PC 0x2000).
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 1, ENTRY_PC), (0x3000, 1, 1, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 1, ENTRY_PC), (0x4000, 1, 1, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x2000), result["cond"]["I"])
        witness = result["cond"]["I"][PC(0x2000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (1, 1))
        self.assertEqual(result["cond"]["D"], {})
        self.assertEqual(result["seq"], {})

    def test_cond_d_leak(self) -> None:
        # Identical architectural and speculative control flow, but the speculative instruction at
        # PC 0x2000 (spec_level 1) reads different addresses in the two traces. The secret-dependent
        # access is exposed only under speculation, so it lands in the "cond" clause.
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 1, ENTRY_PC), (0xAAAA, 8, 1, ENTRY_READ),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 1, ENTRY_PC), (0xBBBB, 8, 1, ENTRY_READ),
                  (0, 0, 0, ENTRY_EOT)]

        result = self._run(reference, target)

        self.assertIn(PC(0x2000), result["cond"]["D"])
        witness = result["cond"]["D"][PC(0x2000)][0]
        self.assertTrue(witness["trace"].endswith("001.trace"))
        self.assertEqual((witness["line"], witness["ref_line"]), (1, 1))
        self.assertEqual(result["cond"]["I"], {})
        self.assertEqual(result["seq"], {})

    def test_no_leak(self) -> None:
        # Identical traces: no divergence, so no leaks are reported.
        trace = [(0x1000, 1, 0, ENTRY_PC), (0xAAAA, 8, 0, ENTRY_READ), (0x2000, 1, 0, ENTRY_PC),
                 (0, 0, 0, ENTRY_EOT)]

        result = self._run(trace, list(trace))

        self.assertEqual(result["seq"], {})
        self.assertEqual(result["cond"], {})


@unittest.skipUnless((_BIN_DIR / "leak_detector").is_file() and (_BIN_DIR / "merger").is_file(),
                     "C++ leak detector binaries not built "
                     "(run `make -C rvzr/model_dynamorio leak-detector`)")
class TestPipelinedDetection(unittest.TestCase):
    """ Tests for the interface used when tracing and leak detection are pipelined: leaks are
    detected one group at a time, and the results are merged into a report while detection of
    the remaining groups is still in progress. """

    def setUp(self) -> None:
        self._temp_dir = tempfile.mkdtemp()
        self._stage3_wd = os.path.join(self._temp_dir, "stage3")
        self._stage4_wd = os.path.join(self._temp_dir, "stage4")
        self._group_dir = os.path.join(self._stage3_wd, "grp")
        os.makedirs(self._group_dir)
        os.makedirs(self._stage4_wd)

    def tearDown(self) -> None:
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _detect(self, reference: List[TraceEntry], target: List[TraceEntry]) -> Config:
        """ Detect leaks in a single group of traces, as the tracer does in pipelined mode. """
        traces = [os.path.join(self._group_dir, name) for name in ("000.trace", "001.trace")]
        _write_trace(traces[0], reference)
        _write_trace(traces[1], target)
        config = _make_min_config(self._stage3_wd, self._stage4_wd, str(_BIN_DIR))
        LeakDetector(config).detect_group(traces)
        return config

    def _leaks_file(self) -> str:
        return os.path.join(self._stage4_wd, "grp", "001.leaks")

    def test_merge_without_cleanup_preserves_leaks_files(self) -> None:
        # An intermediate merge must leave the .leaks files in place, as detection of the
        # remaining groups is still in progress and the final merge needs them
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x3000, 1, 0, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x4000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]
        config = self._detect(reference, target)

        result = LeakDetector(config).merge(cleanup=False)

        self.assertIn(PC(0x2000), result["seq"]["I"])
        self.assertTrue(os.path.isfile(self._leaks_file()))

    def test_merge_with_cleanup_removes_leaks_files(self) -> None:
        # The final merge reports the same leaks, but reclaims the disk space
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x3000, 1, 0, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x4000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]
        config = self._detect(reference, target)

        result = LeakDetector(config).merge()

        self.assertIn(PC(0x2000), result["seq"]["I"])
        self.assertFalse(os.path.exists(self._leaks_file()))

    def test_merge_tolerates_partially_written_leaks_file(self) -> None:
        # An intermediate merge may read a .leaks file that a worker is still writing. Since the
        # records are appended one at a time, such a file must be read as a valid prefix: here,
        # the first of the two leaks is reported and the truncated second one is dropped
        reference = [(0x1000, 1, 0, ENTRY_PC), (0xAAAA, 8, 0, ENTRY_READ), (0x2000, 1, 0, ENTRY_PC),
                     (0xCCCC, 8, 0, ENTRY_READ), (0x3000, 1, 0, ENTRY_PC), (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0xBBBB, 8, 0, ENTRY_READ), (0x2000, 1, 0, ENTRY_PC),
                  (0xDDDD, 8, 0, ENTRY_READ), (0x3000, 1, 0, ENTRY_PC), (0, 0, 0, ENTRY_EOT)]
        config = self._detect(reference, target)
        self.assertEqual(os.path.getsize(self._leaks_file()), 2 * LEAK_RECORD_SIZE)

        # Simulate a file caught mid-write, with the second record only partially flushed
        os.truncate(self._leaks_file(), LEAK_RECORD_SIZE + 5)
        result = LeakDetector(config).merge(cleanup=False)

        self.assertEqual(list(result["seq"]["D"].keys()), [PC(0x1000)])

    def test_report_merges_instead_of_redetecting(self) -> None:
        # With pipelining enabled, `report` must merge the leaks that tracing already detected
        # rather than running the detector again. Overwriting the target trace with a copy of the
        # reference proves that no detection takes place: a re-run would compare two identical
        # traces and find no leak at all.
        reference = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x3000, 1, 0, ENTRY_PC),
                     (0, 0, 0, ENTRY_EOT)]
        target = [(0x1000, 1, 0, ENTRY_PC), (0x2000, 1, 0, ENTRY_PC), (0x4000, 1, 0, ENTRY_PC),
                  (0, 0, 0, ENTRY_EOT)]
        config = self._detect(reference, target)
        config.pipeline_trace_and_detect = True
        _write_trace(os.path.join(self._group_dir, "001.trace"), reference)

        result = LeakDetector(config).build_leakage_map(self._stage3_wd, 0)

        self.assertIn(PC(0x2000), result["seq"]["I"])


if __name__ == "__main__":
    unittest.main()
