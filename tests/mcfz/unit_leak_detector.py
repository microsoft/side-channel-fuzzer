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
    return config


def _write_trace(path: str, entries: List[TraceEntry]) -> None:
    """Serialize trace entries to the on-disk DR trace format: an 8-byte marker followed
    by packed trace_entry_t records (addr:u64, size:u8, spec_level:u8, type:u8)."""
    data = b"T" + b"\x00" * 7  # 8-byte marker
    for addr, size, spec_level, entry_type in entries:
        data += struct.pack("<QBBB", addr, size, spec_level, entry_type)
    with open(path, "wb") as f:
        f.write(data)


class TestLeakDetectorInit(unittest.TestCase):

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
            LeakDetector(self._config())

    def test_empty_stage3_dir(self) -> None:
        os.makedirs(self._stage3_wd)
        with self.assertRaises(FileNotFoundError):
            LeakDetector(self._config())

    def test_valid_stage3_dir(self) -> None:
        os.makedirs(self._stage3_wd)
        # A single (arbitrary) entry makes the directory non-empty
        Path(self._stage3_wd, "placeholder").touch()
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


if __name__ == "__main__":
    unittest.main()
