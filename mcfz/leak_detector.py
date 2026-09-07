"""
File: Module responsible for parsing contract traces and detecting leaks
      (violations of the non-interference property).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
import json
import shutil

from typing import (TYPE_CHECKING, List, Tuple, Dict, NewType, Literal, get_args, Optional)

from typing_extensions import TypedDict

from .util.compressor import Compressor, is_compressed
from .util.logger import Logger
from .util.worker_pool import send_to_worker_pool
from .util import console

if TYPE_CHECKING:
    from .config import Config

# ==================================================================================================
# Local type definitions
# ==================================================================================================
PC = NewType('PC', int)
""" Program Counter, used to identify instructions in the trace. """

FilePath = str
""" String representing a path """

LeakType = Literal['I', 'D']
""" Type of the leak:
    'I' for instruction leaks (e.g., secret dependent branch),
    'D' for data leaks (e.g., secret dependent memory access).
"""

ClauseType = Literal['seq', 'cond']
""" Type of the leak:
    'seq' for architectural leaks (happen under SEQ execution clause),
    'cond' for speculative leaks under the COND execution clause.
"""


class Witness(TypedDict):
    """ A single trace-pair location where a leak was observed.
        * trace is the path of the trace file where the leak was found;
        * line is the line number in that trace file;
        * ref_line is the corresponding line number in the reference trace
            (000.trace, which is the same for all leaks).
    """
    trace: str
    line: int
    ref_line: int


LeakageMap = Dict[ClauseType, Dict[
    LeakType,
    Dict[
        PC,
        List[Witness],
    ],
]]
""" Map of leaks found in the traces, indexed by clause, leak type, and PC.
    The value is a list of trace witnesses where the leak was found.
"""

DirName = str
FileName = str
WorkDirMap = Dict[DirName, List[FileName]]


# ==================================================================================================
# Trace parsing and leakage analysis
# ==================================================================================================
def _find_reference_trace(trace_files: List[FileName]) -> FileName:
    """ Find the reference trace file (000.trace) in the given list of trace files. """
    # Normally the reference trace is the first in the list, but we check to be sure
    for trace_file in trace_files:
        if os.path.basename(trace_file).startswith("000.trace"):
            return trace_file
    raise ValueError(f"Reference trace file (000.trace) not found in the given list. {trace_files}")


class _LeakDetectionWorker:
    """
    Service class that runs the external C++ leak detector over a group of traces that share
    the same reference trace (000.trace), i.e. traces for public-equivalent inputs.

    NOTE: this class is split from the main LeakDetector class to enable multiprocessing.
    """

    def __init__(self, config: Config, leak_detector_path: str) -> None:
        self._config = config
        self._compressor = Compressor(config)
        self._logger = Logger("LeakDetectionWorker")
        self.leak_detector_path = leak_detector_path

    def identify_all_leaks_in_group(self, trace_files: List[FileName]) -> None:
        """
        Identify all leaks in a group of traces that share the same reference trace.
        Runs the external C++ detector, which writes each trace's leaks to a file.
        """
        # Find and parse the reference trace (000.trace) for this group of traces.
        try:
            reference_trace_file = _find_reference_trace(trace_files)
            reference_trace_file_uncompressed = self._get_decompressed_trace(reference_trace_file)
            if reference_trace_file_uncompressed is None:
                return
        except ValueError as e:
            self._logger.warning(str(e) + " Skipping this set of traces.")
            return
        # Iterate over other traces
        for original_trace_file in trace_files:
            if os.path.basename(original_trace_file).startswith("000.trace"):
                continue
            # Decompress the trace
            trace_file = self._get_decompressed_trace(original_trace_file)
            if trace_file is None:
                continue
            # Build output path
            output_path = self._get_output_base_path(trace_file)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            # Run the reporter
            try:
                cmd = [
                    self.leak_detector_path, reference_trace_file_uncompressed, trace_file,
                    output_path
                ]
                subprocess.run(cmd, capture_output=True, check=True, text=True)
            except subprocess.CalledProcessError as e:
                with open(output_path + ".failed", 'w') as f:
                    f.write(e.stdout)
                    f.write(e.stderr)
            # Remove decompressed file to save disk space
            if is_compressed(original_trace_file):
                os.remove(trace_file)
        # Remove decompressed reference trace to save disk space
        if is_compressed(reference_trace_file):
            os.remove(reference_trace_file_uncompressed)

    def _get_output_base_path(self, input_path: FilePath) -> FilePath:
        """ Get the base filename for all tracer output files that correspond to the given input """
        rel_path = os.path.relpath(input_path, self._config.stage3_wd)
        output_path = os.path.join(self._config.stage4_wd, rel_path)
        base = os.path.splitext(output_path)[0] + ".leaks"
        return base

    def _get_decompressed_trace(self, trace_file: FileName) -> Optional[FileName]:
        if not os.path.isfile(trace_file):
            self._logger.warning(f"File {trace_file} not found.\n    "
                                 "Either tracing failed or is incomplete. Skipping")
            return None
        # If the file is compressed, decompress it
        if is_compressed(trace_file):
            decompressed_file = self._compressor.decompress_universal(trace_file, keep=True)
            return decompressed_file
        return trace_file


def _analyse_group_worker(args: Tuple[Config, List[FileName], str]) -> int:
    """
    Worker function for multiprocessing: analyzes a group of traces and generates a file
    with leak information for each trace using the C++ leak detector.
    """
    config, trace_files, leak_detector_path = args
    group_analyser = _LeakDetectionWorker(config, leak_detector_path)
    group_analyser.identify_all_leaks_in_group(trace_files)
    return len(trace_files)


class LeakDetector:
    """
    Class responsible for checking the collected contract traces for violations of the
    non-interference property.
    """

    def __init__(self, config: Config) -> None:
        self._logger = Logger("Analyser")
        self._config = config
        self._leak_detector_path = os.path.join(config.model_root, "leak_detector")
        self._merger_path = os.path.join(config.model_root, "merger")

    def prepare_output_dir(self) -> None:
        """
        Create the directory that holds the leak files produced by this detector.

        Called by the tracer before it starts producing leaks in pipelined mode; the per-group
        subdirectories are created on demand as the groups are analysed.
        """
        os.makedirs(self._config.stage4_wd, exist_ok=True)

    def detect_group(self, trace_files: List[FileName]) -> None:
        """
        Detect all leaks in a single group of traces, i.e. traces collected for
        public-equivalent inputs, and write them to a `.leaks` file per non-reference trace.

        :param trace_files: Paths of all traces in the group, including the reference trace
        """
        worker = _LeakDetectionWorker(self._config, self._leak_detector_path)
        worker.identify_all_leaks_in_group(trace_files)

    def build_leakage_map(self, stage3_dir: str, num_groups: int) -> LeakageMap:
        """
        Analyse all traces in stage3_dir with the C++ leak detector.

        When the tracing and leak detection stages are pipelined, the traces have already been
        analysed by the tracer, and this method only merges the resulting leak files.
        """
        if self._config.pipeline_trace_and_detect:
            return self.merge()

        if not os.path.isdir(self._config.stage3_wd):
            raise FileNotFoundError(
                f"Stage 3 working directory '{self._config.stage3_wd}' does not exist.")
        if not os.listdir(self._config.stage3_wd):
            raise FileNotFoundError(
                f"Stage 3 working directory '{self._config.stage3_wd}' is empty.")

        stage3_dir_map = self._get_directory_map(stage3_dir)

        # Initialize a progress bar to track the progress of the analysis
        progress_bar = console.progress_bar(
            total=sum(len(trace_files) for trace_files in stage3_dir_map.values()),
            desc="Analyzing traces",
            unit="trace",
        )

        # Prepare the list of work items for multiprocessing:
        # a tuple of (config, trace_files, leak_detector_path) for each group of traces.
        all_groups = list(stage3_dir_map.values())
        if num_groups > 0:
            self._logger.info(
                f"Processing only the first {num_groups} groups of traces as requested.")
            all_groups = all_groups[:num_groups]
        work_items = (
            (self._config, trace_files, self._leak_detector_path) for trace_files in all_groups)

        def _on_result(num_processed: int) -> None:
            progress_bar.update(num_processed)

        # Generate all .leaks files in the stage4 folder
        send_to_worker_pool(
            task=_analyse_group_worker,
            work_items=work_items,
            num_workers=self._config.num_workers_detector,
            on_complete=_on_result,
        )
        progress_bar.close()

        return self.merge()

    def merge(self, cleanup: bool = True) -> LeakageMap:
        """
        Merge all `.leaks` files currently present in the stage4 directory into a single report,
        and translate it into a LeakageMap.

        This method is safe to call while leak detection is still in progress: `.leaks` files are
        written append-only in fixed-size records, so a file that is being written is read as a
        valid prefix. A report produced this way may therefore be incomplete, but never corrupt.

        :param cleanup: Whether to remove the individual `.leaks` directories after merging;
               must be False while leak detection is still in progress
        :return: Map of all leaks found so far
        """
        # Merge all .leaks files into a single report
        result = subprocess.run([self._merger_path, self._config.stage4_wd],
                                capture_output=True,
                                text=True,
                                check=True)
        output_dir = Path(self._config.stage4_wd)

        # Print merged report to a json file
        with open(output_dir / "report.json", "w") as f:
            f.write(result.stdout)

        # Log all failed reporter runs (if any)
        with open(output_dir / "failed.txt", "w") as f:
            for path in sorted(str(p) for p in output_dir.rglob("*.failed")):
                f.write(path + "\n")

        # Remove individual .leaks folders to save disk space
        if cleanup and not self._config.keep_stage4_files:
            for item in output_dir.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)

        # Parse the report into a LeakageMap
        return self._parse_report(result.stdout)

    def _get_directory_map(self, stage3_dir: str) -> WorkDirMap:
        """
        Build a map of the working directory that will serve as a todo-list for the analysis.
        This map contains - as keys - all subdirectories in the Stage3 directory that contain
        trace files. The value for each key is a list of trace files in that subdirectory. The
        trace files are produced during the tracing stage, and may or may not be compressed.
        """
        dir_map: WorkDirMap = {}
        subdirs = os.listdir(stage3_dir)
        for subdir in subdirs:
            subdir_full = os.path.join(stage3_dir, subdir)
            if not os.path.isdir(subdir_full):
                continue

            file_list = []
            files_in_dir = set(os.listdir(subdir_full))
            for file_ in files_in_dir:
                # check if the file is a trace file
                # skip all those that are not
                if not file_.endswith(".trace") and \
                   not file_.endswith(".trace.gz") and \
                   not file_.endswith(".trace.bz2"):
                    continue
                # skip uncompressed trace files when a compressed version also exists;
                # decompressing the .gz/.bz2 would otherwise delete the .trace entry
                if file_.endswith(".trace") and \
                   (file_ + ".gz" in files_in_dir or file_ + ".bz2" in files_in_dir):
                    continue
                trace_path = os.path.join(subdir_full, file_)
                file_list.append(trace_path)
            if file_list:
                dir_map[subdir_full] = file_list
        return dir_map

    def _parse_report(self, report: str) -> LeakageMap:
        """ Parse the report generated by the C++ detector and translate it into a LeakageMap """

        leakage_map: LeakageMap = {}
        json_report = json.loads(report)

        for clause in get_args(ClauseType):
            out_clause_map = leakage_map.setdefault(clause, {})
            if clause not in json_report.keys():
                continue

            for leak_type in get_args(LeakType):
                out_type_map = out_clause_map.setdefault(leak_type, {})
                if leak_type not in json_report[clause].keys():
                    continue

                for pc, witnesses in json_report[clause][leak_type].items():
                    # Parse PC
                    parsed_pc = PC(int(pc, 16))
                    out_witnesses = out_type_map.setdefault(parsed_pc, [])

                    for witness in witnesses:
                        out_witnesses.append(
                            Witness(
                                trace=self._resolve_trace_path(witness["trace"]),
                                line=witness["line"],
                                ref_line=witness["ref_line"],
                            ))

        return leakage_map

    def _resolve_trace_path(self, leaks_path: str) -> str:
        """
        Translate a stage4 .leaks path reported by the detector into the corresponding
        stage3 .trace path expected by the LeakageMap.

        The detector reports the path of the _leak_ file (stage4/<input_id>/001.leaks), while
        the LeakageMap references the _trace_ file (stage3/<input_id>/001.trace[.bz2|.gz]).
        """
        filename = leaks_path.replace(self._config.stage4_wd, self._config.stage3_wd)
        filename = filename.replace(".leaks", ".trace")
        # Handle compressed traces
        if not os.path.isfile(filename):
            filename = filename + ".bz2"
        if not os.path.isfile(filename):
            filename = filename.replace(".bz2", ".gz")
        if not os.path.isfile(filename):
            console.warn(f"trace file not found {filename}")
        return filename
