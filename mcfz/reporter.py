"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Optional, Dict, Iterator, NewType, Literal, \
    Final, Union, Any, TypeAlias, cast

import os
import json
from copy import deepcopy
import numpy as np
from elftools.elf.elffile import ELFFile  # type: ignore
from typing_extensions import assert_never
from tqdm import tqdm

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType, TraceEntryArray

if TYPE_CHECKING:
    from .config import Config, ReportVerbosity


# ==================================================================================================
# Local type definitions
# ==================================================================================================
PC = NewType('PC', int)
""" Program Counter, used to identify instructions in the trace. """

TraceFileName = NewType('TraceFileName', str)
""" Name of the trace file, used to link leaks back the trace file they were found in. """

LeakType = Literal['I', 'D']
""" Type of the leak:
    'I' for instruction leaks (e.g., secret dependent branch),
    'D' for data leaks (e.g., secret dependent memory access).
"""

TraceEntryId = NewType('TraceEntryId', int)
""" Entry ID in the original (raw) trace file, used to locate the leak. """

LeakyInstrDType: Final[np.dtype] = np.dtype([
    ('pc', np.uint64),
    ('leak_type', 'U1'),  # 'I' or 'D' as single Unicode character
    ('target_trace_entry_id', np.int64),
    ('ref_trace_entry_id', np.int64),
])
""" Numpy dtype for a leaky instruction:
    * pc: the program counter (PC) of the instruction,
    * leak_type: the type of the leak ('I' or 'D'),
    * target_trace_entry_id: entry ID in the target trace file,
    * ref_trace_entry_id: entry ID in the reference trace file.
"""

LeakyInstrArray: TypeAlias = np.ndarray
""" Array of leaky instructions with dtype LeakyInstrDType. """

LinesInTracePair = NewType('LinesInTracePair', str)
""" A string representing a location of a leak in a trace pair.
    It is in the format "trace_file_name:line_number_in_trace:line_number_in_reference",
    where:
    * trace_file_name is the name of the trace file where
        the leak was found,
    * line_number_in_trace is the line number in the trace file where
        the leak was found,
    * line_number_in_reference is the line number in the reference trace file
        (000.trace, which is the same for all leaks).
"""

LeakageMap = Dict[
    LeakType,
    Dict[
        PC,
        List[LinesInTracePair],
    ],
]
""" Map of leaks found in the traces, indexed by leak type and PC.
    The value is a list of trace file names where the leak was found.
"""

CodeLine = NewType('CodeLine', str)
""" Location of a line in the source code, used to group leaks by code lines.
    It is a string in the format "filename:line_number", where
    * filename is the name of the source file,
    * line_number is the line number in the source file.
"""

LeakageLineMapVrb3 = Dict[
    LeakType,
    Dict[
        CodeLine,
        Dict[
            PC,
            List[LinesInTracePair],
        ],
    ],
]
""" Map of unique leaky lines of code, indexed by leak type and code line.
    The value is a map of PCs where the leak was found, and a list of locations
    where the leak was found in the trace files.
"""

LeakageLineMapVrb2 = Dict[
    LeakType,
    Dict[
        CodeLine,
        List[PC],
    ],
]
""" A variant of LeakageLineMap for the lower verbosity level (verbosity 2). """

LeakageLineMapVrb1 = Dict[
    LeakType,
    List[CodeLine],
]
""" A variant of LeakageLineMap for the lowest verbosity level (verbosity 1). """

LeakageLineMap = Union[
    LeakageLineMapVrb3,
    LeakageLineMapVrb2,
    LeakageLineMapVrb1,
]


# ==================================================================================================
# Classes representing parsed traces and their elements
# ==================================================================================================
TracedInstructionDType: Final[np.dtype] = np.dtype([
    ('pc', np.uint64),  # PC of the instruction
    ('mem_accesses_offset', np.int64),  # Offset in the mem_accesses array
    ('num_mem_accesses', np.int64),  # Number of memory accesses
    ('org_trace_entry_id', np.int64),  # Entry ID in the original (raw) trace
])
TracedInstruction: TypeAlias = np.void


class _Trace:
    """
    A trace of a contract execution, containing a list of instructions executed
    during the execution and their memory accesses.
    """
    file_name: Final[TraceFileName]

    def __init__(self, file_name: str, raw_trace: TraceEntryArray) -> None:
        self.file_name = TraceFileName(file_name)

        # Count the number of instructions and mem. accesses to identify array sizes
        counts = np.bincount(raw_trace['type'], minlength=6)
        num_instructions = counts[TraceEntryType.ENTRY_PC]
        num_mem_accesses = counts[TraceEntryType.ENTRY_READ] + \
            counts[TraceEntryType.ENTRY_WRITE] + counts[TraceEntryType.ENTRY_IND]

        # Pre-allocate arrays for instructions and mem. accesses
        self.instructions = np.zeros(num_instructions, dtype=TracedInstructionDType)
        self.mem_accesses = np.zeros(num_mem_accesses, dtype=np.uint64)

        # Fill in the arrays using vectorized numpy operations
        is_pc = raw_trace['type'] == TraceEntryType.ENTRY_PC
        is_mem = ((raw_trace['type'] == TraceEntryType.ENTRY_READ)
                  | (raw_trace['type'] == TraceEntryType.ENTRY_WRITE)
                  | (raw_trace['type'] == TraceEntryType.ENTRY_IND))

        # Get indices where PCs and mem accesses occur in the raw trace
        pc_indices = np.flatnonzero(is_pc)
        mem_indices = np.flatnonzero(is_mem)

        # Extract instruction PCs and memory accesses directly using boolean indexing
        self.instructions['pc'] = raw_trace['addr'][is_pc]
        self.instructions['org_trace_entry_id'] = pc_indices
        self.mem_accesses = raw_trace['addr'][is_mem]

        # For each PC, find how many mem accesses came before it using searchsorted
        self.instructions['mem_accesses_offset'] = np.searchsorted(mem_indices, pc_indices)

        # num_mem_accesses = next_offset - current_offset
        next_offsets = np.concatenate([
            self.instructions['mem_accesses_offset'][1:],
            [len(self.mem_accesses)]
        ])
        self.instructions['num_mem_accesses'] = next_offsets - \
            self.instructions['mem_accesses_offset']

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self) -> Iterator[np.void]:
        return iter(self.instructions)

    def __getitem__(self, item: int) -> np.void:
        return cast(np.void, self.instructions[item])


# ==================================================================================================
# Trace parsing and leakage analysis
# ==================================================================================================
class _Analyser:
    """
    Class responsible for checking the collected contract traces for violations of the
    non-interference property.
    """
    trace_decoder: TraceDecoder

    def __init__(self) -> None:
        self.trace_decoder = TraceDecoder()

    def build_leakage_map(self, stage3_dir: str) -> LeakageMap:
        """
        Analyse all leaks stored in the given directory after a completed fuzzing campaign.
        """
        leakage_map: LeakageMap = {'I': {}, 'D': {}}
        inputs = self._collect_inputs_to_process(stage3_dir)

        # Initialize a progress bar to track the progress of the analysis
        progress_bar = tqdm(
            total=sum(len(traces) for ref_file, traces in inputs.items()),
            colour='green',
        )

        # Collect traces for each pair and check for leaks
        for reference_trace_file, trace_files in inputs.items():
            reference_trace = self._parse_trace_file(reference_trace_file)

            for trace_file in trace_files:
                progress_bar.update()
                trace = self._parse_trace_file(trace_file)
                leaky_instructions = self._identify_leaks(reference_trace, trace)

                # nothing to do if there are no leaky instructions
                if leaky_instructions.size == 0:
                    continue

                # add the leaky instructions to the global map
                self._update_global_map(leakage_map, leaky_instructions, trace_file)

        progress_bar.close()
        return leakage_map

    def _collect_inputs_to_process(self, stage3_dir: str) -> Dict[str, List[str]]:
        inputs: Dict[str, List[str]] = {}
        input_groups = os.listdir(stage3_dir)
        for input_group in input_groups:
            input_group_dir = os.path.join(stage3_dir, input_group)

            # Get a reference trace for the given group; we will use it to check that
            # all other traces are the same
            reference_trace_file = os.path.join(input_group_dir, "000.trace")
            if not os.path.exists(reference_trace_file):
                # If the reference trace does not exist, skip this group
                continue
            inputs[reference_trace_file] = []

            # Compare the reference trace with all other traces in the group
            for trace_file in os.listdir(input_group_dir):
                # skip non-trace files, the reference trace itself, and the determinism check traces
                if not trace_file.endswith(".trace"):
                    continue
                if "determinism_check_" in trace_file:
                    continue
                trace_file = os.path.join(input_group_dir, trace_file)
                if trace_file == reference_trace_file:
                    continue

                # parse the trace file and extract a list of leaky instructions
                inputs[reference_trace_file].append(trace_file)
        return inputs

    def _parse_trace_file(self, trace_file: str) -> _Trace:
        raw_trace = self.trace_decoder.decode_trace_file(trace_file)
        trace = _Trace(trace_file, raw_trace)
        return trace

    def _identify_leaks(self, ref_trace: _Trace, target_trace: _Trace) -> LeakyInstrArray:
        """
        Check traces for violations of the non-interference property.

        Compares two execution traces and identifies:
        - I-type leaks: PC divergence (secret-dependent control flow)
        - D-type leaks: Memory access divergence (secret-dependent data access)

        FIXME: Rewind to merge point not implemented; stops at first I-type leak.
        """
        end_id = min(len(ref_trace), len(target_trace))
        if end_id == 0:
            return np.array([], dtype=LeakyInstrDType)

        ref_instr = ref_trace.instructions[:end_id]
        tgt_instr = target_trace.instructions[:end_id]

        # Detect I-type leak (PC divergence)
        i_leak, analysis_end = self._find_i_type_leak(ref_instr, tgt_instr, end_id)
        if analysis_end == 0:
            return i_leak

        # Detect D-type leaks (memory access divergence)
        d_leaks = self._find_d_type_leaks(
            ref_trace, target_trace,
            ref_instr[:analysis_end], tgt_instr[:analysis_end]
        )

        return self._combine_arrays(d_leaks, i_leak)

    def _find_i_type_leak(
        self,
        ref_instr: np.ndarray,
        tgt_instr: np.ndarray,
        end_id: int
    ) -> Tuple[LeakyInstrArray, int]:
        """Find first I-type leak (PC divergence) and return analysis boundary."""
        pc_mismatch = ref_instr['pc'] != tgt_instr['pc']
        if not pc_mismatch.any():
            return np.array([], dtype=LeakyInstrDType), end_id

        first_diverge = int(np.argmax(pc_mismatch))
        if first_diverge == 0:
            return np.array([], dtype=LeakyInstrDType), 0  # Can't blame previous instruction

        # The instruction before divergence caused the branch
        prev = ref_instr[first_diverge - 1]
        leak = np.array([(
            prev['pc'], 'I', prev['org_trace_entry_id'], prev['org_trace_entry_id']
        )], dtype=LeakyInstrDType)
        return leak, first_diverge

    def _find_d_type_leaks(
        self,
        ref_trace: _Trace,
        target_trace: _Trace,
        ref_instr: np.ndarray,
        tgt_instr: np.ndarray
    ) -> LeakyInstrArray:
        # Find indices of instructions with memory access differences
        # This can be done fast using numpy bulk operations if the memory access structures match
        fast_path_possible = (
            np.array_equal(ref_instr['mem_accesses_offset'], tgt_instr['mem_accesses_offset'])
            and np.array_equal(ref_instr['num_mem_accesses'], tgt_instr['num_mem_accesses'])
        )
        if fast_path_possible:
            indices = self._find_d_leaks_bulk(ref_trace, target_trace, ref_instr)
        else:
            print("WARNING: slow path for D-leak detection not implemented\nSkipping")
            return np.array([], dtype=LeakyInstrDType)
        if len(indices) == 0:
            return np.array([], dtype=LeakyInstrDType)

        # Build LeakyInstrArray for D-type leaks from instruction indices
        leaks = np.empty(len(indices), dtype=LeakyInstrDType)
        leaks['pc'] = tgt_instr['pc'][indices]
        leaks['leak_type'] = 'D'
        leaks['target_trace_entry_id'] = tgt_instr['org_trace_entry_id'][indices]
        leaks['ref_trace_entry_id'] = ref_instr['org_trace_entry_id'][indices]
        return leaks

    def _find_d_leaks_bulk(
        self,
        ref_trace: _Trace,
        target_trace: _Trace,
        ref_instr: np.ndarray
    ) -> np.ndarray:
        """Find D-leaks via bulk memory comparison (same structure fast path)."""
        mem_end = ref_instr[-1]['mem_accesses_offset'] + ref_instr[-1]['num_mem_accesses']
        mem_diff = ref_trace.mem_accesses[:mem_end] != target_trace.mem_accesses[:mem_end]

        if not mem_diff.any():
            return np.array([], dtype=np.intp)

        # Map differing memory indices back to instruction indices via searchsorted
        diff_indices = np.flatnonzero(mem_diff)
        instr_boundaries = ref_instr['mem_accesses_offset'] + ref_instr['num_mem_accesses']
        leak_indices = np.unique(np.searchsorted(instr_boundaries, diff_indices, side='right'))

        # Filter to valid range with non-zero memory accesses
        valid = (leak_indices < len(ref_instr)) & (ref_instr['num_mem_accesses'][leak_indices] > 0)
        return leak_indices[valid]

    @staticmethod
    def _combine_arrays(*arrays: LeakyInstrArray) -> LeakyInstrArray:
        """Concatenate non-empty arrays."""
        non_empty = [a for a in arrays if len(a) > 0]
        if not non_empty:
            return np.array([], dtype=LeakyInstrDType)
        return np.concatenate(non_empty) if len(non_empty) > 1 else non_empty[0]

    def _update_global_map(self, leakage_map: LeakageMap, leaky_instructions: LeakyInstrArray,
                           source: str) -> None:
        """
        Update the global leakage map with the given address and trace file.
        """
        for leaky_instr in leaky_instructions:
            # Unpack the leaky instruction from numpy structured array
            leak_type: LeakType = leaky_instr['leak_type']
            pc = PC(int(leaky_instr['pc']))
            ref_entry_id = int(leaky_instr['ref_trace_entry_id'])
            tgt_entry_id = int(leaky_instr['target_trace_entry_id'])

            per_type_map = leakage_map[leak_type]

            # If the PC is not in the map, create a new entry
            if pc not in per_type_map:
                per_type_map[pc] = []

            # Create a new leakage location and append it to the map
            leakage_location = LinesInTracePair(f"{source}:{tgt_entry_id}:{ref_entry_id}")
            per_type_map[pc].append(leakage_location)


# ==================================================================================================
# Reporting of the analysis results
# ==================================================================================================


class _HexEncoder(json.JSONEncoder):

    def encode(self, o: Any) -> str:
        if isinstance(o, int):
            return hex(o)
        return super().encode(o)


class _ReportPrinter:
    """
    Class responsible for printing the analysis results to a report file.
    """

    def __init__(self, target_binary: str, config: Config) -> None:
        self._config = config
        with open(target_binary, "rb") as f:
            self._elf_data = ELFFile(f)
            self.dwarf_info = self._elf_data.get_dwarf_info()

    def final_report(self, leakage_map: LeakageMap, report_file: str) -> None:
        """ Print the global map of leaks to the trace log """
        verbosity: ReportVerbosity
        for verbosity in (1, 2, 3):  # type: ignore[assignment]
            leakage_line_map = self._group_by_code_line(leakage_map, verbosity)
            leakage_line_map = self._filter_allowlist(leakage_line_map)
            self._write_report(f"{report_file}.vrb{verbosity}.json", leakage_line_map)

    def _write_report(self, report_file: str, leakage_line_map: LeakageLineMap) -> None:
        """
        Write the report to the given file in a json format:
        {
            "seq": {
                "I": {
                    "file:line": {
                        "0x12345678": ["trace1:10:20", "trace2:15:25"],
                        ...
                    },
                    ...
                },
                "D": {
                    ...
                }
            }
        }
        """
        report_dict = {'seq': leakage_line_map}
        with open(report_file, "w") as f:
            json.dump(report_dict, f, indent=4, sort_keys=True, cls=_HexEncoder)

    def _group_by_code_line(self, leakage_map: LeakageMap,
                            verbosity: ReportVerbosity) -> LeakageLineMap:
        """
        Transform a LeakageMap object into a LeakageLineMap object by
        grouping all instructions that map to the same line in the source code and filtering
        them based on the verbosity level.

        Use DWARF information to get the source code line for each instruction address.

        :param leakage_map: Map of leaks found in the traces, indexed by leak type and PC.
        :param verbosity: Amount of information to include in the report
               (see Config.report_verbosity for details).
        :return: Map of unique leaks, grouped by source code line.
        """
        if verbosity == 1:
            return self._group_by_code_line_vrb1(leakage_map)
        if verbosity == 2:
            return self._group_by_code_line_vrb2(leakage_map)
        if verbosity == 3:
            return self._group_by_code_line_vrb3(leakage_map)
        assert_never(verbosity)

    def _group_by_code_line_vrb3(self, leakage_map: LeakageMap) -> LeakageLineMapVrb3:
        leakage_line_map: LeakageLineMapVrb3 = {'I': {}, 'D': {}}
        for type_ in leakage_map:
            per_type_map = leakage_map[type_]
            for pc in per_type_map:
                # get the source code line for the instruction address
                source_code_line = self._decode_addr(pc)

                # create a new entry in the leakage line map if it does not exist
                if source_code_line not in leakage_line_map[type_]:
                    leakage_line_map[type_][source_code_line] = {}

                # create a new entry for the PC if it does not exist
                if pc not in leakage_line_map[type_][source_code_line]:
                    leakage_line_map[type_][source_code_line][pc] = []

                # append the trace locations to the map
                leakage_line_map[type_][source_code_line][pc].extend(per_type_map[pc])

        return leakage_line_map

    def _group_by_code_line_vrb2(self, leakage_map: LeakageMap) -> LeakageLineMapVrb2:
        leakage_line_map: LeakageLineMapVrb2 = {'I': {}, 'D': {}}
        for type_ in leakage_map:
            per_type_map = leakage_map[type_]
            for pc in per_type_map:
                # get the source code line for the instruction address
                source_code_line = self._decode_addr(pc)

                # create a new entry in the leakage line map if it does not exist
                if source_code_line not in leakage_line_map[type_]:
                    leakage_line_map[type_][source_code_line] = []

                # append the PC to the map
                leakage_line_map[type_][source_code_line].append(pc)
        return leakage_line_map

    def _group_by_code_line_vrb1(self, leakage_map: LeakageMap) -> LeakageLineMapVrb1:
        leakage_line_map: LeakageLineMapVrb1 = {'I': [], 'D': []}
        for type_ in leakage_map:
            per_type_map = leakage_map[type_]
            for pc in per_type_map:
                # get the source code line for the instruction address
                source_code_line = self._decode_addr(pc)

                # append the source code line to the map if it does not exist
                if source_code_line not in leakage_line_map[type_]:
                    leakage_line_map[type_].append(source_code_line)
        return leakage_line_map

    def _filter_allowlist(self, leakage_line_map: LeakageLineMap) -> LeakageLineMap:
        """
        Filter the leakage line map by the allowlist of source code lines.
        The allowlist is a list of source code lines that should be included in the report.
        """
        allowlist_file = self._config.report_allowlist
        if not allowlist_file:
            return leakage_line_map

        # Read the allowlist file and create a set of allowed source code lines
        with open(allowlist_file, "r") as f:
            allowlist_lines = {line.strip() for line in f if line.strip()}

        # Filter the leakage line map by the allowlist
        filtered_leakage_line_map: LeakageLineMap = deepcopy(leakage_line_map)
        for type_ in leakage_line_map:
            per_type_map = leakage_line_map[type_]
            for code_line in per_type_map:
                if code_line in allowlist_lines:
                    filtered_per_type_map = filtered_leakage_line_map[type_]
                    if isinstance(filtered_per_type_map, list):  # Verbosity 1
                        filtered_per_type_map.remove(code_line)
                        continue
                    if isinstance(filtered_per_type_map, dict):  # Verbosity 2 or 3
                        filtered_per_type_map.pop(code_line)

        return filtered_leakage_line_map

    def _decode_addr(self, address: int) -> CodeLine:
        address = address - 0x7ffff20b5000
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self.dwarf_info.iter_CUs():
            # First, look at line programs to find the file/line for the address
            line = self.dwarf_info.line_program_for_CU(CU)
            if not line:
                continue
            delta = 1 if line.header.version < 5 else 0
            prevstate = None
            for entry in line.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = line['file_entry'][prevstate.file - delta].name.decode()
                    line = prevstate.line
                    return CodeLine(f"{filename}:{line}")
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state
        return CodeLine("undefined:0")


# ==================================================================================================
# Public interface to the analysis and reporting module
# ==================================================================================================
class Reporter:
    """
    Class responsible for processing the collected contract traces, detecting leaks exposed in them,
    and building a final report with the results of the analysis.
    """
    _leakage_map: Optional[LeakageMap] = None

    def __init__(self, config: Config) -> None:
        self._config = config

    def analyze(self) -> None:
        """
        Analyze the results of the fuzzing campaign and identify the uncovered
        leaks in the target binary.
        :param target_binary: Path to the target binary
        """
        analyser = _Analyser()
        self._leakage_map = analyser.build_leakage_map(self._config.stage3_wd)

    def generate_report(self, target_binary: str) -> None:
        """
        Generate a report of the analysis.
        """
        assert self._leakage_map is not None, "No leakage map found. Did you run analyze()?"
        report_file = os.path.join(self._config.stage4_wd, "fuzzing_report.json")
        printer = _ReportPrinter(target_binary, self._config)
        printer.final_report(self._leakage_map, report_file)
