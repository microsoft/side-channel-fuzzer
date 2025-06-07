"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Optional, Dict, Iterator, NewType, Literal, \
    Final, Union

import os
import json
from elftools.elf.elffile import ELFFile  # type: ignore
from typing_extensions import assert_never

from .logger import ProgressBar

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

TraceLine = NewType('TraceLine', int)
""" Line number in the trace file, used to locate the leak in the original trace file. """

LeakyInstr = Tuple[PC, LeakType, TraceLine, TraceLine]
""" A tuple representing a leaky instruction:
    * First element is the program counter (PC) of the instruction,
    * Second element is the line number in the trace file where
        the instruction was found,
    * Third element is the line number in the reference trace file
        (private_0.trace, which is the same for all leaks),
    * Fourth element is the type of the leak (see LeakType).
"""

LinesInTracePair = NewType('LinesInTracePair', str)
""" A string representing a location of a leak in a trace pair.
    It is in the format "trace_file_name:line_number_in_trace:line_number_in_reference",
    where:
    * trace_file_name is the name of the trace file where
        the leak was found,
    * line_number_in_trace is the line number in the trace file where
        the leak was found,
    * line_number_in_reference is the line number in the reference trace file
        (private_0.trace, which is the same for all leaks).
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
class _TracedInstruction:
    pc: Final[PC]
    mem_accesses: List[int]
    lit: Final[TraceLine]

    def __init__(self, pc: int, lit: int) -> None:
        self.pc = PC(pc)
        self.mem_accesses = []
        self.lit = TraceLine(lit)

    def __eq__(self, value: object) -> bool:
        assert isinstance(value, _TracedInstruction)
        return self.pc == value.pc and self.mem_accesses == value.mem_accesses


class _Trace:
    """
    A trace of a contract execution, containing a list of instructions executed
    during the execution and their memory accesses.
    """
    file_name: Final[TraceFileName]

    def __init__(self, file_name: str) -> None:
        self.file_name = TraceFileName(file_name)
        self.instructions: List[_TracedInstruction] = []

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self) -> Iterator[_TracedInstruction]:
        return iter(self.instructions)

    def __getitem__(self, item: int) -> _TracedInstruction:
        return self.instructions[item]

    def append(self, instruction: _TracedInstruction) -> None:
        """ Append a new instruction to the trace. """
        self.instructions.append(instruction)


# ==================================================================================================
# Trace parsing and leakage analysis
# ==================================================================================================
class _Analyser:
    """
    Class responsible for checking the collected contract traces for violations of the
    non-interference property.
    """

    def build_leakage_map(self, stage2_dir: str) -> LeakageMap:
        """
        Analyse all leaks stored in the given directory after a completed fuzzing campaign.
        """
        leakage_map: LeakageMap = {'I': {}, 'D': {}}
        input_groups = os.listdir(stage2_dir)

        # Initialize a progress bar to track the progress of the analysis
        progress_bar = ProgressBar(len(input_groups), "Analysis Progress")
        progress_bar.start()

        # Iterate over all input groups
        # (i.e., groups of traces collected from the same public input)
        for input_group in input_groups:
            input_group_dir = os.path.join(stage2_dir, input_group)

            # Get a reference trace for the given group; we will use it to check that
            # all other traces are the same
            reference_trace_file = os.path.join(input_group_dir, "private_0.trace")
            reference_trace = self._parse_trace_file(reference_trace_file)

            # Compare the reference trace with all other traces in the group
            for trace_file in os.listdir(input_group_dir):
                # skip non-trace files and the reference trace itself
                if not trace_file.endswith(".trace"):
                    continue
                if trace_file == "private_0.trace":
                    continue

                # parse the trace file and extract a list of leaky instructions
                trace_file = os.path.join(input_group_dir, trace_file)
                trace = self._parse_trace_file(trace_file)
                leaky_instructions = self._identify_leaks(reference_trace, trace)

                # nothing to do if there are no leaky instructions
                if not leaky_instructions:
                    continue

                # add the leaky instructions to the global map
                self._update_global_map(leakage_map, leaky_instructions, trace_file)

            progress_bar.update()

        return leakage_map

    def _parse_trace_file(self, trace_file: str) -> _Trace:
        trace = _Trace(trace_file)
        with open(trace_file, "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                words = line.split(" ")
                assert len(words) == 3
                type_, val, _ = words
                if type_ == "1":
                    trace.append(_TracedInstruction(int("0x" + val, 16), i + 1))
                if type_ in ["2", "3"]:
                    trace[-1].mem_accesses.append(int("0x" + val, 16))
        return trace

    def _identify_leaks(self, ref_trace: _Trace, target_trace: _Trace) -> List[LeakyInstr]:
        """
        Check the given set of contract traces for violations of the non-interference property
        and return a list of addresses of instructions that violate the property (i.e., are leaky).

        The function walks through the two traces in lockstep, comparing each instruction.
        At each step, three options are possible:
            1. If the PC of the instruction and their memory accesses match,
               then the instruction is not leaky. Move to the next instruction.
            2. If the PC of the instruction matches, but their memory accesses differ,
               then the instruction has a D-type leak. Record it and move to the next instruction.
            3. If the PC of the instruction differs, then the instruction has an I-type leak.
               Record the previous instruction as a leak and rewind to the merge point.
               FIXME: the rewind is not implemented yet; instead, the function terminates after
               the first I-type leak is found.

        :param ref_trace: Reference trace to compare against
        :param trace: Trace to check for leaks
        :return: List of addresses of leaky instructions
        """
        if ref_trace == target_trace:
            return []

        # Initialize the variables to track the leaky instructions and the current entry
        leaky_instructions: List[LeakyInstr] = []
        curr_ref_entry: _TracedInstruction
        curr_tgt_entry: _TracedInstruction
        prev_entry: Optional[_TracedInstruction] = None
        entry_id: int = 0
        end_id: int = min(len(ref_trace), len(target_trace))

        # Iterate through the traces until the end of the shorter trace
        while entry_id < end_id:
            curr_ref_entry = ref_trace[entry_id]
            curr_tgt_entry = target_trace[entry_id]

            # I-type leak: the PC of the instruction differs
            if curr_ref_entry.pc != curr_tgt_entry.pc:
                # Record the previous instruction as a leak
                if prev_entry is not None:
                    leak: LeakyInstr = (prev_entry.pc, 'I', prev_entry.lit, prev_entry.lit)
                    leaky_instructions.append(leak)
                # Rewind to the merge point
                # FIXME: the rewind is not implemented yet; instead, we terminate
                return leaky_instructions

            # D-type leak: the PC of the instruction matches, but memory accesses differ
            if curr_ref_entry.mem_accesses != curr_tgt_entry.mem_accesses:
                # Record the current instruction as a leak
                leak = (curr_tgt_entry.pc, 'D', curr_tgt_entry.lit, curr_ref_entry.lit)
                leaky_instructions.append(leak)

            # Move to the next instruction
            prev_entry = curr_ref_entry
            entry_id += 1

        return leaky_instructions

    def _update_global_map(self, leakage_map: LeakageMap, leaky_instructions: List[LeakyInstr],
                           source: str) -> None:
        """
        Update the global leakage map with the given address and trace file.
        """
        for leaky_instr in leaky_instructions:
            # Unpack the leaky instruction tuple
            per_type_map = leakage_map[leaky_instr[1]]
            pc = leaky_instr[0]
            reference_lit = leaky_instr[2]
            target_lit = leaky_instr[3]

            # If the PC is not in the map, create a new entry
            if pc not in per_type_map:
                per_type_map[pc] = []

            # Create a new leakage location and append it to the map
            leakage_location = LinesInTracePair(f"{source}:{target_lit}:{reference_lit}")
            per_type_map[pc].append(leakage_location)


# ==================================================================================================
# Reporting of the analysis results
# ==================================================================================================
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
        leakage_line_map = self._group_by_code_line(leakage_map, self._config.report_verbosity)
        self._write_report(report_file, leakage_line_map)

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
            json.dump(report_dict, f, indent=4, sort_keys=True)

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

    def _decode_addr(self, address: int) -> CodeLine:
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
        self._leakage_map = analyser.build_leakage_map(self._config.stage2_wd)

    def generate_report(self, target_binary: str) -> None:
        """
        Generate a report of the analysis.
        """
        assert self._leakage_map is not None, "No leakage map found. Did you run analyze()?"
        report_file = os.path.join(self._config.stage3_wd, "fuzzing_report.json")
        printer = _ReportPrinter(target_binary, self._config)
        printer.final_report(self._leakage_map, report_file)
