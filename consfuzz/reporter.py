"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Set, Tuple, Optional, Dict

import os
from elftools.elf.elffile import ELFFile  # type: ignore

from .logger import ProgressBar

if TYPE_CHECKING:
    from .config import Config

PC = int
LeakageMap = Dict[PC, List[str]]


class _TracedInstruction:
    address: PC = 0
    mem_accesses: List[int]
    loc: int

    def __init__(self, addr: int, loc: int) -> None:
        self.address = addr
        self.mem_accesses = []
        self.loc = loc

    def __eq__(self, value: object) -> bool:
        assert isinstance(value, _TracedInstruction)
        return self.address == value.address and self.mem_accesses == value.mem_accesses


class _Trace:
    """
    A trace of a contract execution, containing a list of instructions executed
    during the execution and their memory accesses.
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self.instructions: List[_TracedInstruction] = []

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self):
        return iter(self.instructions)

    def __getitem__(self, item: int) -> _TracedInstruction:
        return self.instructions[item]

    def append(self, instruction: _TracedInstruction) -> None:
        """ Append a new instruction to the trace. """
        self.instructions.append(instruction)


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
        self._leakage_map = analyser.analyze(self._config.stage2_wd)

    def generate_report(self, target_binary: str) -> None:
        """
        Generate a report of the analysis.
        """
        assert self._leakage_map is not None, "No leakage map found. Did you run analyze()?"
        report_file = os.path.join(self._config.stage3_wd, "fuzzing_report.md")
        printer = _ReportPrinter(target_binary)
        printer.final_report(self._leakage_map, report_file)


class _Analyser:
    """
    Class responsible for checking the collected contract traces for violations of the
    non-interference property.
    """

    def analyze(self, stage2_dir: str) -> LeakageMap:
        """
        Analyse all leaks stored in the given directory after a completed fuzzing campaign.
        """
        leakage_map: LeakageMap = {}
        input_groups = os.listdir(stage2_dir)

        # Initialize a progress bar to track the progress of the analysis
        progress_bar = ProgressBar(len(input_groups), "Analysis Progress")
        progress_bar.start()

        for input_group in input_groups:
            input_group_dir = os.path.join(stage2_dir, input_group)

            # Get a reference trace for the given group; we will use it to check that
            # all other traces are the same
            reference_trace_file = os.path.join(input_group_dir, "private_0.trace")
            reference_trace = self._parse_trace_file(reference_trace_file)

            # Compare the reference trace with all other traces in the group
            for trace_file in os.listdir(input_group_dir):
                if not trace_file.endswith(".trace"):
                    continue
                if trace_file == "private_0.trace":
                    continue
                trace_file = os.path.join(input_group_dir, trace_file)
                trace = self._parse_trace_file(trace_file)
                leaky_instr = self.check(reference_trace, trace)
                if not leaky_instr:
                    continue

                # add the leaky instructions to the global map
                for addr in leaky_instr:
                    if addr not in leakage_map:
                        leakage_map[addr] = []
                    leakage_map[addr].append(trace_file)

            progress_bar.update()

        return leakage_map

    def check(self, trace1: _Trace, trace2: _Trace) -> List[PC]:
        """
        Check the given set of contract traces for violations of the non-interference property.
        """
        if trace1 == trace2:
            return []

        if len(trace1) != len(trace2):
            return []  # Different length traces are not supported yet

        leaky_instr = self._process_same_length(trace1, trace2)
        return leaky_instr

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

    def _process_same_length(self, trace1: _Trace, trace2: _Trace) -> List[int]:
        assert len(trace1) == len(trace2)

        # identify leaky instructions
        leaky_instr: List[int] = []
        for i, trace1_entry in enumerate(trace1):
            trace2_entry = trace2[i]
            if trace1_entry != trace2_entry:
                leaky_instr.append(trace1_entry.address)
        leaky_instr = list(set(leaky_instr))
        return leaky_instr

    def _process_different_length(self, trace1: _Trace, trace2: _Trace) -> List[int]:
        raise NotImplementedError("Processing different length traces is not implemented yet: "
                                  f"{trace1.source} and {trace2.source}")
        # assert len(trace1) != len(trace2)

        # leaky_instr: List[int] = []
        # prev_instr_addr: int = 0

        # i1 = 0
        # i2 = 0
        # while i1 < len(trace1) and i2 < len(trace2):
        #     trace_entry1 = trace1[i1]
        #     trace_entry2 = trace2[i2]

        #     # entries match -> no leak
        #     if trace_entry1 == trace_entry2:
        #         prev_instr_addr = trace_entry1.address
        #         i1 += 1
        #         i2 += 1
        #         continue

        #     # addresses match, but memory accesses differ -> memory-based leak
        #     if trace_entry1.address == trace_entry2.address:
        #         leaky_instr.append(trace_entry1.address)
        #         prev_instr_addr = trace_entry1.address
        #         i1 += 1
        #         i2 += 1
        #         continue

        #     # addresses differ -> control flow divergence; record the previous instruction
        #     # as a leak and rewind to the merge point
        #     leaky_instr.append(prev_instr_addr)
        #     break
        #     # FIXME: this part is under construction
        #     # print("l", trace_entry1.loc, trace_entry2.loc, hex(prev_instr_addr))
        #     merge_point1, merge_point2 = self._find_merge_point(i1, i2, trace1, trace2)
        #     print("f", trace1[merge_point1].loc, trace2[merge_point2].loc,
        #           hex(trace1[merge_point1].address), hex(trace2[merge_point2].address))
        #     if merge_point1 == 0 and merge_point2 == 0:
        #         break  # no merge point found
        #     i1 = merge_point1
        #     i2 = merge_point2
        #     assert trace1[merge_point1].address == trace2[merge_point2].address

        # return leaky_instr


class _ReportPrinter:
    """
    Class responsible for printing the report of the analysis.
    """

    def __init__(self, target_binary: str) -> None:
        with open(target_binary, "rb") as f:
            self._elf_data = ELFFile(f)
            self.dwarf_info = self._elf_data.get_dwarf_info()

    def final_report(self, leakage_map: LeakageMap, report_file: str) -> None:
        """ Print the global map of leaks to the trace log """
        # build a map of unique leaky lines of code
        leaky_lines: Dict[str, Set[int]] = {}
        for addr in leakage_map:
            filename, line = self._decode_addr(addr)
            if filename is not None:
                key = f"{filename}:{line}"
            else:
                key = "unknown"
            if key not in leaky_lines:
                leaky_lines[key] = set()
            leaky_lines[key].add(addr)

        # write the report in a markdown table format:
        # | File:Line | Leaky addresses |
        # ( 20 char) | (60 char)
        with open(report_file, "w") as f:
            f.write(f"| {'File:Line':18} | {'Leaky addresses':58} |\n")
            f.write("|" + "-" * 20 + "|" + "-" * 60 + "|\n")
            for loc, addresses in sorted(leaky_lines.items(), key=lambda x: x[0]):
                f.write(f"| {loc:20} | ")
                for addr in addresses:
                    f.write(f"0x{addr:x}, ")
                f.write("|\n")

    def _decode_addr(self, address: int) -> Tuple[Optional[str], Optional[int]]:
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
                    return filename, line
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
        return None, None
