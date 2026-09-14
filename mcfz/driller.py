"""
File: Module responsible for helping to "drill down" into specific findings from fuzzing;
      It allows users to deeply investigate specific program points of interest.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import re
import json
import shutil
import tempfile
import textwrap

from dataclasses import dataclass, field
from typing import Any, Dict, Final, List, Literal, Tuple, Optional

import numpy as np
import numpy.typing as npt

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType

from .leak_detector import PC, FileName
from .reporter import CodeLine
from .config import Config
from .util import console, gdb
from .util.compressor import Compressor
from .util.gdb import DebugScriptBuilder, GdbScriptBuilder

# ==================================================================================================
# Data Types
# ==================================================================================================

TracedInstructionDType: Final[np.dtype[np.void]] = np.dtype([
    ('pc', np.uint64),  # PC of the instruction
    ('spec_level', np.uint8),  # Level of nested speculation (0 = architectural)
    ('org_trace_entry_id', np.int32),  # Entry ID in the original (raw) trace
])

# Width of the section-header rules in the `details` report.
_SECTION_WIDTH: Final[int] = 78

# General-purpose registers (plus flags) compared between the two executions at the leak.
_DIFF_REGS: Final[List[str]] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "eflags"
]

# x86 EFLAGS bits relevant to conditional branches (constant-time analysis).
_EFLAGS_BITS: Final[List[Tuple[str, int]]] = [("CF", 0), ("PF", 2), ("AF", 4), ("ZF", 6), ("SF", 7),
                                              ("OF", 11)]

# Maps a conditional-jump mnemonic to the EFLAGS bits whose values its condition reads.
_JCC_FLAGS: Final[Dict[str, List[str]]] = {
    "je": ["ZF"],
    "jz": ["ZF"],
    "jne": ["ZF"],
    "jnz": ["ZF"],
    "ja": ["CF", "ZF"],
    "jnbe": ["CF", "ZF"],
    "jbe": ["CF", "ZF"],
    "jna": ["CF", "ZF"],
    "jae": ["CF"],
    "jnb": ["CF"],
    "jnc": ["CF"],
    "jb": ["CF"],
    "jc": ["CF"],
    "jnae": ["CF"],
    "jg": ["ZF", "SF", "OF"],
    "jnle": ["ZF", "SF", "OF"],
    "jle": ["ZF", "SF", "OF"],
    "jng": ["ZF", "SF", "OF"],
    "jge": ["SF", "OF"],
    "jnl": ["SF", "OF"],
    "jl": ["SF", "OF"],
    "jnge": ["SF", "OF"],
    "js": ["SF"],
    "jns": ["SF"],
    "jo": ["OF"],
    "jno": ["OF"],
    "jp": ["PF"],
    "jpe": ["PF"],
    "jnp": ["PF"],
    "jpo": ["PF"]
}

# Outcome of capturing one piece of evidence about a leak.
# "not_applicable": the evidence does not apply to this kind of leak.
# "stale_address": gdb never reached the leak; the recorded address is likely stale.
_CaptureStatus = Literal["ok", "not_applicable", "stale_address", "failed"]


# ==================================================================================================
# Data-focused Classes
# ==================================================================================================
@dataclass
class _SpecWinInfo:
    """ Information about a speculation window related to a leak """
    start_pc: PC = PC(0)
    start_pc_gdb: int = 0

    pc: PC = PC(0)
    trace_line_id: int = 0
    pc_gdb: int = 0
    pc_occurrence: int = 0


@dataclass
class _RunState:
    """ Captured execution state at the leak instruction for a single input """
    regs: Dict[str, int]
    next_pc: int


@dataclass
class _StaticContext:
    """ Disassembly and source listing at the leak instruction """
    status: _CaptureStatus = "failed"
    disasm: str = ""
    source: List[str] = field(default_factory=list)


@dataclass
class _ExecDiff:
    """ Execution states at the leak, for the reference and the target input """
    status: _CaptureStatus = "failed"
    ref: Optional[_RunState] = None
    tgt: Optional[_RunState] = None


@dataclass
class _Backtrace:
    """ Call stack at the leak site """
    status: _CaptureStatus = "failed"
    frames: List[str] = field(default_factory=list)


def _extract_instructions(trace_path: FileName) -> npt.NDArray[np.void]:
    """
    Extract PC entries with their speculation levels and original raw-trace indices.

    Raw indices preserve report locations when non-PC events are filtered out. ENTRY_PC and
    spec_level follow the trace format in rvzr/model_dynamorio/backend/include/types/trace.hpp.
    """
    raw_trace = TraceDecoder().decode_trace_file(str(trace_path))
    pc_indices = np.flatnonzero(raw_trace['type'] == TraceEntryType.ENTRY_PC)
    assert len(pc_indices) == 0 or pc_indices[-1] < 2 ** 31, \
        "Raw trace index too large for int32 offsets; trace parsing would need adjustment"

    instructions = np.zeros(len(pc_indices), dtype=TracedInstructionDType)
    instructions['pc'] = raw_trace['addr'][pc_indices]
    instructions['spec_level'] = raw_trace['spec_level'][pc_indices]
    instructions['org_trace_entry_id'] = pc_indices
    return instructions


class _LeakInfo:
    # pylint: disable=too-many-instance-attributes  # justification: data container class

    def __init__(self, clause_type: str, leak_type: str, code_line: str, pc_hex: str,
                 trace_path: str, trace_line_id: int) -> None:
        # original info from the report
        self.clause_type = clause_type
        self.leak_type = leak_type
        self.code_line = CodeLine(code_line)
        self.org_pc = PC(int(pc_hex, 16))

        self.org_trace_path = FileName(trace_path)
        self.org_trace_line_id = int(trace_line_id)

        # spec windows info
        self.spec_windows: List[_SpecWinInfo] = []

        # set later
        self.bin_path = FileName("")
        self.input_path: FileName = FileName('')
        self.trace_path: FileName = FileName('')
        self.org_template_cmd: List[str] = []

        # evidence collected by the `Driller`, rendered by the `_DrillerInterface`
        self.debug_script_path: FileName = FileName('')
        self.static_context = _StaticContext()
        self.exec_diff = _ExecDiff()
        self.backtrace = _Backtrace()

    @property
    def org_input_path(self) -> FileName:
        """ Compute the input file path from the trace path """
        trace_dir = os.path.dirname(self.org_trace_path)
        trace_file: str = os.path.basename(self.org_trace_path)

        input_dir = trace_dir.replace('stage3', 'stage2')
        input_file = trace_file.removesuffix('.bz2').removesuffix('.gz')
        input_file = input_file.replace('.trace', '.bin')
        return FileName(os.path.join(input_dir, input_file))

    def driver_cmd(self, input_path: str) -> List[str]:
        """ Build the driver invocation: the binary followed by the template arguments with the
        `@@` placeholder replaced by the given input path """
        return [self.bin_path] + \
            [arg.replace('@@', input_path) for arg in self.org_template_cmd[1:]]

    def build_gdb_cmd(self,
                      fast: bool = False,
                      single_step: bool = False,
                      ignored_cond: Optional[str] = None) -> None:
        """
        Generate a debug shell script that opens two gdb sessions in tmux, and store its path
        in `debug_script_path`.

        :param fast: If True, skip intermediate gdb prompts
        :param single_step: If True, drop to interactive gdb at first speculative instruction
        :param ignored_cond: gdb condition restricting breakpoint hits to non-ignored contexts
        """
        assert self.org_template_cmd, "Original template command not set."
        output_dir = os.path.dirname(self.input_path)
        self.debug_script_path = FileName(
            DebugScriptBuilder.build(
                self, output_dir, fast=fast, single_step=single_step, ignored_cond=ignored_cond))


# ==================================================================================================
# User-facing report rendering
# ==================================================================================================
class _DrillerInterface:
    """ Renders and prints the user-facing `details` report for a single leak """

    def __init__(self, leak_info: _LeakInfo) -> None:
        self.leak_info = leak_info

    # ==============================================================================================
    # Report assembly
    def print_report(self) -> None:
        """ Print a human-readable report of the leak, with evidence collected by the `Driller` """
        leak = self.leak_info
        out: List[str] = [self._section("VIOLATION")]
        kind = console.paint(self._headline, console.BOLD, console.RED)
        tag = console.paint(f"{leak.leak_type}-type \u00b7 {leak.clause_type}", console.DIM)
        out.append(f"  {kind}   {tag}")
        out.append(f"  {console.paint('Source ', console.DIM)}  "
                   f"{console.paint(str(leak.code_line), console.DIM)}")

        # The same instruction has two addresses: the trace address (recorded during tracing and
        # passed to `--pc`) and the runtime address it relocates to when re-loaded under gdb with
        # ASLR disabled. Show both so the reader can map between the report and a gdb session.
        gdb_pc = leak.spec_windows[-1].pc_gdb if leak.spec_windows else 0
        addr_line = (f"  {console.paint('Address', console.DIM)}  {leak.org_pc:#x} "
                     f"{console.paint('(trace, the --pc value)', console.DIM)}")
        if gdb_pc:
            addr_line += (f" \u2192 {gdb_pc:#x} "
                          f"{console.paint('(gdb runtime, ASLR off)', console.DIM)}")
        out.append(addr_line)
        out.append("")
        out += [console.paint(line, console.DIM) for line in self._wrap_indented(self._diagnosis)]

        location_text = self._render_static_context()
        if location_text:
            out += ["", self._section("LOCATION"), location_text]

        spec_block = self._render_spec_path()
        if spec_block:
            out += ["", self._section("SPECULATION PATH"), spec_block]

        out += ["", self._section("WHY IT LEAKS"), self._render_exec_diff()]
        out += ["", self._section("CALL STACK"), self._render_backtrace()]

        out += [
            "",
            self._section("REPRODUCE"),
            console.paint("  Two gdb sessions side-by-side in tmux (requires tmux):", console.DIM),
            f"  {console.paint(str(leak.debug_script_path), console.BOLD)}",
        ]

        out += [
            "",
            self._section("ARTIFACTS"),
            f"  {'Input':<6} {console.paint(str(leak.org_input_path), console.DIM)}",
            f"  {'Trace':<6} {console.paint(str(leak.org_trace_path), console.DIM)} "
            f"{console.paint(f'(line {leak.org_trace_line_id})', console.DIM)}",
        ]

        print("\n".join(out) + "\n")

    @staticmethod
    def _section(title: str) -> str:
        rule = "\u2500" * max(0, _SECTION_WIDTH - len(title) - 4)
        return (console.paint(f"\u2501\u2501 {title} ", console.BOLD, console.CYAN)
                + console.paint(rule, console.CYAN))

    @staticmethod
    def _wrap_indented(text: str, indent: str = "  ", width: int = 80) -> List[str]:
        return textwrap.wrap(
            text, width=width, initial_indent=indent,
            subsequent_indent=indent) or [indent.rstrip()]

    @property
    def _headline(self) -> str:
        if self.leak_info.leak_type == 'I':
            return "Secret-dependent branch"
        return "Secret-dependent memory access"

    @property
    def _diagnosis(self) -> str:
        if self.leak_info.leak_type == 'I':
            text = ("The branch outcome (and thus control flow) depends on a secret, "
                    "violating constant-time execution.")
        else:
            text = ("The address of a load/store depends on a secret, "
                    "violating constant-time execution.")
        if self.leak_info.clause_type != 'seq':
            text += " The leak is exposed only under speculative execution."
        return text

    def _render_spec_path(self) -> str:
        """
        Render the nested speculation-window tree for a speculative leak. Returns an empty string
        for architectural (single-window) leaks, whose PC and trace line already appear elsewhere.
        """
        spec_windows = self.leak_info.spec_windows
        if len(spec_windows) <= 1:
            return ""

        lines: List[str] = []
        last_lvl = len(spec_windows) - 1
        for lvl, win in enumerate(spec_windows):
            prefix = "    " * lvl
            if lvl == 0:
                lines.append(f"  Architectural execution starts at pc "
                             f"{console.paint(f'{win.start_pc:#x}', console.DIM)}:")
            else:
                lines.append(f"  {prefix}\u251c\u2500\u2500 Start of spec window at PC "
                             f"{console.paint(f'{win.start_pc:#x}', console.DIM)}:")

            if lvl == last_lvl:
                tag = console.paint("LEAK!", console.BOLD, console.RED)
                lines.append(f"  {prefix}\u2514\u2500\u2500 {tag} At line {win.trace_line_id} "
                             f"(PC: {win.pc:#x})")
            else:
                tag = console.paint("MISPREDICTION", console.BOLD, console.YELLOW)
                lines.append(f"  {prefix}\u2514\u2500\u2500 {tag} at line {win.trace_line_id} "
                             f"(PC: {win.pc:#x})")
        return "\n".join(lines)

    def _render_stale_address(self, feature: str) -> str:
        """
        Build an explanatory message for the case where the program never reached the leak
        instruction under gdb, so ``feature`` (e.g. "Execution diff") could not be captured.

        :param feature: Human-readable name of the report section that is unavailable
        :return: A rendered explanation of the likely address mismatch
        """
        win = self.leak_info.spec_windows[-1]
        lines = [
            f"  {feature} unavailable: the program ran to completion without ever stopping at the",
            "  leak instruction. gdb placed a breakpoint at the recorded address",
            f"  {win.pc_gdb:#x} (trace pc {self.leak_info.org_pc:#x}), "
            "but execution never reached it.", "",
            "  Possible reason: the binary was recompiled or otherwise changed",
            "  since the trace was recorded, leading to a stale leak address.",
            "  Re-run the fuzzer or patch the PC manually."
        ]
        return "\n".join(console.paint(line, console.DIM) for line in lines)

    # ==============================================================================================
    # Leak location
    def _render_static_context(self) -> str:
        """
        Render the leak instruction and source listing into a "Leak Location" block.
        Returns an empty string when nothing was captured, so the section is omitted.
        """
        ctx = self.leak_info.static_context
        if ctx.status != "ok":
            return ""

        leak_line = str(self.leak_info.code_line).rsplit(":", 1)[-1]
        out: List[str] = []
        if ctx.disasm:
            out.append(f"  {console.paint('Instruction', console.DIM)}  {ctx.disasm}")
        if ctx.source:
            out.append(f"  {console.paint(f'Source ({self.leak_info.code_line})', console.DIM)}")
            for src in ctx.source:
                tokens = src.split()
                line_no = tokens[0] if tokens else ""
                body = src.strip().expandtabs(4)
                if line_no == leak_line:
                    marker = console.paint("\u25b6", console.BOLD, console.RED)
                    out.append(f"    {marker} {console.paint(body, console.BOLD)}")
                else:
                    out.append(f"      {console.paint(body, console.DIM)}")

        return "\n".join(out)

    # ==============================================================================================
    # Execution diff
    def _render_exec_diff(self) -> str:
        """ Render a human-readable diff of the two execution states captured at the leak """
        diff = self.leak_info.exec_diff
        if diff.status == "not_applicable":
            return ("  Execution diff is only available for architectural (seq) leaks; "
                    "this leak occurs under speculation.")
        if diff.status == "stale_address":
            return self._render_stale_address("Execution diff")
        if diff.status != "ok":
            return "  Execution diff unavailable (could not capture state under gdb)."
        assert diff.ref is not None and diff.tgt is not None
        ref, tgt = diff.ref, diff.tgt

        is_branch = self.leak_info.leak_type == 'I'
        ref_tag = console.paint("reference", console.CYAN)
        tgt_tag = console.paint("target", console.YELLOW)
        lines: List[str] = [
            console.paint(f"  Legend: {ref_tag} input vs {tgt_tag} input", console.DIM)
        ]
        if is_branch:
            lines += self._render_branch_diff(ref, tgt)
        lines += self._render_reg_diffs(ref, tgt, is_branch)
        return "\n".join(lines)

    @staticmethod
    def _render_reg_diffs(ref: _RunState, tgt: _RunState, is_branch: bool) -> List[str]:
        """ Render the general-purpose registers whose values differ between the two executions """
        # For a branch leak the deciding flags are reported separately, so eflags is excluded here
        # to keep the "data" registers distinct.
        skip = {'eflags'} if is_branch else set()
        reg_diffs = [(name, ref.regs[name], tgt.regs[name])
                     for name in _DIFF_REGS
                     if name not in skip and name in ref.regs and name in tgt.regs
                     and ref.regs[name] != tgt.regs[name]]
        if not reg_diffs:
            if is_branch:
                return []
            return ["  No tracked register values differ at the leak instruction."]

        header = ("  Registers feeding the condition that diverge:"
                  if is_branch else "  Diverging registers:")
        lines = [header]
        for name, ref_val, tgt_val in reg_diffs:
            ref_s = console.paint(f"{ref_val:#018x}", console.CYAN)
            tgt_s = console.paint(f"{tgt_val:#018x}", console.YELLOW)
            lines.append(f"    {name:<6} {ref_s}  \u2192  {tgt_s}")
        return lines

    def _render_branch_diff(self, ref: _RunState, tgt: _RunState) -> List[str]:
        """ Render the control-flow, branch-target, and deciding-flag detail for an I-type leak """
        disasm = self.leak_info.static_context.disasm
        taken_target = self._parse_branch_target(disasm)

        def direction(state: _RunState) -> str:
            if taken_target is not None:
                return "branch taken" if state.next_pc == taken_target else "fall-through"
            return f"next pc {state.next_pc:#x}"

        if ref.next_pc != tgt.next_pc:
            lines = [
                console.paint("  Control flow diverges:", console.BOLD, console.RED),
                f"    {console.paint('reference', console.CYAN)}  \u2192  {direction(ref)}",
                f"    {console.paint('target', console.YELLOW)}     \u2192  {direction(tgt)}",
            ]
        else:
            lines = [f"  Control flow converges (both {direction(ref)})"]

        lines += self._render_branch_targets(ref, tgt, disasm, taken_target)
        lines += self._render_deciding_flags(ref, tgt, disasm)
        return lines

    def _render_branch_targets(self, ref: _RunState, tgt: _RunState, disasm: str,
                               taken_target: Optional[int]) -> List[str]:
        """ Render the taken/fall-through targets, annotated with which input reaches each """
        if taken_target is None:
            return []

        def who(pc: int) -> str:
            names = []
            if ref.next_pc == pc:
                names.append(console.paint("reference", console.CYAN))
            if tgt.next_pc == pc:
                names.append(console.paint("target", console.YELLOW))
            return f"({', '.join(names)})" if names else ""

        taken_sym = self._parse_branch_target_sym(disasm)
        taken_str = f"{taken_target:#x}" + (f" {taken_sym}" if taken_sym else "")

        lines = ["  Branch targets:", f"    {'taken':<13}\u2192 {taken_str}   {who(taken_target)}"]
        fall_through = next((pc for pc in (ref.next_pc, tgt.next_pc) if pc != taken_target), None)
        if fall_through is not None:
            lines.append(f"    {'fall-through':<13}\u2192 {fall_through:#x}   {who(fall_through)}")
        return lines

    def _render_deciding_flags(self, ref: _RunState, tgt: _RunState, disasm: str) -> List[str]:
        """ Identify which EFLAGS bits the branch condition reads and which of them differ """

        def decode_eflags(value: int) -> Dict[str, int]:
            return {name: (value >> bit) & 1 for name, bit in _EFLAGS_BITS}

        mnem = self._branch_mnemonic(disasm)
        tested = _JCC_FLAGS.get(mnem)
        if not tested or 'eflags' not in ref.regs or 'eflags' not in tgt.regs:
            return []

        ref_flags = decode_eflags(ref.regs['eflags'])
        tgt_flags = decode_eflags(tgt.regs['eflags'])
        deciding = [f for f in tested if ref_flags[f] != tgt_flags[f]]
        if not deciding:
            return [f"  Branch {mnem} tests {', '.join(tested)} (none of them differ here)."]

        lines = [f"  Branch {mnem} tests {', '.join(tested)}; deciding flag(s) that differ:"]
        for flag in deciding:
            ref_s = console.paint(f"reference={ref_flags[flag]}", console.CYAN)
            tgt_s = console.paint(f"target={tgt_flags[flag]}", console.YELLOW)
            lines.append(f"    {flag}  {ref_s}  \u2192  {tgt_s}")
        return lines

    @staticmethod
    def _parse_branch_target(disasm: str) -> Optional[int]:
        """ Extract the jump-target address from a disassembled direct branch instruction """
        # disasm looks like "=> 0x<pc> <sym>:\t<mnemonic> 0x<target> <sym>"; the first address
        # is the branch PC, the second is its target.
        addresses = re.findall(r'0x[0-9a-fA-F]+', disasm)
        if len(addresses) >= 2:
            return int(addresses[1], 16)
        return None

    @staticmethod
    def _parse_branch_target_sym(disasm: str) -> str:
        """ Extract the trailing ``<symbol+off>`` annotation of a direct branch's target """
        match = re.search(r'(<[^>]+>)\s*$', disasm)
        return match.group(1) if match else ""

    @staticmethod
    def _branch_mnemonic(disasm: str) -> str:
        """ Extract the (lowercased) mnemonic from a disassembled branch instruction """
        after_colon = disasm.split(":", 1)[-1]
        tokens = after_colon.split()
        return tokens[0].lower() if tokens else ""

    # ==============================================================================================
    # Call stack
    def _render_backtrace(self) -> str:
        """ Render the captured call stack, prefixed with a note on where it was captured """
        backtrace = self.leak_info.backtrace
        if backtrace.status == "stale_address":
            return self._render_stale_address("Backtrace")
        if backtrace.status != "ok":
            return "  Backtrace unavailable (could not capture call stack under gdb)."

        win = self.leak_info.spec_windows[0]
        if len(self.leak_info.spec_windows) > 1:
            note = (f"  Captured at the spec-window start (trace pc {win.pc:#x}); "
                    f"the leak is reached speculatively from here.")
        else:
            note = f"  Captured at the leak instruction (trace pc {win.pc:#x})."
        return "\n".join([console.paint(note, console.DIM)]
                         + self._format_backtrace(backtrace.frames))

    def _format_backtrace(self, frames: List[str]) -> List[str]:
        """ Condense raw gdb frames into aligned ``#N  function   file:line`` lines """
        parsed = [self._condense_frame(f) for f in frames]
        func_w = max((len(func) for _, func, _ in parsed), default=0)
        out: List[str] = []
        for i, (idx, func, loc) in enumerate(parsed):
            idx_s = console.paint(f"{idx:<4}", console.DIM)
            func_s = console.paint(func, console.BOLD) if i == 0 else func
            loc_s = console.paint(loc, console.DIM) if loc else ""
            pad = " " * (func_w - len(func))
            out.append(f"  {idx_s} {func_s}{pad}   {loc_s}".rstrip())
        return out

    @staticmethod
    def _condense_frame(frame: str) -> Tuple[str, str, str]:
        """
        Split a raw gdb backtrace frame into its ``(index, function, location)`` parts, dropping
        the verbose argument list and absolute path that make raw frames wrap.
        """
        idx_match = re.match(r'(#\d+)\s+', frame)
        idx = idx_match.group(1) if idx_match else "#?"
        rest = frame[idx_match.end():] if idx_match else frame
        # Drop a leading "0x... in " address prefix, if present
        rest = re.sub(r'^0x[0-9a-fA-F]+\s+in\s+', '', rest)
        # The function name is everything up to the first " (" argument list
        func_match = re.match(r'([^\s(]+)', rest)
        func = func_match.group(1) if func_match else "??"
        # The source location follows " at " near the end of the frame
        loc_match = re.search(r'\sat\s+(\S+)', frame)
        loc = os.path.basename(loc_match.group(1)) if loc_match else ""
        return idx, func, loc


# ==================================================================================================
# Driller logic
# ==================================================================================================
class Driller:
    """ Investigates specific findings from fuzzing by drilling down into violations """

    def __init__(self,
                 config: Config,
                 output_dir: str,
                 fast: bool = False,
                 single_step: bool = False,
                 keep_trace: bool = False) -> None:
        self._config = config
        self._output_dir = output_dir
        self._fast = fast
        self._single_step = single_step
        self._keep_trace = keep_trace
        self._trace_tmpdir: Optional[str] = None
        assert config.bin_native is not None  # enforced by config validation
        self._target_bin = config.bin_native
        self._template_cmd = [config.bin_native if s == "@#" else s for s in config.template_cmd]
        self._ignored_funcs: List[str] = self._load_ignored_funcs()

    def _load_ignored_funcs(self) -> List[str]:
        """ Load the ignored function symbols from the tracing ignorelist, if configured """
        path = self._config.tracing_ignorelist
        if not path or not os.path.exists(path):
            return []
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def _ignored_caller_expression(self) -> Optional[str]:
        """
        Build a gdb condition expression that holds only when the leak instruction is reached
        *outside* any ignored function. Applied to the leak breakpoints of both the batch
        captures and the generated debug script.

        :return: The condition expression, or ``None`` when no functions are ignored
        """
        if not self._ignored_funcs:
            return None
        pattern = "^(" + "|".join(re.escape(fn) for fn in self._ignored_funcs) + ")$"
        return f'!$_any_caller_matches("{pattern}", 64)'

    def drill_down(self, pc: int) -> None:
        """
        Drill down into a specific violation detected by the fuzzer,
        identified by its program counter (PC).
        :param pc: The program counter to investigate
        """
        self._check_required_files()

        pc_hex = hex(pc)

        # Search for the PC in the report
        with open(os.path.join(self._config.stage4_wd, "report_verbosity_3.json"), 'r') as f:
            report_data = json.load(f)
        leak_info = self._find_pc_in_report(report_data, pc_hex)

        # Populate additional fields in leak_info
        self._copy_files(leak_info)
        leak_info.spec_windows = self._find_spec_windows(leak_info)
        for spec_win in leak_info.spec_windows:
            spec_win.start_pc_gdb = self._translate_pc_to_gdb(spec_win.start_pc)
            spec_win.pc_gdb = self._translate_pc_to_gdb(spec_win.pc)

        # The decompressed trace is no longer needed once speculation windows are known
        self._cleanup_trace_tmp()

        # Collect the evidence about the leak
        leak_info.build_gdb_cmd(
            fast=self._fast,
            single_step=self._single_step,
            ignored_cond=self._ignored_caller_expression())
        leak_info.static_context = self._capture_static_context(leak_info)
        leak_info.exec_diff = self._capture_exec_diff(leak_info)
        leak_info.backtrace = self._capture_backtrace(leak_info)

        # Pretty print the details
        _DrillerInterface(leak_info).print_report()

    def _cleanup_trace_tmp(self) -> None:
        """ Remove the temporary decompressed trace directory, if one was created """
        if self._trace_tmpdir:
            shutil.rmtree(self._trace_tmpdir, ignore_errors=True)
            self._trace_tmpdir = None

    def _check_required_files(self) -> None:
        stag3_dir: str = self._config.stage3_wd
        if not os.path.isdir(stag3_dir):
            raise FileNotFoundError(f"Stage 3 working directory not found: {stag3_dir}.")
        if not os.path.exists(os.path.join(stag3_dir, "mappings.txt")):
            raise FileNotFoundError(f"Required file 'mappings.txt' not found in {stag3_dir}.")

        report_file = os.path.join(self._config.stage4_wd, "report_verbosity_3.json")
        if not os.path.exists(report_file):
            raise FileNotFoundError(f"Report file not found: {report_file}.")

    def _find_pc_in_report(self, report_data: Dict[str, Any], pc_hex: str) -> _LeakInfo:
        # Search the flat list of leak records for one whose witnesses include this PC
        for leak in report_data.get("leaks", []):
            witnesses = leak.get("witnesses", {})
            if pc_hex not in witnesses:
                continue
            first = witnesses[pc_hex][0]
            code_line = f"{leak['file']}:{leak['line']}"
            return _LeakInfo(leak["clause"], leak["type"], code_line, pc_hex, first["trace"],
                             first["line"])
        raise ValueError(f"PC {pc_hex} not found in the report.")

    def _translate_pc_to_gdb(self, pc: int) -> int:
        """ Translate a PC address from the trace to the corresponding address under gdb. """
        trace_base, module_path = self._get_trace_base(pc)
        gdb_base = self._get_gdb_base(os.path.basename(module_path))
        return gdb_base + (pc - trace_base)

    def _get_trace_base(self, pc: int) -> Tuple[int, str]:
        """ Find the trace base address and module path from mappings.txt """
        mappings_file = os.path.join(self._config.stage3_wd, "mappings.txt")

        modules = []
        with open(mappings_file, "r") as f:
            for line in f:
                parts = line.strip().rsplit(' ', 1)
                if len(parts) == 2:
                    modules.append((parts[0], int(parts[1], 16)))

        # Sort by start address descending and find module containing the PC
        modules.sort(key=lambda m: m[1], reverse=True)
        for module_name, start_addr in modules:
            if pc >= start_addr:
                return start_addr, module_name

        raise RuntimeError(f"Module for PC {pc:#x} not found in mappings.txt")

    def _create_valid_driver_invocation(self) -> List[str]:
        """
        Create a valid driver invocation command by replacing the input placeholder with a real seed
        """
        first_seed = next(os.scandir(self._config.afl_seed_dir)).name
        seed_path = os.path.join(self._config.afl_seed_dir, first_seed)
        return [seed_path if s == "@@" else s for s in self._template_cmd]

    def _get_gdb_base(self, module_basename: str) -> int:
        """ Run a dummy gdb session and find the module's base address under gdb """
        builder = GdbScriptBuilder()
        builder.breakpoint_at_symbol(self._config.tracing_entrypoint)
        builder.run()  # load all modules
        builder.command('info proc mappings')

        output = gdb.run_batch(builder, self._create_valid_driver_invocation())
        for line in output.split('\n'):
            if module_basename in line:
                return int(line.split()[0], 16)

        raise RuntimeError(f"Module {module_basename} not found in gdb mappings output")

    def _find_spec_windows(self, leak_info: _LeakInfo) -> List[_SpecWinInfo]:
        # Reconstructs speculation windows for the drill-down report. The window/misprediction
        # model here (boundaries at `spec_level` changes; a misprediction sits at `spec_level - 1`
        # immediately before the window) must stay in sync with the detector's
        # `skip_spec_window` / `get_prev` in `rvzr/model_dynamorio/leak_detector/trace_reader.cpp`.

        # parse the trace
        instructions = _extract_instructions(leak_info.trace_path)
        line_ids = instructions['org_trace_entry_id']
        pcs = instructions['pc']
        spec_levels = instructions['spec_level']

        # Find the spec level of the target line
        cur_target_id = leak_info.org_trace_line_id
        target_inst = instructions[line_ids == cur_target_id]
        assert len(target_inst) == 1 and target_inst['pc'][0] == leak_info.org_pc, \
            (f"Line {cur_target_id} of {leak_info.trace_path} does not hold the reported leak "
             f"instruction {leak_info.org_pc:#x}; the report and the trace are out of sync")
        cur_spec_level = int(target_inst['spec_level'][0])

        # Populate the spec windows info by traversing nested speculation windows backwards
        # until we reach architectural execution
        spec_windows: List[_SpecWinInfo] = []
        while True:
            target_pc = target_inst['pc'][0]

            # Find start of the current window
            if cur_spec_level == 0:
                start_id = 0
            else:
                mispred_mask = (spec_levels == cur_spec_level - 1) & (line_ids < cur_target_id)
                start_id = line_ids[mispred_mask][-1] + 1
            start_pc = pcs[line_ids == start_id][0]

            # Find occurrences of the target PC in the current window
            cur_win_mask = (line_ids >= start_id) & (line_ids < cur_target_id)
            cur_win_mask &= (spec_levels == cur_spec_level)
            spec_windows.append(
                _SpecWinInfo(
                    start_pc=start_pc,
                    pc=target_pc,
                    trace_line_id=cur_target_id,
                    pc_occurrence=int(np.count_nonzero(cur_win_mask & (pcs == target_pc)))))
            if cur_spec_level == 0:
                break
            # Go down in the speculation hierarchy
            cur_spec_level -= 1
            cur_target_id = start_id - 1
            target_inst = instructions[line_ids == cur_target_id]

        # Reverse to get the order from outermost (architectural) to innermost speculation window
        spec_windows.reverse()
        assert (len(spec_windows) == 1) == (leak_info.clause_type == 'seq'), \
            (f"Found {len(spec_windows)} speculation window(s), which contradicts the reported "
             f"'{leak_info.clause_type}' clause")
        return spec_windows

    def _copy_files(self, leak_info: _LeakInfo) -> None:
        # Copy all relevant files into the output directory (clear if exists)
        if os.path.exists(self._output_dir):
            shutil.rmtree(self._output_dir)
        os.makedirs(self._output_dir, exist_ok=True)

        # Inputs
        input_dest = os.path.join(self._output_dir, os.path.basename(leak_info.org_input_path))
        shutil.copy2(leak_info.org_input_path, input_dest)

        ref_input = os.path.join(os.path.dirname(leak_info.org_input_path), "000.bin")
        shutil.copy2(ref_input, os.path.join(self._output_dir, "000.bin"))

        # Trace: decompress for speculation-window analysis. By default the (large) decompressed
        # trace is written to a temporary directory and removed once parsed; with keep_trace it is
        # retained in the output directory for manual inspection.
        compressor = Compressor(self._config)
        trace_name = os.path.basename(leak_info.org_trace_path)
        if self._keep_trace:
            trace_copy = os.path.join(self._output_dir, trace_name)
        else:
            self._trace_tmpdir = tempfile.mkdtemp(prefix="mcfz-trace-")
            trace_copy = os.path.join(self._trace_tmpdir, trace_name)
        shutil.copy2(leak_info.org_trace_path, trace_copy)
        trace_dest_ = compressor.decompress_universal(trace_copy)

        # Binary
        bin_dest = os.path.join(self._output_dir, os.path.basename(self._target_bin))
        shutil.copy2(self._target_bin, bin_dest)

        # Save the updated paths in the leak_info for further use
        leak_info.input_path = input_dest
        leak_info.trace_path = trace_dest_
        leak_info.bin_path = bin_dest
        leak_info.org_template_cmd = self._template_cmd

    def _capture_exec_diff(self, leak_info: _LeakInfo) -> _ExecDiff:
        """
        Run the reference and target inputs under gdb up to the leak instruction and capture their
        execution state at that point.

        Only the architectural (SEQ) case is supported: a speculative leak instruction never
        executes architecturally, so it cannot be reached under gdb.
        """
        if len(leak_info.spec_windows) != 1:
            return _ExecDiff("not_applicable")

        ref_input = os.path.join(self._output_dir, "000.bin")
        ref_state, ref_out = self._capture_leak_state(ref_input, leak_info)
        tgt_state, tgt_out = self._capture_leak_state(str(leak_info.input_path), leak_info)
        if ref_state is None or tgt_state is None:
            if gdb.inferior_exited(ref_out) or gdb.inferior_exited(tgt_out):
                return _ExecDiff("stale_address")
            return _ExecDiff("failed")

        return _ExecDiff("ok", ref_state, tgt_state)

    def _stage_to_leak(self, builder: GdbScriptBuilder, win: _SpecWinInfo) -> None:
        """ Add the commands that run the target up to the leak occurrence in the given window """
        builder.breakpoint(win.start_pc_gdb, temporary=True)
        builder.run()

        leak_bp = builder.breakpoint(win.pc_gdb)
        ignored_cond = self._ignored_caller_expression()
        if ignored_cond is not None:
            builder.condition(leak_bp, ignored_cond)
        if win.pc_occurrence > 0:
            builder.ignore(leak_bp, win.pc_occurrence)
        builder.continue_()

    def _capture_leak_state(self, input_path: str,
                            leak_info: _LeakInfo) -> Tuple[Optional[_RunState], str]:
        """
        Run one input under gdb to the leak instruction and capture its execution state.
        """
        win = leak_info.spec_windows[-1]
        target_args = leak_info.driver_cmd(input_path)

        builder = GdbScriptBuilder()
        self._stage_to_leak(builder, win)
        builder.begin_section('REGS')
        builder.command('info registers ' + ' '.join(_DIFF_REGS))
        builder.end_section()
        builder.command('stepi')
        builder.print_value('NEXTPC', '(unsigned long)$pc')

        output = gdb.run_batch(builder, target_args)
        return self._parse_leak_state(output), output

    @staticmethod
    def _parse_leak_state(output: str) -> Optional[_RunState]:
        """ Parse the marker-delimited gdb output produced by `_capture_leak_state` """
        sections = gdb.split_sections(output)
        next_pc = gdb.parse_value(output, 'NEXTPC')

        regs: Dict[str, int] = {}
        for line in sections.get('REGS', []):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    regs[parts[0]] = int(parts[1], 16)
                except ValueError:
                    pass

        if not regs or next_pc is None:
            return None
        return _RunState(regs=regs, next_pc=next_pc)

    @staticmethod
    def _first_disasm(dis_lines: List[str]) -> str:
        """ Collapse the leading "=> " marker and gdb's tab/space padding of an `x/1i` line """
        return " ".join(dis_lines[0].strip().removeprefix("=>").split()) if dis_lines else ""

    def _capture_backtrace(self, leak_info: _LeakInfo) -> _Backtrace:
        """
        Capture the call stack (backtrace) at the leak site under gdb.

        For an architectural (seq) leak this is the call stack at the leak instruction itself.
        For a speculative leak the leak instruction is reachable only under speculation, so the
        backtrace is captured at the start of the (outermost) speculation window — the
        architectural frame from which speculation toward the leak begins.
        """
        win = leak_info.spec_windows[0]
        target_args = leak_info.driver_cmd(str(leak_info.input_path))

        builder = GdbScriptBuilder()
        builder.setting('backtrace limit 64')
        self._stage_to_leak(builder, win)
        builder.begin_section('BT')
        builder.command('bt')
        builder.end_section()

        output = gdb.run_batch(builder, target_args)
        frames = self._parse_backtrace(output)
        if not frames:
            if gdb.inferior_exited(output):
                return _Backtrace("stale_address")
            return _Backtrace("failed")

        return _Backtrace("ok", frames)

    @staticmethod
    def _parse_backtrace(output: str) -> List[str]:
        """ Parse the marker-delimited gdb `bt` output produced by `_capture_backtrace` """
        return [
            " ".join(line.split())
            for line in gdb.split_sections(output).get('BT', [])
            if line.strip().startswith("#")
        ]

    def _capture_static_context(self, leak_info: _LeakInfo) -> _StaticContext:
        """
        Capture the leak instruction's disassembly and surrounding source lines.
        """
        pc_gdb = leak_info.spec_windows[-1].pc_gdb
        dummy = self._create_valid_driver_invocation()

        builder = GdbScriptBuilder()
        builder.setting('listsize 7')
        builder.breakpoint_at_symbol(self._config.tracing_entrypoint)
        builder.run()
        builder.begin_section('DIS')
        builder.command(f'x/1i {pc_gdb:#x}')
        builder.begin_section('SRC')
        builder.command(f'list *{pc_gdb:#x}')
        builder.end_section()

        disasm, source = Driller._split_static_context(gdb.run_batch(builder, dummy))
        if not disasm and not source:
            return _StaticContext("failed")
        return _StaticContext("ok", disasm, source)

    @staticmethod
    def _split_static_context(output: str) -> Tuple[str, List[str]]:
        """ Extract the leak disassembly and source listing from the marker-delimited gdb output """
        sections = gdb.split_sections(output)

        # gdb's `list *addr` prefixes the listing with a redundant "0x<runtime-addr> is at
        # <file>:<line>." line; the runtime address and source location are already shown in the
        # VIOLATION banner, so drop it.
        source = [
            line.rstrip()
            for line in sections.get('SRC', [])
            if not re.match(r'0x[0-9a-fA-F]+\s+is at\b', line.strip())
        ]

        return Driller._first_disasm(sections.get('DIS', [])), source
