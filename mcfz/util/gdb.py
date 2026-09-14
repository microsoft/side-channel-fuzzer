"""
File: Interaction with GDB; builds the gdb command scripts and the tmux launcher used by the
      driller to open side-by-side debug sessions for a violation, runs gdb in batch mode, and
      parses its output.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os

from typing import Dict, Final, List, Optional, TYPE_CHECKING
from subprocess import run, PIPE

if TYPE_CHECKING:
    from ..driller import _LeakInfo

# Sections of gdb output are delimited by marker lines of the form `__MCFZ_<NAME>__`, emitted by
# `GdbScriptBuilder.begin_section` and read back by `split_sections`.
_MARKER_PREFIX: Final[str] = "__MCFZ_"
_MARKER_SUFFIX: Final[str] = "__"
_END_SECTION: Final[str] = "END"


def _marker(name: str) -> str:
    return f"{_MARKER_PREFIX}{name}{_MARKER_SUFFIX}"


def run_batch(builder: GdbScriptBuilder, target_args: List[str]) -> str:
    """
    Run gdb in batch mode with the builder's commands and return its stdout

    :param builder: The commands to execute, in order
    :param target_args: The target invocation to pass to gdb's ``--args``
    :return: The stdout of the gdb session
    """
    gdb_cmd = ['gdb', '--batch', '-nx']
    for cmd in builder.commands():
        gdb_cmd += ['-ex', cmd]
    gdb_cmd += ['--args'] + target_args
    result = run(gdb_cmd, stdout=PIPE, stderr=PIPE, text=True, check=False)
    return result.stdout


def inferior_exited(output: str) -> bool:
    """
    Report whether the gdb output shows the debugged program running to completion.

    A clean exit means gdb never stopped at any of the staged breakpoints, so no state could be
    captured.

    :param output: The stdout of a gdb session
    :return: True if the program ran to completion
    """
    return "exited normally" in output or "exited with code" in output


def split_sections(output: str) -> Dict[str, List[str]]:
    """
    Split gdb output into the sections delimited by `GdbScriptBuilder.begin_section`.

    Marker lines and blank lines are dropped; all other lines are returned verbatim, so that
    indentation-carrying output (e.g. source listings) survives.

    :param output: The stdout of a gdb session
    :return: A map of section name to the lines gdb printed within that section
    """
    sections: Dict[str, List[str]] = {}
    current: Optional[List[str]] = None

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(_MARKER_PREFIX) and stripped.endswith(_MARKER_SUFFIX):
            name = stripped[len(_MARKER_PREFIX):-len(_MARKER_SUFFIX)]
            current = None if name == _END_SECTION else sections.setdefault(name, [])
        elif current is not None and stripped:
            current.append(line)

    return sections


def parse_value(output: str, name: str) -> Optional[int]:
    """
    Read back a hexadecimal value emitted by `GdbScriptBuilder.print_value`

    :param output: The stdout of a gdb session
    :param name: The name the value was printed under
    :return: The value, or ``None`` if gdb never printed it
    """
    marker = _marker(name)
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == marker:
            try:
                return int(parts[1], 16)
            except ValueError:
                continue
    return None


class GdbScriptBuilder:
    """ Encapsulates GDB command syntax and script generation for leak debugging """

    def __init__(self) -> None:
        self._commands: List[str] = []
        self._n_break: int = 0

        # apply default settings that make gdb output easier to parse and more compact
        self.setting('pagination off')
        self.setting('width 0')
        self.setting('disable-randomization on')

    def breakpoint(self, pc: int, temporary: bool = False) -> int:
        """ Add a breakpoint at the given PC address and return the breakpoint number """
        if temporary:
            self._commands.append(f"tbreak *{pc:#x}")
        else:
            self._commands.append(f"break *{pc:#x}")
        self._n_break += 1
        return self._n_break

    def breakpoint_at_symbol(self, symbol: str) -> int:
        """ Add a breakpoint at the given symbol and return the breakpoint number """
        self._commands.append(f"break {symbol}")
        self._n_break += 1
        return self._n_break

    def condition(self, bp_num: int, expr: str) -> None:
        """ Add a command that makes the given breakpoint fire only when `expr` holds """
        self._commands.append(f"condition {bp_num} {expr}")

    def setting(self, expr: str) -> None:
        """ Add a ``set`` command, e.g. ``setting("pagination off")`` """
        self._commands.append(f"set {expr}")

    def command(self, cmd: str) -> None:
        """ Add a verbatim gdb command, for commands without a dedicated method """
        self._commands.append(cmd)

    def comment(self, text: str) -> None:
        """ Add a comment line; only valid for scripts, not for ``-ex`` invocations """
        self._commands.append(f"# {text}")

    def begin_section(self, name: str) -> None:
        """ Add a command that marks the start of a named section in gdb's output """
        self._commands.append(f'printf "\\n{_marker(name)}\\n"')

    def end_section(self) -> None:
        """ Add a command that marks the end of the current output section """
        self.begin_section(_END_SECTION)

    def print_value(self, name: str, expr: str) -> None:
        """ Add a command that prints the given expression as a named hexadecimal value """
        self._commands.append(f'printf "{_marker(name)} %#lx\\n", {expr}')

    def run(self) -> None:
        """ Add a command to start program execution """
        self._commands.append("run")

    def jump(self, pc: int) -> None:
        """ Add a command to jump to the given PC address """
        self._commands.append(f"jump *{pc:#x}")

    def continue_(self) -> None:
        """ Add a command to continue program execution """
        self._commands.append("continue")

    def delete(self, bp_num: int) -> None:
        """ Add a command to delete the given breakpoint """
        self._commands.append(f"del {bp_num}")

    def ignore(self, bp_num: int, count: int) -> None:
        """ Add a command to ignore the next `count` hits of the given breakpoint """
        self._commands.append(f"ignore {bp_num} {count}")

    def shell_prompt(self, message: str) -> None:
        """ Add a shell command that prints a message and waits for user input """
        self._commands.append(
            f'shell printf "[MCFZ] {message}. Press [Enter] to continue..." && read _')

    def shell_message(self, message: str) -> None:
        """ Add a shell command that prints a message without waiting """
        self._commands.append(f'shell printf "[MCFZ] {message}\\n"')

    def write(self, path: str) -> None:
        """ Write the accumulated GDB commands to a script file """
        with open(path, 'w') as f:
            f.write("\n".join(self._commands))

    def commands(self) -> List[str]:
        """ Return the accumulated GDB commands, for passing to gdb via ``-ex`` """
        return list(self._commands)

    @classmethod
    def create_leak_script(cls,
                           leak_info: _LeakInfo,
                           path: str,
                           args_cmd: str,
                           fast: bool = False,
                           single_step: bool = False,
                           ignored_cond: Optional[str] = None) -> str:
        """
        Create a gdb script that reaches the violation described in leak_info,
        save it to the given path, and return the full gdb command to run it.

        :param leak_info: Information about the leak to investigate
        :param path: Path to save the gdb script
        :param args_cmd: The command (with arguments) to pass to gdb's ``--args``
        :param fast: If True, skip intermediate gdb prompts (architectural and spec window starts)
        :param single_step: If True, drop to interactive gdb at the first speculative instruction,
            with breakpoints set at all remaining points of interest
        :param ignored_cond: gdb condition restricting breakpoint hits to non-ignored contexts
        :return: The full gdb command string (e.g., ``gdb -x script.gdb --args cmd``)
        """
        builder = cls()

        def poi_breakpoint(pc: int) -> int:
            b_num = builder.breakpoint(pc)
            if ignored_cond is not None:
                builder.condition(b_num, ignored_cond)
            return b_num

        for lvl, win in enumerate(leak_info.spec_windows):
            is_first = lvl == 0
            is_last = lvl == len(leak_info.spec_windows) - 1

            # Reach start of this window
            b_num = builder.breakpoint(win.start_pc_gdb, temporary=True)
            if is_first:
                builder.run()
            else:
                builder.jump(win.start_pc_gdb)
                if single_step:
                    # Set breakpoints at all remaining POIs and drop to interactive mode
                    for remaining_win in leak_info.spec_windows[lvl:]:
                        poi_breakpoint(remaining_win.pc_gdb)
                    builder.shell_prompt(
                        f'Entered single-step mode at first speculative instruction '
                        f'(pc: {win.start_pc_gdb:#x}). '
                        f'Breakpoints set at all remaining POIs. '
                        f'Use ni/si to single-step or continue to reach next POI')
                    break

            if not fast:
                builder.shell_prompt(
                    "Reached first architectural instruction" if is_first else
                    f'Reached start of spec window (level: {lvl}, pc: {win.start_pc_gdb:#x})')

            # Reach target instruction
            b_num = poi_breakpoint(win.pc_gdb)
            if win.pc_occurrence > 0:
                builder.comment(f"Skip {win.pc_occurrence} earlier hit(s) of breakpoint {b_num} "
                                "so execution stops at the")
                builder.comment("occurrence of this PC that actually triggers the leak")
                builder.ignore(b_num, win.pc_occurrence)
            builder.continue_()

            msg_template = 'Reached {label} (level: {lvl}, pc: {win:#x})'
            if is_last:
                builder.shell_message(
                    msg_template.format(label="leak instruction", lvl=lvl, win=win.pc_gdb))
                continue

            builder.shell_prompt(
                msg_template.format(label="mispredicted instruction", lvl=lvl, win=win.pc_gdb))
            builder.delete(b_num)

        builder.write(path)
        return f'gdb -x {path} --args {args_cmd}'


class DebugScriptBuilder:
    """ Creates the debug bash script that launches tmux with side-by-side gdb sessions """

    _SCRIPT_TEMPLATE: Final[str] = """\
#!/bin/bash
# Debug script for violation at PC {pc_hex}
# Opens two gdb sessions side-by-side using tmux:
#   Left pane (0):  Reference input (000.bin)
#   Right pane (1): Target input ({input_basename})

# Kill any existing session with the same name
tmux kill-session -t {session_name} 2>/dev/null

# Create new tmux session with two panes and labeled borders
tmux new-session -s {session_name} \\; \\
    set-option -g pane-border-status top \\; \\
    set-option -g pane-border-format " #{{pane_title}} " \\; \\
    set-option -g mouse on \\; \\
    bind-key -n M-Left select-pane -L \\; \\
    bind-key -n M-Right select-pane -R \\; \\
    split-window -h \\; \\
    select-pane -t 0 -T "000.bin" \\; \\
    select-pane -t 1 -T "{input_basename}" \\; \\
    send-keys -t 0 '{ref_gdb_cmd}' C-m \\; \\
    send-keys -t 1 '{target_gdb_cmd}' C-m
"""

    @classmethod
    def build(cls,
              leak_info: _LeakInfo,
              output_dir: str,
              fast: bool = False,
              single_step: bool = False,
              ignored_cond: Optional[str] = None) -> str:
        """
        Create gdb scripts and a tmux debug launcher for investigating a leak.

        Creates two gdb scripts (for reference and target inputs) and a bash script
        that launches them side-by-side in tmux.

        :param leak_info: Information about the leak to investigate
        :param output_dir: Directory to write debug scripts into
        :param fast: If True, skip intermediate gdb prompts
        :param single_step: If True, drop to interactive gdb at first speculative instruction
        :param ignored_cond: gdb condition restricting breakpoint hits to non-ignored contexts
        :return: Path to the generated debug.sh script
        """

        def make_gdb_cmd(input_path: str, script_name: str) -> str:
            cmd = leak_info.driver_cmd(input_path)
            return GdbScriptBuilder.create_leak_script(
                leak_info,
                os.path.join(output_dir, script_name),
                " ".join(cmd),
                fast=fast,
                single_step=single_step,
                ignored_cond=ignored_cond)

        ref_gdb_cmd = make_gdb_cmd(os.path.join(output_dir, "000.bin"), "debug_ref.gdb")
        target_gdb_cmd = make_gdb_cmd(str(leak_info.input_path), "debug_target.gdb")

        # Write the tmux debug script
        script_path = os.path.join(output_dir, "debug.sh")
        script_content = cls._SCRIPT_TEMPLATE.format(
            pc_hex=f"{leak_info.org_pc:#x}",
            session_name=f"mcfz_{leak_info.org_pc:x}",
            input_basename=os.path.basename(leak_info.input_path),
            ref_gdb_cmd=ref_gdb_cmd,
            target_gdb_cmd=target_gdb_cmd,
        )
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)

        return script_path
