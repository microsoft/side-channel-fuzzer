"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import sys
from datetime import datetime
from typing import TYPE_CHECKING, NoReturn, Dict, List, Optional, Set, Any, Final, Tuple
from pprint import pformat
from traceback import print_stack

from .config import CONF
from .stats import FuzzingStats

if TYPE_CHECKING:
    from .model import Model
    from .sandbox import SandboxLayout
    from .model_unicorn.execution_context import ModelExecutionState
    from .model_unicorn.speculator_abc import UnicornSpeculator
    from .model_unicorn.model import UnicornModel
    from .instruction_spec import InstructionSpec
    from .traces import HTrace, Violation, CTrace
    from .tc_components.test_case_data import InputData

MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)

RED = '\033[33;31m'
GREEN = '\033[33;32m'
YELLOW = '\033[33;33m'
BLUE = '\033[33;34m'
PURPLE = '\033[33;35m'
CYAN = '\033[33;36m'
GRAY = '\033[33;37m'
COL_RESET = "\033[0m"

M_COL = PURPLE
PC_COL = COL_RESET
VAL_COL = CYAN

HTRACE_R1_COL = CYAN
HTRACE_R2_COL = YELLOW

STAT = FuzzingStats()


# ==================================================================================================
# Private: Logging configuration
# ==================================================================================================
class _LoggingConfig:
    # pylint: disable=too-few-public-methods
    # justification: data class
    """
    A global object responsible for keeping track of how stuff should be printed.
    This object is shared among all modules (via Borg pattern)
    and is used to determine the logging behavior.
    """
    _borg_shared_state: Dict[Any, Any] = {}

    redraw_mode: bool = True
    line_ending: str = ""

    # info modes
    info: bool = False
    stat: bool = False
    debug: bool = False

    # debugging specific modules
    dbg_timestamp: bool = False
    dbg_violation: bool = False
    dbg_dump_htraces: bool = False
    dbg_dump_ctraces: bool = False
    dbg_dump_traces_unlimited: bool = False
    dbg_executor_raw: bool = False
    dbg_model: bool = False
    dbg_coverage: bool = False
    dbg_generator: bool = False
    dbg_priming: bool = False
    dbg_isa_filter: bool = False

    dbg_model_print_id: bool = True

    _all_modes: List[str] = [
        "info", "stat", "dbg_timestamp", "dbg_violation", "dbg_dump_htraces", "dbg_dump_ctraces",
        "dbg_dump_traces_unlimited", "dbg_executor_raw", "dbg_model", "dbg_coverage",
        "dbg_generator", "dbg_priming", "dbg_isa_filter"
    ]

    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state
        if not self._borg_shared_state:
            self.update_logging_modes()

    def update_logging_modes(self) -> None:
        """
        Function that adjust the logging configuration after
        a change has been made to the CONF object """
        # Check that all entries in the config a valid
        for mode in CONF.logging_modes:
            if not mode:  # skip empty values
                continue
            if mode not in self._all_modes:
                error(f"Unknown value '{mode}' of config variable 'logging_modes'")

        # Set the output format
        self.line_ending = '\n' if CONF.multiline_output else ''
        self.redraw_mode = not CONF.multiline_output

        # Set the logging modes
        self.debug = False
        for mode in self._all_modes:
            val = mode in CONF.logging_modes
            setattr(self, mode, val)
            if "dbg" in mode:
                self.debug |= val

        # Check if Python is not running in optimized mode if debugging is required
        # (otherwise, the debug messages won't be printed)
        if not __debug__:
            dbg_required = any([
                self.dbg_timestamp, self.dbg_model, self.dbg_coverage, self.dbg_dump_htraces,
                self.dbg_dump_ctraces, self.dbg_generator, self.dbg_priming, self.dbg_executor_raw,
                self.dbg_isa_filter
            ])
            if dbg_required:
                warning(
                    "", "Current value of `logging_modes` requires debugging mode!\n"
                    "Remove '-O' from python arguments")


# ==================================================================================================
# Public interface to logging configuration
# ==================================================================================================
# create an initial instance of the logging configuration
# to be used by functions in this module
_LOG_CONF = _LoggingConfig()


def update_logging_after_config_change() -> None:
    """ Update the logging configuration after a change has been made to the CONF object """
    _LOG_CONF.update_logging_modes()


# ==================================================================================================
# Public: Simple logging functions
# ==================================================================================================
# FIXME: deprecated; use exceptions instead
def error(msg: str, print_tb: bool = False, print_last_tb: bool = False) -> NoReturn:
    """ Print an error message and exit the program """
    if _LOG_CONF.redraw_mode:
        print("")

    if print_tb:
        print("Encountered an unrecoverable error\nTraceback:")
        print_stack()
        print("\n")
    elif print_last_tb:
        print("Encountered an unrecoverable error\nTraceback:")
        print_stack(limit=3)
        print("\n")

    if CONF.color:
        print(f"{RED}ERROR:{COL_RESET} {msg}")
    else:
        print(f"ERROR: {msg}")
    sys.exit(1)


def warning(src: str, msg: str) -> None:
    """ Print a warning message """
    if _LOG_CONF.redraw_mode:
        print("")
    if CONF.color:
        print(f"{RED}WARNING:{COL_RESET} [{src}] {msg}")
    else:
        print(f"WARNING: [{src}] {msg}")


def inform(src: str, msg: str, end: str = "\n") -> None:
    """ Print a general information message """
    if _LOG_CONF.info:
        if _LOG_CONF.redraw_mode:
            print("")
        print(f"INFO: [{src}] {msg}", end=end, flush=True)


def dbg(src: str, msg: str) -> None:
    """ Print a debug message """
    if not __debug__:
        return
    if _LOG_CONF.debug:
        if _LOG_CONF.redraw_mode:
            print("")
        print(f"DBG: [{src}] {msg}")


# ==================================================================================================
# Public: Module-specific logging
# ==================================================================================================
class FuzzLogger:
    """ A class that provides logging services for the Fuzzer module """

    one_percent_progress: float = 0.0
    progress: float = 0.0
    progress_percent: int = 0
    msg: str = ""
    _msg_width: int = 0
    start_time: datetime
    _conf: Final[_LoggingConfig]

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    # ----------------------------------------------------------------------------------------------
    # Phases of the fuzzer

    def reset(self, max_iterations: int, start_time: datetime) -> None:
        """ Reset the state of the fuzzer """
        self.one_percent_progress = max_iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.start_time = start_time

    def start(self, iterations: int, start_time: datetime) -> None:
        """ Print the start message of the fuzzer (namely, the start time) """
        self.reset(iterations, start_time)
        if not self._conf.info:
            return
        inform("fuzzer", start_time.strftime('Starting at %H:%M:%S'))

    def start_round(self, round_id: int) -> None:
        """ Update the progress bar for the next fuzzing round """
        if not self._conf.info:
            return

        # Update the progress state
        if STAT.test_cases > self.progress:
            self.progress += self.one_percent_progress
            self.progress_percent += 1
        if STAT.test_cases == 0:
            msg = ""
        else:
            msg = f"\r{STAT.test_cases:<6}({self.progress_percent:>2}%)| Stats: "
            msg += STAT.get_brief()
        self.msg = msg

        # Print the progress bar
        if STAT.test_cases > 0:
            print(f"{self.msg:<{self._msg_width}}", end=self._conf.line_ending, flush=True)
        if self._conf.dbg_timestamp and round_id and round_id % 1000 == 0:
            dbg(
                "fuzzer", f"Time: {datetime.today()} | "
                f" Duration: {(datetime.today() - self.start_time).total_seconds()} seconds")

    def priming(self, num_violations: int) -> None:
        """ Print a message indicating that the fuzzer is in the priming phase """
        if not self._conf.info:
            return
        msg = self.msg + f"> Priming  {num_violations}             "
        print(msg, end=self._conf.line_ending, flush=True)
        self._msg_width = max(self._msg_width, len(msg))

    def nesting_increased(self) -> None:
        """ Print a message indicating that the model's nesting level has been increased """
        if not self._conf.info:
            return
        msg = self.msg + f"> Nest   {CONF.model_max_nesting}         "
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def slow_path(self) -> None:
        """ Print a message indicating that the fuzzer has entered the slow path """
        if not self._conf.info:
            return
        msg = self.msg + ">" + " Entering slow path..."
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def timeout(self) -> None:
        """ Print a message indicating that the fuzzer has timed out """
        if not self._conf.info:
            return
        inform("fuzzer", "\nTimeout expired")

    def sample_size_increase(self, sample_size: int) -> None:
        """ Print a message indicating that the sample size has been increased """
        if not self._conf.info:
            return
        msg = self.msg + ">" + " Increasing sample size... to " + str(sample_size)
        self._msg_width = max(self._msg_width, len(msg))
        print(msg, end=self._conf.line_ending, flush=True)

    def report_violations(self, violation: Violation) -> None:
        """ Print the detected violations """
        print("\n\n================================ Violations detected ==========================")
        print(violation.full_str())

    def finish(self) -> None:
        """ Print the finish message of the fuzzer (namely, the finish
        time and the duration of the fuzzer) """
        if not self._conf.info:
            return
        now = datetime.today()
        print("")  # new line after the progress bar
        if self._conf.stat:
            print("================================ Statistics ================================"
                  "===\n")
            print(STAT)
        print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
        print(datetime.today().strftime('Finished at %H:%M:%S'))

    def report_model_coverage(self, model: Model) -> None:
        """ Save model coverage """
        if not __debug__:
            return
        if not self._conf.dbg_coverage:
            return
        model.report_coverage("coverage.txt")

    # ----------------------------------------------------------------------------------------------
    # Debugging
    def dbg_dump_traces(self, inputs: List[InputData], htraces: List[HTrace],
                        reference_htraces: List[HTrace], ctraces: List[CTrace]) -> None:
        """ Print the collected traces """
        if not __debug__:
            return
        if not self._conf.dbg_dump_htraces and not self._conf.dbg_dump_ctraces:
            return
        if not htraces:  # might be empty due to tracing errors
            return

        # Optionally trim the output
        if len(inputs) > 100 and not self._conf.dbg_dump_traces_unlimited:
            warning("fuzzer", "Trace output is will be limited to 100 traces")
            inputs = inputs[:100]

        # Replace corrupted traces with the reference traces
        for i, htrace in enumerate(htraces):
            if htrace.is_corrupted_or_ignored() \
               and not reference_htraces[i].is_corrupted_or_ignored():
                htraces[i] = reference_htraces[i]

        print("\n================================ Collected Traces =============================")
        org_debug_state = self._conf.dbg_model
        self._conf.dbg_model = False
        for i, _ in enumerate(inputs):
            print(f"- Input {i}:")
            colors: Tuple[str, ...]
            if self._conf.dbg_dump_ctraces:
                colors = (M_COL, PC_COL, VAL_COL, COL_RESET) if CONF.color else ()
                ctrace_str = ctraces[i].full_str(*colors)
                print(f"  CTr: {ctrace_str} | Hash: {ctraces[i]}")
            if self._conf.dbg_dump_htraces:
                colors = (HTRACE_R1_COL, HTRACE_R2_COL, COL_RESET) if CONF.color else ()
                htrace_str = htraces[i].full_str('    ', *colors)
                print(f"  HTr:\n{htrace_str}")
            if CONF.color and htraces[i].get_max_pfc()[0] > htraces[i].get_max_pfc()[1]:
                print(f"  Feedback: {YELLOW}{htraces[i].get_max_pfc()}{COL_RESET}")
            else:
                print(f"  Feedback: {htraces[i].get_max_pfc()}")
        self._conf.dbg_model = org_debug_state

    def dbg_dump_architectural_traces(self, hardware_regs: List[List[int]],
                                      model_regs: List[List[int]]) -> None:
        """ Print the architectural traces """
        if not __debug__:
            return
        if CONF.fuzzer != "architectural":
            return
        if not self._conf.dbg_dump_htraces and not self._conf.dbg_dump_ctraces:
            return

        print("\n========================== Architectural Traces ==============================")
        for i, _ in enumerate(hardware_regs):
            if i > 100 and not self._conf.dbg_dump_traces_unlimited:
                warning("fuzzer", "Trace output is limited to 100 traces")
                break
            print(f"Input {i}:")
            if self._conf.dbg_dump_ctraces:
                print(f"  Model Registers: {[hex(v) for v in model_regs[i]]}")
            if self._conf.dbg_dump_htraces:
                print(f"  HW Registers:    {[hex(v) for v in hardware_regs[i]]}")

    def dbg_violation(self, violation: Violation, model: Model) -> None:
        """ Print a detailed report of the violation """
        if not __debug__:
            return

        if self._conf.dbg_violation:
            print("================================ Violation Traces =============================")
            hw_classes = violation.get_hw_classes()
            model.load_test_case(violation.test_case_code)
            for hw_class in hw_classes:
                measurement = hw_class.measurements[0]
                print(f"                      ##### Input {measurement.input_id} #####")
                model_debug_state = self._conf.dbg_model, self._conf.dbg_model_print_id
                self._conf.dbg_model = True
                self._conf.dbg_model_print_id = False
                model.trace_test_case([measurement.input_], CONF.model_max_nesting)
                self._conf.dbg_model, self._conf.dbg_model_print_id = model_debug_state
                print("\n\n")

    def dbg_priming_progress(self, input_id: int, current_input_id: int) -> None:
        """ Print a message indicating the progress of the priming phase """
        if not __debug__:
            return
        if not self._conf.dbg_priming:
            return
        print(f"\nPriming #{input_id} in place of #{current_input_id}")

    def dbg_priming_fail(self, input_id: int, current_input_id: int, htrace_to_reproduce: HTrace,
                         new_htrace: HTrace) -> None:
        """ Print a message indicating that the priming phase has failed """
        if not __debug__:
            return
        if not self._conf.dbg_priming:
            return

        print(f"\nPriming failed for input {input_id} in place of {current_input_id}")
        print(f"{'HTrace':64} Original|New")
        print(htrace_to_reproduce.full_pair_str(new_htrace))


class ModelLogger:
    """
    A class that provides logging services for the Model modules. Primarily, this class
    is responsible for printing the debug trace of the model.
    (printed when dbg_model or dbg_violation is set in the config file)
    """

    model_layout: Optional[SandboxLayout] = None

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def set_model_layout(self, layout: SandboxLayout) -> None:
        """ Store the layout of the model being debugged """
        self.model_layout = layout

    def dbg_header(self, input_id: int) -> None:
        """ Print the header of the debug information """
        if not __debug__:
            return
        if not self._conf.dbg_model or not self._conf.dbg_model_print_id:
            return

        print(f"\n                     ##### Input {input_id} #####")

    def dbg_mem_access(self, is_store: bool, value: int, address: int, size: int,
                       model: UnicornModel, layout: SandboxLayout) -> None:
        """
        Print debug information about memory access, if debugging is enabled.
        The information includes:
            - Memory address (as an offset from the start of the main actor's data section)
            - Type of access (load or store)
            - Value being read or written

        :param type_: The type of memory access (UC_MEM_READ or UC_MEM_WRITE)
        :param value: The value being read or written
        :param address: The address being accessed
        :param size: The size of the memory access
        :param model: The model being debugged
        :param layout: The layout of the model being debugged
        :return: None
        """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        # Address details
        normalized_address = layout.data_addr_to_offset(address)

        # Value details
        val = value if is_store else int.from_bytes(
            model.emulator.mem_read(address, size), byteorder='little')

        # Build and print the report string
        type_str = "store to" if is_store else "load from"
        if CONF.color:
            msg = f"    > {CYAN}{type_str}{COL_RESET} +0x{normalized_address:x} " \
                  f"{CYAN}value {COL_RESET}0x{val:x}"
        else:
            msg = f"    > {type_str} +0x{normalized_address:x} value 0x{val:x}"

        print(msg)

    def dbg_instruction(self, pc: int, model: UnicornModel, state: ModelExecutionState,
                        speculator: UnicornSpeculator) -> None:
        """
        Print debug information about the current instruction, if debugging is enabled.
        The information includes:
          - Instruction name and operands
          - Current register values
          - Whether the instruction is speculative, and if so, the speculative nesting level
        """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        # Instruction details
        instruction = state.current_instruction
        name = str(instruction)
        code_offset = model.layout.code_addr_to_offset(pc)
        is_exit = state.is_exit_addr(pc)

        # Speculation details
        in_speculation = speculator.in_speculation()
        nesting = speculator.nesting()

        # Build and print the report string
        inst_str = name
        if CONF.color:
            if in_speculation:
                inst_str = YELLOW + inst_str + COL_RESET
            else:
                inst_str = GREEN + inst_str + COL_RESET
        if in_speculation:
            inst_str = f"[transient, nesting = {nesting}] " + inst_str
        inst_str = f"0x{code_offset:<2x}: {inst_str}"
        if is_exit:
            inst_str += " [test_case_exit]"
        print(inst_str)

        # Print the register values
        model.print_registers(oneline=True)

    def dbg_rollback(self, address: int) -> None:
        """ Print a message indicating that the model has rolled back to a specific address """
        if not __debug__:
            return
        if not self._conf.dbg_model:
            return

        assert self.model_layout is not None
        base = self.model_layout.code_start()

        msg = f"ROLLBACK to 0x{address - base:x}"
        if CONF.color:
            msg = YELLOW + msg + COL_RESET
        print(msg)

    def dbg_exception(self, errno: int, descr: str) -> None:
        """ Print a message indicating that an exception has occurred """
        if not __debug__:
            return

        if not self._conf.dbg_model:
            return

        msg = f"EXCEPTION #{errno}: {descr}"
        if CONF.color:
            msg = RED + msg + COL_RESET
        print(msg)


class GeneratorLogger:
    """ A class that provides logging services for the Program Generator module """

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_instruction_pool(self, instructions: List[InstructionSpec]) -> None:
        """
        Print the instruction pool used by the Program Generator, if debugging is enabled.
        The instructions are grouped by category and printed in a human-readable format.
        """
        if not __debug__:
            return
        if not self._conf.dbg_generator or not CONF.is_generation_enabled():
            return

        instructions_by_category: Dict[str, Set[str]] = {i.category: set() for i in instructions}
        for i in instructions:
            instructions_by_category[i.category].add(i.name)
        n_instructions = sum(len(v) for v in instructions_by_category.values())

        dbg("generator", f"Instructions under test {n_instructions}:")
        for k, instruction_list in instructions_by_category.items():
            print("  - " + k + ": " + pformat(sorted(instruction_list), indent=4, compact=True))
        print("")


class ExecutorLogger:
    """ A class that provides logging services for the Executor module """

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_raw_traces(self, htraces: List[HTrace]) -> None:
        """ Print the raw traces collected by the executor """
        if not __debug__:
            return
        if not self._conf.dbg_executor_raw:
            return

        print("Collected raw traces:")
        for input_id, htrace in enumerate(htraces):
            prefix = f"{input_id:03}, "
            print(htrace.full_str(prefix))


class ISALogger:
    """ A class that provides logging services for the isa_spec module """

    def __init__(self) -> None:
        self._conf = _LoggingConfig()

    def dbg_dump_filtering_reason(self, instruction: InstructionSpec, reason: str) -> None:
        """
        Print the reason why a specific instruction was filtered out by the ISA module,
        if debugging is enabled.
        """
        if not __debug__:
            return
        if not self._conf.dbg_isa_filter or not CONF.is_generation_enabled():
            return

        dbg("isa_spec", f"{instruction.name} ({instruction.category}) filtered out: {reason}")
