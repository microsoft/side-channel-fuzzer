"""
File: DynamoRIO-based backend to the contract model.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import tempfile
from subprocess import check_output, CalledProcessError, STDOUT
from typing import List, Tuple, Optional, TYPE_CHECKING, Final, Any
from typing_extensions import TypeAlias

import numpy as np
from numpy.typing import NDArray

from .trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType

from ..model import Model
from ..sandbox import BaseAddrTuple, SandboxLayout, DataArea
from ..traces import CTrace, CTraceEntry
from ..tc_components.test_case_data import save_input_sequence_as_rdbf, InputTaint
from ..config import CONF

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData

_DRRUN_TRACING_FLAGS: Final[str] = " --mode rvzr --instrumented-func test_case_entry "
_ADAPTER_PATH: Final[str] = "~/.local/dynamorio/adapter"
_DRRUN_CMD: Final[str] = "~/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so " \
    " {flags} -- {binary} {args}"

# Constants for trace processing
_N_REGISTERS_IN_DUMP: Final[int] = 6  # rax, rbx, rcx, rdx, rsi, rdi
_BYTES_PER_TAINT_ENTRY: Final[int] = 8  # each taint entry corresponds to 8 bytes
_EOT_MARKER: Final[int] = np.iinfo(np.uint64).max  # end-of-transmission marker for taint files

# Type aliases for raw trace entries (CFFI objects from TraceDecoder)
# Note: These are dynamically typed CFFI objects, so we use Any with documentation
_RawTraceEntry: TypeAlias = Any  # CFFI struct: trace_entry_t with addr, size, type fields
_RawDebugTraceEntry: TypeAlias = Any  # CFFI struct: debug_trace_entry_t with type, regs union
_RawTrace: TypeAlias = List[_RawTraceEntry]  # List of trace entries from one test execution
_RawDebugTrace: TypeAlias = List[_RawDebugTraceEntry]  # List of debug trace entries


class DynamoRIOModel(Model):
    """
    Adapter class that connects the DynamoRIO backend to the rest of Revizor.
    """
    _obs_clause_name: Optional[str] = None
    _exec_clause_name: Optional[str] = None

    _installation_checked: bool = False  # flag to avoid checking DR installation multiple times

    _test_case: Optional[TestCaseProgram] = None  # the current test case
    _files: _DRFileManager

    poison_value: int = 0  # If this value is != 0, it will be returned on speculative faulty loads

    # ----------------------------------------------------------------------------------------------
    # Constructor/Destructor
    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        # NOTE: the `bases` argument is not used as DynamoRIO backend does not allow
        #       for customization of the memory layout
        self._enable_mismatch_check_mode = enable_mismatch_check_mode
        self.is_speculative = True  # may be changed by configure_clauses
        self.poison_value = 0  # may be changed later
        self._files = _DRFileManager()

    def __del__(self) -> None:
        self._files.delete_temp_files()

    # ----------------------------------------------------------------------------------------------
    # Public Interfaces
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Prepare the test case to be traced by the DynamoRIO backend.
        This means creating a binary in the RCBF format so that it can be parsed by the backend.
        :param test_case: the test case to load
        :return: None
        """
        self._test_case = test_case

        # remove the previous RCBF file if it exists and create a new one
        self._files.cleanup_on_load_test_case()

        # store the test case in the RCBF format
        test_case.get_obj().save_rcbf(self._files.rcbf)

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """ Implementation of Model.trace_test_case using the DynamoRIO backend. """
        trace = self._trace_test_case_common(inputs, nesting, enable_taints=False)
        self._files.cleanup_after_tracing()
        return trace

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """ Implementation of Model.trace_test_case_with_taints using the DynamoRIO backend. """
        traces = self._trace_test_case_common(inputs, nesting, enable_taints=True)
        assert self._test_case is not None, "Test case must be loaded before tracing"
        taint_reader = _TaintReader(self.layout, self._test_case)
        taints = taint_reader.decode_taints(self._files.taints)
        self._files.cleanup_after_tracing()
        return traces, taints

    def report_coverage(self, path: str) -> None:
        raise NotImplementedError()

    def configure_clauses(self, obs_clause_name: str, exec_clause_name: str) -> None:
        """
        Configure the backend to use the given observation and execution clauses.
        Also check if the given clauses are supported.
        :param obs_clause_name: the name of the observation clause
        :param exec_clause_name: the name of the execution clause
        :return: None
        :raises: ValueError if the given clauses are not supported
        """
        assert self._obs_clause_name is None and self._exec_clause_name is None, \
            "Cannot reconfigure the observation and execution clauses"

        # ensure that the DynamoRIO backend is installed
        self._check_if_installed()

        # check if the contract is supported
        if obs_clause_name not in self.get_supported_obs_clauses(False):
            raise ValueError(f"Unsupported observation clause {obs_clause_name}")
        self._obs_clause_name = obs_clause_name

        if exec_clause_name not in self.get_supported_exec_clauses(False):
            raise ValueError(f"Unsupported execution clause {exec_clause_name}")
        self._exec_clause_name = exec_clause_name

        if exec_clause_name in ["seq", "no_speculation"]:
            self.is_speculative = False

    @classmethod
    def get_supported_obs_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        Get the list of supported observation clauses.
        :return: list of supported observation clauses
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-tracers", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    @classmethod
    def get_supported_exec_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        Get the list of supported execution clauses.
        :return: list of supported execution clauses
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-speculators", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    @classmethod
    def _check_if_installed(cls) -> None:
        """
        Ensure that the DynamoRIO backend is installed.
        :return: None
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if not cls._installation_checked:  # check only once
            cmd = _DRRUN_CMD.format(flags="--trace-output /dev/null", binary="ls", args="/dev/null")
            try:
                output = check_output(cmd, shell=True, stderr=STDOUT).decode("utf-8")
            except (FileNotFoundError, CalledProcessError):
                output = ""
            if '/dev/null' not in output:
                raise FileNotFoundError(
                    "DynamoRIO backend is not installed\n\n\n"
                    "Please follow the instructions in "
                    "https://microsoft.github.io/side-channel-fuzzer/quick-start/")
            cls._installation_checked = True

    def _trace_test_case_common(self, inputs: List[InputData], nesting: int,
                                enable_taints: bool) -> List[CTrace]:
        """
        Execute the test case with the given inputs on DR backend and return the traces
        and the sandbox addresses.
        :param inputs: input sequence to trace
        :param nesting: maximum nesting level to emulated in the model
        :return: list of contract traces, one per input
        """
        assert self._test_case is not None, "No test case was loaded"
        if len(inputs) == 0:
            return []

        # store the input sequence
        save_input_sequence_as_rdbf(inputs, self._files.rdbf)

        # call the backend
        cmd = self._construct_drrun_cmd(enable_taints, nesting)
        _ = check_output(cmd, shell=True)

        # the execution might have had a different layout than before, update it
        self._update_layout()

        # read traces from the trace files
        reader = _TraceReader(self.layout, self._test_case)
        traces = reader.decode_traces(self._files.traces)
        assert len(traces) > 0, "No traces were retrieved from the DynamoRIO backend"
        assert len(traces) == len(inputs), "Mismatch between the number of inputs and traces"

        if self._enable_mismatch_check_mode:
            # In this mode, the contract trace is the register values at the end of the test case
            dbg_reader = _DbgTraceReader(self.layout, self._test_case)
            dbg_traces = dbg_reader.decode_traces(self._files.dbg_traces)
            arch_traces = [CTrace(t.get_typed()[-_N_REGISTERS_IN_DUMP:]) for t in dbg_traces]
            return arch_traces

        return traces

    def _construct_drrun_cmd(self, enable_taints: bool, nesting: int) -> str:
        """
        Construct a command to call the DynamoRIO backend
        with the given test case and input sequence.
        """
        flags = _DRRUN_TRACING_FLAGS + \
            f" --tracer {self._obs_clause_name}" + \
            f" --speculator {self._exec_clause_name}" + \
            f" --max-nesting {nesting}" + \
            f" --max-spec-window {CONF.model_max_spec_window}" \
            f" --trace-output {self._files.traces}"
        if enable_taints:
            flags += f" --taint-output {self._files.taints} --enable-taint-tracker"
        if self._enable_mismatch_check_mode:
            flags += f" --log-level 1 --debug-trace-output {self._files.dbg_traces}"
        if self.poison_value != 0:
            flags += f" --poison-value {self.poison_value}"

        binary = _ADAPTER_PATH
        args = f"{self._files.rcbf} {self._files.rdbf} {self._files.layout}"
        cmd = _DRRUN_CMD.format(flags=flags, binary=binary, args=args)
        # print(cmd)
        return cmd

    def _update_layout(self) -> None:
        """ Update the memory layout based on the addresses communicated by the adapter
        via the bases file. """
        assert self._test_case is not None, "No test case was loaded"
        with open(self._files.layout, 'rb') as f:
            code_base_addr = int.from_bytes(f.read(8), byteorder="little")
            data_base_addr = int.from_bytes(f.read(8), byteorder="little")
        self.layout = SandboxLayout((data_base_addr, code_base_addr), self._test_case.n_actors())


# ==================================================================================================
# Private: File management
# ==================================================================================================
class _DRFileManager:
    """
    Local class responsible for managing temporary files used by the DynamoRIO backend.
    """

    def __init__(self) -> None:
        self.rcbf: str  # tmp file for current test case in RCBF format
        self.rdbf: str  # tmp file for current input sequence in RDBF format
        self.layout: str  # tmp file for receiving memory layout
        self.traces: str  # tmp file for receiving contract traces
        self.dbg_traces: str  # tmp file for receiving debug traces
        self.taints: str  # tmp file for receiving taint traces
        self._create_temp_files()

    def cleanup_on_load_test_case(self) -> None:
        """ Clean up RCBF and RDBF files when loading a new test case """
        with open(self.rcbf, 'wb') as f:
            f.truncate()
        with open(self.rdbf, 'wb') as f:
            f.truncate()

    def cleanup_after_tracing(self) -> None:
        """ Clean up the files that will be used by the adapter to store its output """
        with open(self.traces, 'wb') as f:
            f.truncate()
        with open(self.dbg_traces, 'wb') as f:
            f.truncate()
        with open(self.taints, 'wb') as f:
            f.truncate()
        with open(self.layout, 'wb') as f:
            f.truncate()

    def _create_temp_files(self) -> None:
        with tempfile.NamedTemporaryFile("wb", delete=False) as rcbf_f:
            self.rcbf = rcbf_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as rdbf_f:
            self.rdbf = rdbf_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as trace_f:
            self.traces = trace_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as dbg_trace_f:
            self.dbg_traces = dbg_trace_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as taint_f:
            self.taints = taint_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as bases_f:
            self.layout = bases_f.name

    def delete_temp_files(self) -> None:
        """ Delete all temporary files created for the DynamoRIO backend """
        if os.path.exists(self.rcbf):
            os.unlink(self.rcbf)
        if os.path.exists(self.rdbf):
            os.unlink(self.rdbf)
        if os.path.exists(self.traces):
            os.unlink(self.traces)
        if os.path.exists(self.dbg_traces):
            os.unlink(self.dbg_traces)
        if os.path.exists(self.taints):
            os.unlink(self.taints)
        if os.path.exists(self.layout):
            os.unlink(self.layout)


# ==================================================================================================
# Private: Decoding of Traces
# ==================================================================================================
class _TraceReader:
    """
    Local class responsible for reading traces produced by DynamoRIO backend,
    removing irrelevant information from them, and converting them to the
    format that is expected by the contract model.
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case
        self._decoder = TraceDecoder()

    def decode_traces(self, trace_path: str) -> List[CTrace]:
        """
        Read the traces produced by the DynamoRIO backend and return them in the format
        that is expected by the contract model.
        :return: list of contract traces
        """
        traces: List[CTrace] = []

        # iterate over the binary trace and parse the entries
        raw_traces: List[_RawTrace] = self._decoder.decode_trace_file(trace_path)
        for raw_trace in raw_traces:
            converted = self._raw_to_ctrace(raw_trace)
            if converted:
                traces.append(converted)

        # trim non relevant entries
        traces = self._trim_traces(traces)

        return traces

    def _raw_to_ctrace(self, raw_trace: _RawTrace) -> CTrace:
        trace: List[CTraceEntry] = []

        for entry in raw_trace:
            type_ = TraceEntryType(entry.type)
            if type_ in (TraceEntryType.ENTRY_READ, TraceEntryType.ENTRY_WRITE):
                val = self._layout.data_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="mem", value=val))
            elif type_ == TraceEntryType.ENTRY_PC:
                val = self._layout.code_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="pc", value=val))
            elif type_ == TraceEntryType.ENTRY_IND:
                val = self._layout.code_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="ind", value=val))

        return CTrace(trace)

    def _trim_traces(self, traces: List[CTrace]) -> List[CTrace]:
        """
        Last instruction of the trace is the return instruction, which is inserted automatically
        by the model and thus does not belong to the test case. We remove the corresponding entries
        from the traces.
        :return: the traces with the irrelevant entries removed
        """
        new_traces: List[CTrace] = []
        for trace in traces:
            entry_list = trace.get_typed()

            # Identify observations that belong to the return instruction
            last_mem = None
            last_pc = None
            if entry_list[-1].type_ == "mem":
                last_mem = entry_list[-1].value
                entry_list.pop()
            if entry_list[-1].type_ == "pc":
                last_pc = entry_list[-1].value
                entry_list.pop()

            # In case the return happened multiple times (e.g., due to speculation),
            # remove all corresponding entries
            filtered_list = []
            for entry in entry_list:
                if last_pc is not None and entry.type_ == "pc" and entry.value == last_pc:
                    continue
                if last_mem is not None and entry.type_ == "mem" and entry.value == last_mem:
                    continue
                filtered_list.append(entry)

            new_traces.append(CTrace(filtered_list))

        return new_traces


class _DbgTraceReader:
    """
    Local class responsible for reading debug traces produced by DynamoRIO backend.
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case
        self._decoder = TraceDecoder()

    def decode_traces(self, dbg_path: str) -> List[CTrace]:
        """
        Read the debug traces produced by the DynamoRIO backend and return them in the format
        that is expected by the contract model.
        :return: list of debug traces
        """
        dbg_traces: List[CTrace] = []

        # do the same for debug traces
        raw_dbg_traces: List[_RawDebugTrace] = self._decoder.decode_debug_trace_file(dbg_path)
        for raw_dbg_trace in raw_dbg_traces:
            converted = self._raw_dbg_to_ctrace(raw_dbg_trace)
            if converted:
                dbg_traces.append(converted)

        # trim non relevant entries
        if dbg_traces:
            dbg_traces = self._trim_dbg_traces(dbg_traces)

        return dbg_traces

    def _raw_dbg_to_ctrace(self, raw_dbg_trace: _RawDebugTrace) -> CTrace:
        trace: List[CTraceEntry] = []

        for entry in raw_dbg_trace:
            type_ = DebugTraceEntryType(entry.type)
            if type_ == DebugTraceEntryType.ENTRY_REG_DUMP:
                val = self._layout.code_addr_to_offset(entry.regs.pc)
                trace.append(CTraceEntry(type_="pc", value=val))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xax))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xbx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xcx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xsi))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdi))

        return CTrace(trace)

    def _trim_dbg_traces(self, dbg_traces: List[CTrace]) -> List[CTrace]:
        """ Same as _trim_traces, but for debug traces """
        # Each register dump consists of 1 PC + N register values
        dump_size = 1 + _N_REGISTERS_IN_DUMP

        new_dbg_traces = []
        for dbg_trace in dbg_traces:
            entry_list = dbg_trace.get_typed()

            # Remove the last register dump (corresponding to the return instruction)
            last_pc = None
            if entry_list[-dump_size].type_ == "pc":
                last_pc = entry_list[-dump_size].value
                entry_list = entry_list[:-dump_size]

            # Remove all register dumps corresponding to the return instruction
            filtered_list = []
            skip_count = 0
            for entry in entry_list:
                if skip_count > 0:
                    skip_count -= 1
                    continue
                if last_pc is not None and entry.type_ == "pc" and entry.value == last_pc:
                    skip_count = _N_REGISTERS_IN_DUMP  # skip the register entries as well
                    continue
                filtered_list.append(entry)

            new_dbg_traces.append(CTrace(filtered_list))

        return new_dbg_traces


# ==================================================================================================
# Private: Decoding of Input Taints
# ==================================================================================================
class _TaintReader:
    """
    Local class responsible for reading input taints produced by DynamoRIO backend.

    Taint output format:
    - Input 1:
        [taint_value (8 bytes)]
        ... repeated for each tainted value
        [end_marker (8 bytes)] (the marker is max_uint64)
    - Input 2:
        ...
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._n_actors = test_case.n_actors()

    def decode_taints(self, taint_path: str) -> List[InputTaint]:
        """
        Read the input taints produced by the DynamoRIO backend and return them in the format
        that is expected by the contract model.
        :return: list of input taints
        """
        taints: List[InputTaint] = []

        # for convenience, read the entire file into a numpy array
        array: NDArray[np.uint64] = self._file_to_ndarray(taint_path)
        sandbox_end: int = self._layout.data_area_offset(DataArea.OVERFLOW_PAD)

        taint = InputTaint(self._n_actors)
        linear_view = taint.full_linear_view()
        unfinished = False
        for entry in array:
            val = int(entry)

            # end marker reached? store the current input taint and start a new one
            if val == _EOT_MARKER:
                taints.append(taint)
                taint = InputTaint(self._n_actors)
                linear_view = taint.full_linear_view()
                unfinished = False
                continue
            unfinished = True

            if val > sandbox_end:
                # invalid taint value (may happen because some of the adapter code was tainted)
                continue

            linear_view[val // _BYTES_PER_TAINT_ENTRY] = True

        assert not unfinished, "Taint file ended unexpectedly without end marker"
        return taints

    def _file_to_ndarray(self, path: str) -> NDArray[np.uint64]:
        """
        Read the taint file and convert it to a numpy array.
        :return: numpy array containing the taint entries (uint64 values)
        """
        with open(path, 'rb') as f:
            data = f.read()
        n_entries = len(data) // _BYTES_PER_TAINT_ENTRY
        array = np.frombuffer(data, dtype=np.uint64, count=n_entries)
        return array
