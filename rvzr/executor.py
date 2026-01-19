"""
File: Architecture-independent parts of the adaptor to the executor kernel module

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Set, Generator, Optional, Final
from abc import ABC

import sys
import subprocess
import os.path

import numpy as np
import numpy.typing as npt

from rvzr.logs import ExecutorLogger, warning
from rvzr.config import CONF, ConfigException
from rvzr.sandbox import BaseAddrTuple
from rvzr.stats import FuzzingStats
from rvzr.traces import HTrace, RawHTraceSample, HTraceType
from rvzr.tc_components.test_case_data import save_input_sequence_as_rdbf

if TYPE_CHECKING:
    from rvzr.tc_components.test_case_code import TestCaseProgram
    from rvzr.tc_components.test_case_data import InputData

KMOutputLine = Tuple[int, int, int, int, int, int]
ReadingsArray = npt.NDArray[np.void]

STAT = FuzzingStats()


# ==================================================================================================
# Helper functions
# ==================================================================================================
def km_write(value: str, path: str) -> None:
    """
    Write a value to a file in the /sys filesystem.
    This is used to configure the executor kernel module.
    """
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def _is_smt_enabled() -> bool:
    """
    Check if SMT is enabled on the current CPU.

    :return: True if SMT is enabled, False otherwise
    """
    try:
        out = subprocess.run("lscpu", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        warning("executor", "Could not check if SMT is enabled. Is lscpu installed?")
        return True
    for line in out.stdout.decode().split("\n"):
        if line.startswith("Thread(s) per core:"):
            if line[-1] == "1":
                return False
            return True
    return True


def _can_set_reserved() -> bool:
    """
    Check if setting reserved bits is possible on the current CPU.
    :return: True if it's possible, False otherwise
    """
    actors_conf = CONF.get_actors_conf()
    reserved_requested = False
    for a in actors_conf:
        if 'reserved_bit' in actors_conf[a]['data_properties'] and \
           actors_conf[a]['data_properties']['reserved_bit']:
            reserved_requested = True
            break
        if 'reserved_bit' in actors_conf[a]['data_ept_properties'] and \
           actors_conf[a]['data_ept_properties']['reserved_bit']:
            reserved_requested = True
            break
    if not reserved_requested:
        return True

    if CONF.instruction_set == 'arm64':
        return False  # reserved bits are not (yet?) supported on ARM64

    assert CONF.instruction_set == 'x86-64'
    physical_bits = int(
        subprocess.run(
            "lscpu | grep 'Address sizes' | awk '{print $3}'",
            shell=True,
            check=True,
            capture_output=True).stdout.decode().strip())
    if physical_bits > 51:
        return False
    return True


def _is_kernel_module_installed() -> bool:
    return os.path.isfile("/sys/rvzr_executor/trace")


def _configure_kernel_module() -> None:
    km_write(str(CONF.executor_warmups), '/sys/rvzr_executor/warmups')
    km_write("1" if CONF.enable_pre_run_flush else "0", "/sys/rvzr_executor/enable_pre_run_flush")
    km_write(CONF.executor_mode, "/sys/rvzr_executor/measurement_mode")


def _read_trace(n_reps: int,
                n_inputs: int,
                arch_mode: bool = False) -> Generator[Tuple[int, int, KMOutputLine], None, None]:
    """
    ProgramGenerator function that reads and parses the output of the kernel module.
    The generator handles the batched output of the kernel module and yields the traces one by one.
    The traces are read in reverse order.

    Example:
    Assume the kernel module output for n_reps=2 and n_inputs=2 is:
    ```
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    ```
    then the generator will yield the following tuples:
    ```
    (0, 1, [htrace1, pfc0, .., pfc4])
    (0, 0, [htrace0, pfc0, .., pfc4])
    (1, 1, [htrace1, pfc0, .., pfc4])
    (1, 0, [htrace0, pfc0, .., pfc4])
    ```

    :param n_reps: number of repetitions of the measurements
    :param n_inputs: number of inputs
    :param arch_mode: if True, the kernel module is in architecture mode
    :return: a generator that yields a tuple (repetition, input_id, htrace, [pfc1, ..., pfc5])
    :raises IOError: if the kernel module output is malformed
    """
    if n_inputs <= 0:
        return

    rep_id = 0
    last_input_id = n_inputs - 1
    while rep_id < n_reps:
        input_id: int = last_input_id
        reading_finished: bool = False
        while not reading_finished:
            # read the next batch of traces from the kernel module
            output = subprocess.check_output(
                f"taskset -c {CONF.executor_taskset} cat /sys/rvzr_executor/trace", shell=True)
            lines = output.decode().split("\n")

            # parse the output
            for line in lines:
                # print(rep_id, input_id, line)
                # skip empty lines
                if not line:
                    continue

                # we reached the end of the batch? read the next batch
                if 'done' in line:
                    reading_finished = True
                    break

                # transform the line into a sequence of ints
                line_ints = tuple(int(x) for x in line.split(","))

                # if the line width is unexpected, it's an error
                if len(line_ints) != 6:
                    warning("executor", f"Unexpected line width: {len(line_ints)}")
                    _rewind_km_output_to_end()
                    raise IOError()

                # if the hardware trace is zero, it's an error (except for arch mode)
                if line_ints[0] == 0 and not arch_mode:
                    warning("executor", "Kernel module error; see dmesg for details")
                    _rewind_km_output_to_end()
                    raise IOError()

                # yield the trace
                yield rep_id, input_id, line_ints

                # move to next input
                input_id -= 1
                if input_id < 0:
                    # if we reached the end of a repetition, restart the input counter
                    input_id = last_input_id
                    rep_id += 1
        assert input_id == last_input_id, f"input_id: {input_id}, rep_id: {rep_id}"
    return


def _rewind_km_output_to_end() -> None:
    """
    Read to the end of the kernel module output, until the 'done' line.
    """
    while True:
        output = subprocess.check_output(
            f"taskset -c {CONF.executor_taskset} cat /sys/rvzr_executor/trace", shell=True)
        if 'done' in output.decode():
            break


# ==================================================================================================
# Public: Implementation of the python adapter to the executor kernel module
# ==================================================================================================
class Executor(ABC):
    """
    Interface for the executor module. The executor is a module responsible for executing
    test cases on the CPU-under-test and collecting the corresponding hardware traces.

    The high-level workflow is as follows:
    1. Load the test case code into the kernel module.
    2. Load the test case data (i.e., input sequence) into the kernel module.
    3. Run the measurements by calling the kernel module (see _get_raw_measurements). Each
       measurement is repeated `n_reps` times.
    4. Aggregate the measurements into sets of traces (see _aggregate_measurements).
    """

    _curr_test_case: Optional[TestCaseProgram] = None
    _ignore_list: Set[int]
    _log: Final[ExecutorLogger]
    _TSC_MASK: Final[np.uint64] = np.uint64(0x0FFFFFFFFFFFFFF0)

    _enable_mismatch_check_mode: Final[bool]
    """ mismatch_check_mode: If True, the executor will return GPR values instead of
    hardware traces, which is used to check for mismatches between the model and the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False, skip_setup: bool = False):
        super().__init__()
        self._enable_mismatch_check_mode = enable_mismatch_check_mode

        self._ignore_list = set()
        self._log = ExecutorLogger()
        if skip_setup:
            warning("executor", "Executor starting without setting up the kernel module")
            return

        # Check the execution environment:
        if _is_smt_enabled() and not enable_mismatch_check_mode:
            warning("executor", "SMT is on! You may experience false positives.")
        if not _can_set_reserved():
            raise ConfigException("Cannot set reserved bits on this CPU")

        # Initialize the kernel module
        if not _is_kernel_module_installed():
            print("x86 executor: kernel module not installed\n\n"
                  "Go to https://microsoft.github.io/side-channel-fuzzer/quick-start/ for "
                  "installation instructions.")
            sys.exit(1)
        _configure_kernel_module()
        self._set_vendor_specific_features()

    # ==============================================================================================
    # Public Interface: Test Case Loading and Tracing
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Load a test case into the executor.
        This function must be called before calling `trace_test_case`.

        This function also sets the mismatch check mode in the kernel module if requested.
        The flag has to be set before loading the test case because the kernel module links
        the test case code with different measurement functions based on this flag.

        :param test_case: the test case object to load
        :return: None
        """
        # enable mismatch check mode if requested
        km_write("1" if self._enable_mismatch_check_mode else "0",
                 "/sys/rvzr_executor/enable_dbg_gpr_mode")

        # write the test case to the kernel module
        test_case.get_obj().save_rcbf('/sys/rvzr_executor/test_case')
        self._curr_test_case = test_case

        # reset the ignore list; as we are testing a new program now, the old ignore list is not
        # relevant anymore
        self._ignore_list = set()

    def trace_test_case(self, inputs: List[InputData], n_reps: int) -> List[HTrace]:
        """ Call the executor kernel module to collect the hardware traces for
         the test case (previously loaded with `load_test_case`) and the given inputs.

        :param inputs: list of inputs to be used for the test case
        :param n_reps: number of times to repeat each measurement
        :return: a list of HTrace objects, one for each input
        :raises IOError: if the kernel module output is malformed
        """
        # Skip if it's a dummy call
        if not inputs:
            return []
        n_inputs = len(inputs)

        # Skip if all inputs are ignored
        if n_inputs <= len(self._ignore_list):
            warning("executor", "All inputs are ignored. Skipping measurements")
            return [HTrace.empty_trace() for _ in range(n_inputs)]

        # Store statistics
        STAT.executor_reruns += n_reps * n_inputs

        # Transfer inputs to the kernel module
        # TODO: that's a quick-and-dirty optimization to reduce the number of KM calls;
        # it should be rewritten
        input_sequence = inputs if n_reps % 5 != 0 or n_inputs >= 1000 else inputs * 5
        save_input_sequence_as_rdbf(input_sequence, '/sys/rvzr_executor/inputs')

        # Check that the transfer was successful
        with open('/sys/rvzr_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                raise IOError("Error writing inputs to the kernel module")

        # Call the kernel module and read traces
        all_readings: ReadingsArray = np.ndarray(shape=(n_inputs, n_reps), dtype=RawHTraceSample)
        for rep_id, input_id, readings in \
                _read_trace(n_reps, n_inputs, arch_mode=self._enable_mismatch_check_mode):
            all_readings[input_id][rep_id] = readings

        # Post-process results and return a list of HTrace objects
        traces = self._raw_readings_to_traces(all_readings, n_inputs)
        self._log.dbg_dump_raw_traces(traces)
        return traces

    def _identify_trace_type(self) -> HTraceType:
        """ Identify the type of the traces based on the configuration """
        if self._enable_mismatch_check_mode:
            return "reg"
        if CONF.executor_mode == 'TSC':
            return "tsc"
        return "cache"

    def _raw_readings_to_traces(self, all_readings: ReadingsArray, n_inputs: int) -> List[HTrace]:
        """ Convert the raw readings into HTrace objects and perform post-processing if needed """
        traces = []
        trace_type = self._identify_trace_type()
        for input_id in range(n_inputs):
            raw = all_readings[input_id]

            # No post-processing in mismatch check mode
            if self._enable_mismatch_check_mode:
                traces.append(HTrace(raw, trace_type))
                continue

            # Zero-out traces for ignored inputs
            if input_id in self._ignore_list:
                traces.append(HTrace.invalid_trace(trace_type))
                continue

            # When using TSC mode, we need to mask the lower 4 bits of the trace
            if CONF.executor_mode == 'TSC':
                raw['trace'] &= self._TSC_MASK

            traces.append(HTrace(raw, trace_type))
        return traces

    # ==============================================================================================
    # Public Interface: Base Addresses
    def read_base_addresses(self) -> BaseAddrTuple:
        """
        Reads the base addresses of two sandbox regions (data and code) from the executor
        kernel module and returns them as a tuple.
        This data is primarily used to synchronize the memory layout between the executor
        and the model.
        :return: a tuple with the base addresses of the data and code regions
        """

        with open('/sys/rvzr_executor/print_data_base', 'r') as f:
            data_start = f.readline()
        with open('/sys/rvzr_executor/print_code_base', 'r') as f:
            code_start = f.readline()
        return int(data_start, 16), int(code_start, 16)

    # ==============================================================================================
    # Public Interface: Ignore List
    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero

        :param ignore_list: a list of input IDs to ignore
        """
        self._ignore_list = set(ignore_list)

    def extend_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Add a list of new inputs IDs to the current ignore list.

        :param ignore_list: a list of input IDs to add to the ignore list
        """
        self._ignore_list.update(ignore_list)

    # ==============================================================================================
    # Public Interface: Quick and Dirty Mode
    def set_quick_and_dirty(self, state: bool) -> None:
        """
        Enable or disable the quick and dirty mode in the executor. In this mode, the executor
        will skip some of the stabilization phases, which will make the measurements faster but
        less reliable.

        :param state: True to enable the quick and dirty mode, False to disable it
        """
        km_write("1" if state else "0", "/sys/rvzr_executor/enable_quick_and_dirty_mode")

    # ==============================================================================================
    # Private Interface: Vendor-specific Features
    def _set_vendor_specific_features(self) -> None:
        """ Set vendor-specific features in the kernel module """
