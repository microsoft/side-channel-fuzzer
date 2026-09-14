"""
File: Classes representing contract and hardware traces as well as derived containers thereof.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import Counter

from typing import List, Optional, Final, NamedTuple, Tuple, Dict, Generator, Callable, Literal
from typing_extensions import assert_never

import xxhash
import numpy as np
import numpy.typing as npt

from .tc_components.test_case_data import InputData, InputID
from .tc_components.test_case_code import TestCaseProgram
from .config import CONF

_REG_ID_TO_NAME_X86 = {0: "rax", 1: "rbx", 2: "rcx", 3: "rdx", 4: "rsi", 5: "rdi"}
_REG_ID_TO_NAME_ARM = {0: "x0", 1: "x1", 2: "x2", 3: "x3", 4: "x4", 5: "x5"}

# ==================================================================================================
# Contract Trace
# ==================================================================================================
CTraceEntryType = Literal["mem", "pc", "val", "reg", "ind"]


class CTraceEntry(NamedTuple):
    """
    Named tuple that represents a single entry in a contract trace.
    """
    type_: CTraceEntryType
    value: int


UntypedCTrace = List[int]


class CTrace:
    """
    Class representing a contract trace. It encapsulates a list of integers that represent a raw
    trace collected from the model, and it provides basic comparison and hashing interfaces that
    allow to compare traces for equality and to store them in sets or dictionaries.
    """
    _trace: Final[List[CTraceEntry]]
    _untyped: Final[UntypedCTrace]
    _hash: Final[int]

    _printed_as_l1d_map: bool = False
    """ Flag indicating that the trace should be printed  """

    # ==============================================================================================
    # Constructors

    @classmethod
    def empty_trace(cls) -> CTrace:
        """ Produce a dummy CTrace object with empty raw trace """
        return cls([])

    def __init__(self, trace: List[CTraceEntry]) -> None:
        self._trace = trace
        self._untyped = [entry.value for entry in trace]
        self._hash = xxhash.xxh64(str(self._untyped).encode(), seed=0).intdigest()

    # ==============================================================================================
    # Printers

    def __str__(self) -> str:
        # For most cases, just print the hash value
        if not self._printed_as_l1d_map:
            return str(self._hash)

        # When printing as L1D map was requested, print the trace as a 64-bit bit mask
        # representing the cache state
        map_value = 0
        for address in self._untyped:
            page_offset = (address & 0b111111000000) >> 6
            cache_set_index = 0x8000000000000000 >> page_offset
            map_value |= cache_set_index
        map_str = f"{map_value:064b}"
        map_str = map_str.replace("0", ".").replace("1", "^")
        return map_str

    def full_str(self,
                 m_col: str = "",
                 pc_col: str = "",
                 val_col: str = "",
                 reset_col: str = "") -> str:
        """
        Return a string representation of the complete typed trace.
        Optionally, the colors can be specified for memory addresses, program counters, and values.

        Example output: [mem: 0x100, pc: 0x200, val: 0x300]

        :param m_col: color for memory addresses entries
        :param pc_col: color for program counters entries
        :param val_col: color for values entries
        :param reset_col: color reset string
        :return: colorized string representation of the trace
        """
        assert reset_col or not (m_col or pc_col or val_col), \
            "If any color is set, reset_col must be set as well"

        s = "["
        len_ = len(self._trace)
        reg_names = _REG_ID_TO_NAME_X86 if CONF.instruction_set == "x86-64" else _REG_ID_TO_NAME_ARM
        for i, item in enumerate(self._trace):
            if item.type_ == "mem":
                s += "mem: " + m_col + hex(item.value) + reset_col
            elif item.type_ == "pc":
                s += "pc: " + pc_col + hex(item.value) + reset_col
            elif item.type_ == "ind":
                s += "indcall: " + pc_col + hex(item.value) + reset_col
            elif item.type_ == "val":
                s += "val: " + val_col + hex(item.value) + reset_col
            elif item.type_ == "reg":
                name = reg_names[i]
                s += name + ": " + hex(item.value) + reset_col
            else:
                assert_never(item.type_)
            if i != len_ - 1:
                s += ", "
        return s + "]"

    # ==============================================================================================
    # Public Methods

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CTrace):
            raise NotImplementedError("Cannot compare CTrace with non-CTrace object")
        return self._hash == other._hash

    def __lt__(self, other: CTrace) -> bool:
        return self._hash < other._hash

    def __gt__(self, other: CTrace) -> bool:
        return self._hash > other._hash

    def __len__(self) -> int:
        return len(self._untyped)

    def __hash__(self) -> int:
        return self._hash

    def is_empty(self) -> bool:
        """ Check if the trace was created from an empty list or via `empty_trace()` """
        return len(self) == 0

    def get_untyped(self) -> UntypedCTrace:
        """
        Get a raw trace containing only integers values of the CTrace without type information
        """
        return self._untyped

    def get_typed(self) -> List[CTraceEntry]:
        """ Get the full trace used to construct the CTrace object """
        return self._trace

    def set_printed_as_l1d(self, val: bool = True) -> None:
        """
        Set the flag indicating that the trace should be printed as L1D map.
        This is normally used only for debugging purposes.
        :param val: flag value
        :return: None
        """
        self._printed_as_l1d_map = val


# ==================================================================================================
# Hardware Trace
# ==================================================================================================
HTraceType = Literal["cache", "tsc", "reg"]

RawHTraceSample = np.dtype([
    ("trace", np.uint64),
    ("pfc0", np.uint64),
    ("pfc1", np.uint64),
    ("pfc2", np.uint64),
    ("pfc3", np.uint64),
    ("pfc4", np.uint64),
])
ArrayOfSamples = npt.NDArray[np.void]
PFCTuple = Tuple[int, int, int, int, int]


class HTrace:
    """
    Class representing a sequence of hardware trace samples. The samples are normally received from
    the executor: It executes a test case program with a given input multiple times, and each
    execution produces a single hardware trace and a set of readings from performance counters.
    The results of such repeated executions are collected into a single HTrace object.
    """
    _raw: Final[ArrayOfSamples]
    _hash: Final[int]
    _is_corrupted_or_ignored: Final[bool]
    _max_pfc: Optional[PFCTuple] = None
    type_: Final[HTraceType]

    # ==============================================================================================
    # Constructors

    @classmethod
    def empty_trace(cls, type_: HTraceType = "cache") -> HTrace:
        """ Get a dummy HTrace object with empty hardware trace and zeros for perf counters """
        return cls(np.ndarray(0, dtype=RawHTraceSample), type_)

    @classmethod
    def invalid_trace(cls, type_: HTraceType = "cache") -> HTrace:
        """ Get a dummy HTrace object with corrupted hardware trace and zeros for perf counters """
        invalid_sample: npt.NDArray[np.void] = np.zeros(1, dtype=RawHTraceSample)
        return cls(invalid_sample, type_)

    def __init__(self, htrace_samples: ArrayOfSamples, type_: HTraceType = "cache") -> None:
        # check that the input has the expected shape
        assert htrace_samples.ndim == 1, "htrace_samples must be a 1D array"
        assert htrace_samples.dtype == RawHTraceSample, "htrace_samples must be of type RawHTrace"

        # store and process the samples
        self._raw = htrace_samples
        self._hash = xxhash.xxh64(str(htrace_samples['trace']).encode(), seed=0).intdigest()
        self._is_corrupted_or_ignored = all(x == 0 for x in htrace_samples['trace'])
        self.type_ = type_

    # ==============================================================================================
    # Printers

    def __str__(self) -> str:
        return str(self._hash)

    def full_str(self,
                 line_prefix: str = "",
                 region1_col: str = "",
                 region2_col: str = "",
                 reset_col: str = "") -> str:
        """
        Return a string (table) representation of the set of samples used to create this trace

        :param line_prefix: string to prepend to each line
        :return: string representation of the trace
        """
        # Nothing to print if the trace is empty
        if self.is_empty():
            return line_prefix
        if self.type_ == "cache":
            return self._full_cache_str(line_prefix, region1_col, region2_col, reset_col)
        if self.type_ == "tsc":
            return self._full_tsc_str(line_prefix)
        if self.type_ == "reg":
            return self._full_arch_str(line_prefix)

        assert_never(self.type_)
        return ""  # pylint: disable=unreachable  # justification: mypy workaround

    def _full_arch_str(self, line_prefix: str) -> str:
        """ Return a string representation of an architectural trace.
        Example output:
        [rax:0x00000000000001, rbx:0x00000000000002, rcx:0x00000000000003, rdx:0x00000000000004,
        rsi:0x00000000000005, rdi:0x00000000000006]
        """
        assert len(self._raw) == 1, "Invalid trace shape"
        s = line_prefix
        reg_names = _REG_ID_TO_NAME_X86 if CONF.instruction_set == "x86-64" else _REG_ID_TO_NAME_ARM
        s += "["
        s += f"{reg_names[0]}: 0x{self._raw[0]['trace']:x}, "
        s += f"{reg_names[1]}: 0x{self._raw[0]['pfc0']:x}, "
        s += f"{reg_names[2]}: 0x{self._raw[0]['pfc1']:x}, "
        s += f"{reg_names[3]}: 0x{self._raw[0]['pfc2']:x}, "
        s += f"{reg_names[4]}: 0x{self._raw[0]['pfc3']:x}, "
        s += f"{reg_names[5]}: 0x{self._raw[0]['pfc4']:x}"
        s += "]"
        return s

    def _full_tsc_str(self, line_prefix: str) -> str:
        """ Return a string representation of a TSC trace.
        Example output:
        00000001 [16]
        00000002 [16]
        """
        s = ""
        mask = np.uint64(0xFFFFFFFFFFFFFF)
        counter = Counter(self._raw['trace'])
        trace_distribution = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        for t, c in trace_distribution:
            t = t & mask
            s += f"{line_prefix}{t:08} [{c}]\n"
        return s

    def _full_cache_str(self, line_prefix: str, r1_col: str, r2_col: str, reset_col: str) -> str:
        """ Return a string representation of a cache trace
        Example output:
            .....^..................^....................................... [16]
            ........................^....................................... [16]
        """
        s = ""
        counter = Counter(self._raw['trace'])
        trace_distribution = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        for t, c in trace_distribution:
            line = f"{t:064b}"
            line = line.replace("0", ".").replace("1", "^")
            line = r1_col + line[0:8] + r2_col + line[8:16] \
                + r1_col + line[16:24] + r2_col + line[24:32] \
                + r1_col + line[32:40] + r2_col + line[40:48] \
                + r1_col + line[48:56] + r2_col + line[56:64] \
                + reset_col + line[64:]
            s += f"{line_prefix}{line} [{c}]\n"
        return s

    def full_pair_str(self,
                      other: HTrace,
                      r1_col: str = "",
                      r2_col: str = "",
                      res_col: str = "") -> str:
        """ Return a string representation of two sample distributions side-by-side"""
        if self.type_ == "cache":
            assert other.type_ == "cache"
            return self._full_cache_pair_str(other, r1_col, r2_col, res_col)
        if self.type_ == "tsc":
            assert other.type_ == "tsc"
            return self._full_tsc_pair_str(other)
        if self.type_ == "reg":
            raise NotImplementedError("Cannot compare architectural traces")

        assert_never(self.type_)
        return ""  # pylint: disable=unreachable  # justification: mypy workaround

    def _full_tsc_pair_str(self, other: HTrace) -> str:
        """ Return a string representation of two TSC sample distributions side-by-side
        Example output:
        00000001        |16     | 8      |
        00000002        |16     | 24     |
        """
        mask = np.uint64(0xFFFFFFFFFFFFFF)
        c1 = Counter(self.get_raw_traces())
        c2 = Counter(other.get_raw_traces())
        keys = set(c1.keys()) | set(c2.keys())
        traces = sorted(keys, key=lambda x: (c1[x] << 10000) + c2[x], reverse=True)

        final_str = ""
        for t in traces:
            t = t & mask
            final_str += f"{t:08} | {c1[t]:<6} | {c2[t]:<6} |\n"
        return final_str

    def _full_cache_pair_str(self, other: HTrace, r1_col: str, r2_col: str, res_col: str) -> str:
        """ Return a string representation of two cache sample distributions side-by-side
        Example output:
        .....^..................^....................................... |16     | 8      |
        .....^.......................................................... |16     | 24     |
        """
        c1 = Counter(self.get_raw_traces())
        c2 = Counter(other.get_raw_traces())
        keys = set(c1.keys()) | set(c2.keys())
        traces = sorted(keys, key=lambda x: (c1[x] << 10000) + c2[x], reverse=True)

        final_str = ""
        for t in traces:
            s = f"{t:064b}"
            s = s.replace("0", ".").replace("1", "^")
            s = r1_col + s[0:8] + r2_col + s[8:16] \
                + r1_col + s[16:24] + r2_col + s[24:32] \
                + r1_col + s[32:40] + r2_col + s[40:48] \
                + r1_col + s[48:56] + r2_col + s[56:64] \
                + res_col + s[64:]
            final_str += s + f" | {c1[t]:<6} | {c2[t]:<6}|\n"
        return final_str

    # ==============================================================================================
    # Public Methods

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HTrace):
            raise NotImplementedError("Cannot compare HTrace with non-HTrace object")
        return self._hash == other._hash

    def __len__(self) -> int:
        return len(self._raw)

    def __hash__(self) -> int:
        return self._hash

    def merge(self, other: HTrace) -> HTrace:
        """
        Merge two HTrace objects into a single HTrace object
        :param other: HTrace object to merge with
        :return: A new HTrace object that contains all samples from both objects
        """
        samples = np.concatenate([self._raw, other._raw])  # pylint: disable=protected-access
        # justification: other is also an HTrace, so accessing its private _raw is same-class access
        return HTrace(samples, self.type_)

    def is_empty(self) -> bool:
        """ Check if the trace was created from an empty sample or via `empty_trace()` """
        return len(self) == 0

    def is_corrupted_or_ignored(self) -> bool:
        """
        Check if the trace was created from a corrupted sample.
        A corrupted sample is a sample were all values are zero, which is a way that executor
        signals that the trace was not collected properly.
        """
        return self._is_corrupted_or_ignored

    def get_raw_readings(self) -> ArrayOfSamples:
        """ Get all raw readings used to construct the HTrace object (including both the trace and
        the performance counters) """
        return self._raw

    def get_raw_traces(self) -> npt.NDArray[np.uint64]:
        """ Get all raw traces in the HTrace object (does NOT include performance counters) """
        return self._raw['trace']

    def sample_size(self) -> int:
        """ Get the number of htrace samples in the HTrace object """
        return len(self._raw)

    def get_max_pfc(self) -> PFCTuple:
        """ Get the maximum values of performance counters in the HTrace object """
        if self._max_pfc is None:
            new_max_pfc = (0, 0, 0, 0, 0)
            for sample in self._raw:
                if sample['pfc0'] > new_max_pfc[0]:
                    new_max_pfc = (int(sample['pfc0']), int(sample['pfc1']), int(sample['pfc2']),
                                   int(sample['pfc3']), int(sample['pfc4']))
            self._max_pfc = new_max_pfc
        return self._max_pfc


# ==================================================================================================
# Trace Containers
# ==================================================================================================
class TraceBundle(NamedTuple):
    """
    Container for a set of measurements produced by executing a test case with a given input on
    the model and on the executor. It contains the input, the input ID, the contract trace, the
    hardware trace.
    """
    input_id: InputID
    input_: InputData
    ctrace: CTrace
    htrace: HTrace


HWEquivalenceFunction = Callable[[HTrace, HTrace], bool]


def _default_eq_function(htrace1: HTrace, htrace2: HTrace) -> bool:
    """ Default equivalence function that compares hardware traces for equality """
    return htrace1 == htrace2


class HardwareEqClass:
    """
    Container for a set of TraceBundles that are hardware-equivalent;
    that is, all TraceBundles in the list have similar hardware trace.
    Note that the notion of similarity is configurable and defined by CONF.analyser
    """

    htrace: Final[HTrace]
    """ hardware trace that all measurements in the equivalence class share """

    measurements: Final[List[TraceBundle]]
    """ a list of TraceBundles that are hardware-equivalent """

    # ==============================================================================================
    # Constructors

    def __init__(self, measurements: List[TraceBundle]) -> None:
        self.htrace = measurements[0].htrace
        self.measurements = measurements

    @classmethod
    def build_hw_classes(
        cls,
        measurements: List[TraceBundle],
        equivalence_function: HWEquivalenceFunction = _default_eq_function
    ) -> List[HardwareEqClass]:
        """
        Break down a list of measurements into hardware equivalence classes.
        :param measurements: a list of measurements
        :param equivalence_function: a function that compares two hardware traces and returns True
                if they are equivalent (i.e., they are similar enough to be considered the same)
        :return: List of hardware classes formed from the input measurements
        """
        # Collect lists of measurements with equivalent hardware traces
        hw_groups: Dict[int, List[TraceBundle]] = {}
        diverging_htraces: List[HTrace] = []
        for measurement in measurements:
            htrace = measurement.htrace

            # First iteration: create a new hardware equivalence class
            if not diverging_htraces:
                diverging_htraces.append(htrace)
                hw_groups[hash(htrace)] = [measurement]
                continue

            # Subsequent iterations: check if the htrace is equivalent to any existing class
            for htrace_other in diverging_htraces:
                if equivalence_function(htrace, htrace_other):
                    hw_groups[hash(htrace_other)].append(measurement)
                    break
            else:
                diverging_htraces.append(htrace)
                hw_groups[hash(htrace)] = [measurement]

        # Create HardwareEqClass objects for each group
        hw_classes: List[HardwareEqClass] = []
        for group in hw_groups.values():
            hw_classes.append(cls(group))
        return hw_classes

    # ==============================================================================================
    # Public Methods

    def __len__(self) -> int:
        return len(self.measurements)

    def __iter__(self) -> Generator[TraceBundle, None, None]:
        yield from self.measurements

    def __getitem__(self, index: int) -> TraceBundle:
        return self.measurements[index]

    def __eq__(self, other: object) -> bool:
        """
        Compare two hardware equivalence classes for equality.
        Two classes are equal if they have the same hardware trace and the same measurements.
        """
        if not isinstance(other, HardwareEqClass):
            raise NotImplementedError("Cannot compare HardwareEqClass with object of another type")
        return self.htrace == other.htrace and self.measurements == other.measurements


class ContractEqClass:
    """
    ContractEqClass is a container for a set of TraceBundles that are contract-equivalent;
    that is, all TraceBundles in the list have the same contract trace.
    """

    ctrace: Final[CTrace]
    """ contract trace that all measurements in the equivalence class share """

    measurements: Final[List[TraceBundle]]
    """ list of TraceBundles that are contract-equivalent """

    _hw_classes: Optional[List[HardwareEqClass]] = None

    # ==============================================================================================
    # Constructors

    def __init__(self, measurements: List[TraceBundle]) -> None:
        self.ctrace = measurements[0].ctrace
        self.measurements = measurements

        # check that all measurements have the same contract trace
        for measurement in measurements:
            assert measurement.ctrace == self.ctrace, "All measurements must have the same ctrace"

    @classmethod
    def build_contract_classes(cls, measurements: List[TraceBundle]) -> List[ContractEqClass]:
        """
        Break down a list of measurements into contract equivalence classes
        :param measurements: a list of measurements
        :return: List of contract classes formed from the input measurements
        """
        # Collect lists of measurements with equivalent contract traces
        eq_groups: Dict[int, List[TraceBundle]] = {}
        for measurement in measurements:
            ctrace = measurement.ctrace
            hash_ = hash(ctrace)
            if hash_ not in eq_groups:
                eq_groups[hash_] = [measurement]
            else:
                eq_groups[hash_].append(measurement)

        # Create ContractEqClass objects for each group
        eq_classes: List[ContractEqClass] = []
        for group in eq_groups.values():
            eq_classes.append(cls(group))
        return eq_classes

    def __len__(self) -> int:
        return len(self.measurements)

    def set_hw_classes(self, hw_classes: List[HardwareEqClass]) -> None:
        """
        Set the hardware equivalence classes for this contract equivalence class.
        :param hw_classes: a dictionary of hardware equivalence classes indexed by htrace hash
        """
        assert self._hw_classes is None, "Attempting to set hardware equivalence classes twice"
        self._hw_classes = hw_classes

    def set_trivial_hw_classes(self) -> None:
        """
        Set the hardware equivalence classes for this contract equivalence class by directly
        comparing hardware traces for equality.
        """
        assert self._hw_classes is None, "Attempting to set hardware equivalence classes twice"
        self._hw_classes = HardwareEqClass.build_hw_classes(self.measurements)

    def get_hw_classes(self) -> List[HardwareEqClass]:
        """
        Get a dictionary of all hardware equivalence classes
        in the contract equivalence class; indexed by htrace hash.
        """
        assert self._hw_classes is not None, "Hardware equivalence classes not set"
        return self._hw_classes


class Violation(ContractEqClass):
    """
    Violation is a special type of equivalence class that represents a violation of a contract.
    It is a container for a list of measurements (TraceBundle) that triggered the violation
    as well as a complete sequence of inputs that triggered the violation and the test case program.
    """

    input_sequence: List[InputData]
    """ complete sequence of inputs that triggered the violation """

    test_case_code: Final[TestCaseProgram]
    """ test case program that triggered the violation """

    # ==============================================================================================
    # Constructors

    def __init__(self, measurements: List[TraceBundle], input_sequence: List[InputData],
                 test_case_code: TestCaseProgram) -> None:
        super().__init__(measurements)
        self.input_sequence = input_sequence
        self.test_case_code = test_case_code

    @classmethod
    def from_contract_eq_class(cls, eq_class: ContractEqClass, input_sequence: List[InputData],
                               test_case_code: TestCaseProgram) -> Violation:
        """
        Create a Violation object from a ContractEqClass object
        :param eq_class: ContractEquivalenceClass object
        :param input_sequence: complete sequence of inputs that triggered the violation
        :return: Violation object
        """
        violation = cls(eq_class.measurements, input_sequence, test_case_code)
        violation.set_hw_classes(eq_class.get_hw_classes())
        return violation

    @classmethod
    def pseudo_violation_from_inputs(cls, input_sequence: List[InputData],
                                     test_case_code: TestCaseProgram) -> Violation:
        """
        Create a pseudo-violation object from a list of inputs.

        This interface is used by the variants of the fuzzer that rely on non-standard definition
        of violations (e.g., ArchFuzzer). Such fuzzers may not produce traces, yet they still
        have to return a violation object from the analyser.

        :param input_: input that triggered the pseudo-violation
        :return: Violation object
        """
        measurements = []
        hw_classes = []
        for i, input_ in enumerate(input_sequence):
            bundle = TraceBundle(InputID(i), input_, CTrace.empty_trace(), HTrace.empty_trace())
            measurements.append(bundle)
            hw_classes.append(HardwareEqClass([bundle]))
        violation = cls(measurements, input_sequence, test_case_code)
        violation.set_hw_classes(hw_classes)
        return violation

    # ==============================================================================================
    # Public Methods
    def full_str(self, region1_col: str = "", region2_col: str = "", reset_col: str = "") -> str:
        """
        Return a string representation of the violation, including the contract and hardware
        traces of all measurements in the violation
        """
        # pylint: disable=too-many-locals  # justification: the method is clear enough as is

        s = "Violation Details:\n"

        # Four cases to consider:
        hw_classes = self._hw_classes

        # 1. No hardware equivalence classes (set_hw_classes() was never called)
        if hw_classes is None or not hw_classes:
            s += f"  Contract trace: (hash {self.ctrace})\n"
            s += f"    {self.ctrace.full_str()} \n"
            s += "  Hardware traces:\n"
            for measurement in self.measurements:
                s += measurement.htrace.full_str("    ") + "\n"
            return s

        # 2. Only one measurement in the violation (normally the case for ArchFuzzer)
        if len(hw_classes) == 1:
            s += "  Special Case: Single-input violation\n"
            s += f"  Input ID: {self.measurements[0].input_id}\n"
            s += f"  Contract trace: (hash {self.ctrace})\n"
            s += f"    {self.ctrace.full_str()} \n"
            s += "  Hardware traces:\n"
            s += f"    {hw_classes[0].htrace.full_str()} \n"
            return s

        # 3. If there are two HW classes, print them side by side for improved readability
        hw_classes = self.get_hw_classes()
        if len(hw_classes) == 2:
            inputs1 = [m.input_id for m in hw_classes[0]]
            inputs2 = [m.input_id for m in hw_classes[1]]
            htrace1 = hw_classes[0][0].htrace
            htrace2 = hw_classes[1][0].htrace
            trace_table = htrace1.full_pair_str(htrace2, region1_col, region2_col, reset_col)

            line_width = max(len(line) for line in trace_table.splitlines())
            assert line_width > 19, "Invalid trace table"
            trace_width = line_width - 19

            header = "\n" + "-" * line_width + "\n"
            header += f"{'HTrace':^{trace_width}} | ID:{inputs1[0]:<3} | ID:{inputs2[0]:<3}|\n"
            header += "-" * line_width + "\n"
            s += header + trace_table
            return s

        # 4. With more than two HW classes, print each HW class separately
        for hw_class in hw_classes:
            inputs = [measurement.input_id for measurement in hw_class]
            s += "  Inputs "
            s += f"{inputs}\n" if len(inputs) < 4 else f"{inputs[:4]} (+ {len(inputs) - 4} )\n"
            s += hw_class.htrace.full_str("    ", region1_col, region2_col, reset_col)
        s += "\n"
        return s
