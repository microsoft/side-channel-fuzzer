"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
from copy import deepcopy
from collections import OrderedDict
from typing import List, Dict, TextIO, Any, TypedDict, Set, Literal
from types import ModuleType

import yaml

from .arch.x86 import config as x86_config
from .arch.arm64 import config as arm64_config

# ==================================================================================================
# Custom Types
# ==================================================================================================
PagePropertyName = Literal['present', 'writable', 'user', 'write-through', 'cache-disable',
                           'accessed', 'dirty', 'executable', 'reserved_bit', 'randomized']
PageConf = Dict[PagePropertyName, bool]


class ActorConf(TypedDict):
    """ Type definition for actor configuration """
    name: str
    mode: str
    privilege_level: str
    observer: bool
    data_properties: PageConf
    data_ept_properties: PageConf
    instruction_blocklist: Set[str]
    fault_blocklist: Set[str]


ActorConfKey = Literal["name", "mode", "privilege_level", "observer", "data_properties",
                       "data_ept_properties", "instruction_blocklist", "fault_blocklist"]

ActorsConf = Dict[str, ActorConf]

Architecture = Literal["x86-64", "arm64"]


# ==================================================================================================
# Helper classes
# ==================================================================================================
class IncludeLoader(yaml.SafeLoader):
    """
    Helper class to enable `!include` statements in configuration files
    """
    visited: List[str] = []
    file_id_counter: int = 0

    def __init__(self, stream: TextIO, include_dir: str = "") -> None:
        self._search_paths = [os.path.split(stream.name)[0]]
        if include_dir:
            self._search_paths.append(include_dir)
        self.visited.append(os.path.abspath(stream.name))
        super(IncludeLoader, self).__init__(stream)

    def __del__(self) -> None:
        if self.visited:
            self.visited.pop()

    def include(self, node: yaml.Node) -> Any:
        """
        Include another YAML file
        """
        # find the included file
        relative_filename: str = self.construct_scalar(node)  # type: ignore
        for root in self._search_paths:
            filename = os.path.join(root, relative_filename)
            if os.path.exists(filename):
                break
        else:
            raise ConfigException(f"Included file {relative_filename} does not exist")

        # check for cycles
        if os.path.abspath(filename) in self.visited:
            raise ConfigException(f"Circular include detected in {filename}")

        with open(filename, 'r') as f:
            return yaml.load(f, IncludeLoader)

    def construct_yaml_map(self, node: yaml.MappingNode) -> Dict[Any, Any]:
        """
        Custom constructor that renames all `file` keys to `file_<unique_id>` to prevent multiple
        include statements from overwriting each other
        """
        for k, _ in node.value:
            if k.value == 'file':
                k.value = f'file_{self.file_id_counter}'
                self.file_id_counter += 1
        data = self.construct_mapping(node)
        return data


IncludeLoader.add_constructor('!include', IncludeLoader.include)
IncludeLoader.add_constructor(u'tag:yaml.org,2002:map', IncludeLoader.construct_yaml_map)


class ConfigException(SystemExit):

    def __init__(self, message: str) -> None:
        super().__init__("\nCONFIG ERROR: " + message + "\n")


def _get_architecture() -> Architecture:
    with open('/proc/cpuinfo', 'r') as f:
        for line in f:
            if 'AuthenticAMD' in line or 'GenuineIntel' in line:
                return 'x86-64'
            if 'CPU implementer' in line:
                return 'arm64'
        return 'x86-64'


def _get_cpu_vendor() -> str:
    with open('/proc/cpuinfo', 'r') as f:
        for line in f:
            if 'AuthenticAMD' in line:
                return 'x86-64-amd'
            if 'GenuineIntel' in line:
                return 'x86-64-intel'
            if 'CPU implementer' in line:
                return 'arm64'
        return 'x86-64-intel'


# ==================================================================================================
# Main configuration class
# ==================================================================================================
class Conf:
    """
    Data class to store global configuration options. It implements the Borg pattern to ensure that
    all instances share the same state. The configuration options are loaded from a YAML file and
    can be accessed as class attributes.
    """

    # ==============================================================================================
    # Fuzzer
    fuzzer: str = "basic"
    """ fuzzer: type of the fuzzing algorithm """
    enable_priming: bool = True
    """ enable_priming: whether to check violations with priming """
    enable_speculation_filter: bool = False
    """ enable_speculation_filter: if True, discard test cases that don't trigger speculation"""
    enable_observation_filter: bool = False
    """ enable_observation_filter: if True,discard test cases that don't leave speculative traces"""
    enable_fast_path_model: bool = True
    """ enable_fast_path_boosting: if enabled, the same contract trace will be used
    for all inputs in the same taint-based input class """

    # ==============================================================================================
    # Program Generator
    generator: str = "random"
    """ generator: type of the program generator """
    instruction_set: Architecture = _get_architecture()
    """ instruction_set: ISA under test """
    instruction_categories: List[str] = []
    """ instruction_categories: list of instruction categories to use for generating programs """
    instruction_allowlist: List[str] = []
    """ instruction_allowlist: list of instructions to use for generating programs;
    combined with instruction_categories; has priority over instruction_blocklist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    instruction_blocklist: List[str] = []
    """ instruction_blocklist: list of instruction that will NOT be used for generating programs;
    filters out instructions from instruction_categories, but not from instruction_allowlist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    instruction_blocklist_append: List[str] = []
    """ instruction_blocklist_append: same as instruction_blocklist, but the list is added
    to the existing blocklist instead of replacing it """
    program_generator_seed: int = 0
    """ program_generator_seed: seed of the program generator; if set to zero, a random seed
    will be used """
    program_size: int = 24
    """ program_size: size of generated programs """
    avg_mem_accesses: int = 12
    """ avg_mem_accesses: average number of memory accesses in generated programs """
    min_bb_per_function: int = 1
    """ min_bb_per_function: minimal number of basic blocks per function in generated programs """
    max_bb_per_function: int = 2
    """ max_bb_per_function: maximum number of basic blocks per function in generated programs """
    min_successors_per_bb: int = 2
    """ min_bb_per_function: min. number of successors for each basic block in generated programs
    Note 1: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successor is required
    for correctness"""
    max_successors_per_bb: int = 2
    """ min_bb_per_function: min. number of successors for each basic block in generated programs
    Note: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successor is required
    for correctness """
    register_allowlist: List[str] = []
    """ register_allowlist: list of registers that CAN be used for generating programs;
     has higher priority than register_blocklist.
     The resulting list is: (all registers - register_blocklist) + register_allowlist """
    register_blocklist: List[str] = []
    """ register_blocklist: list of registers that will NOT be used for generating programs;
     has lower priority than register_allowlist.
     The resulting list is: (all registers - register_blocklist) + register_allowlist """
    faults_allowlist: List[str] = []
    """ faults_allowlist: by default, generator will produce programs that never
    trigger exceptions. This option modifies this behavior by permitting the generator to produce
    'unsafe' instruction sequences that could potentially trigger an exception. Model and executor
     will also be configured to handle these exceptions gracefully """

    # ==============================================================================================
    # Input Data Generator
    data_generator: str = 'random'
    """ data_generator: type of the input generator """
    data_generator_seed: int = 10
    """ data_generator_seed: input generation seed; will use a random seed if set to zero """
    data_generator_entropy_bits: int = 31
    """ data_generator_entropy_bits: entropy of the random values created by the input generator """
    inputs_per_class: int = 2
    """ inputs_per_class: number of inputs per input class """
    input_gen_probability_of_special_value: float = 0.05
    """ input_gen_probability_of_special_value: probability of generating a special value
    (zero or maximum value) when setting a register value in the input generator. This is used
    to test fast paths in the microarchitecture """

    # ==============================================================================================
    # Contract Model
    model_backend: str = 'unicorn'
    """ model_backend: The backend used to collect contract traces on generated test cases """
    contract_execution_clause: List[str] = ["seq"]
    """ contract_execution_clause: """
    contract_observation_clause: str = 'ct'
    """ contract_observation_clause: """
    model_min_nesting: int = 1
    """ model_max_nesting: """
    model_max_nesting: int = 30
    """ model_max_nesting: """
    model_max_spec_window: int = 250
    """ model_max_spec_window: """

    # ==============================================================================================
    # Executor
    executor: str = _get_cpu_vendor()
    """ executor: executor type """
    executor_mode: str = 'P+P'
    """ executor_mode: hardware trace collection mode """
    executor_warmups: int = 5
    """ executor_warmups: number of warmup rounds executed before starting to collect
    hardware traces """
    executor_sample_sizes: List[int] = [10, 50, 100, 500]
    """ executor_sample_sizes: a list of sample sizes to be used during the measurements;
    the executor will first collect the hardware traces with the first sample size in the list,
    and if a violation is detected, it will try to reproduce it with all the following
    sample sizes """
    executor_filtering_repetitions: int = 10
    """ executor_filtering_repetitions: number of repetitions while filtering test cases """
    executor_taskset: int = 0
    """ executor_taskset: id of the CPU core on which the executor is running test cases """
    enable_pre_run_flush: bool = True
    """ enable_pre_run_flush: if enabled, the executor will do its best to flush
    the microarchitectural state before running test cases """

    # ==============================================================================================
    # Analyser
    analyser: str = 'chi2'
    """ analyser: type of the analyser """
    analyser_subsets_is_violation: bool = False
    """ analyser_subsets_is_violation: [only for analyser='sets' or analyser='bitmaps']
    if False, the analyser will not label hardware traces as mismatching if they form
    a subset relation """
    analyser_outliers_threshold: float = 0.1
    """ analyser_outliers_threshold: [only for analyser='sets' or analyser='bitmaps']
    analyser will ignore the htraces that appear in less then this percentage of the repetitions.
    I.e., a htrace passes the filter if it is observed at least
        (analyser_outliers_threshold * len(htrace)) times """
    analyser_stat_threshold: float = 0.5
    """ analyser_stat_threshold: [only for analyser='chi2' and analyser='mwu']
    Threshold for the statistical tests. If a pair of hardware traces has the (normalized)
    statistics below the threshold, then the traces are considered equivalent.

    Note: The threshold default value (0.5) is conservative and avoids false positives
    at cost of false negatives. For more precise results, set the threshold to a lower value.

    For the chi2 test, the threshold is the statistics / (len(htrace1) + len(htrace2))
    For the mwu test, the threshold is the p-value """

    # ==============================================================================================
    # Coverage
    coverage_type: str = 'none'
    """ coverage_type: coverage type """

    # ==============================================================================================
    # Minimizer
    minimizer_retries: int = 1
    """ minimizer_retries: number of attempts to reproduce the violation when minimizing """

    # ==============================================================================================
    # Output
    multiline_output: bool = False
    """ multiline_output: """
    logging_modes: List[str] = ["info", "stat"]
    """ logging_modes: """
    color: bool = False

    # ==============================================================================================
    # Alternatives for config options (also extended by ISA-specific config.py)
    _option_values: Dict[str, List[str]] = {
        "fuzzer": ["basic", "architectural", "archdiff"],
        "generator": ["random"],
        "instruction_set": ["x86-64", "arm64"],
        "data_generator": ["random"],
        "model_backend": ["dummy", "unicorn", "dynamorio"],
        "contract_execution_clause": [
            "seq", "no_speculation", "seq-assist", "cond", "conditional_br_misprediction", "bpas",
            "nullinj-fault", "nullinj-assist", "delayed-exception-handling", "div-zero",
            "div-overflow", "meltdown", "fault-skip", "noncanonical", "vspec-ops-div",
            "vspec-ops-memory-faults", "vspec-ops-memory-assists", "vspec-ops-gp", "vspec-all-div",
            "vspec-all-memory-faults", "vspec-all-memory-assists"
        ],
        "contract_observation_clause": [
            "none", "l1d", "pc", "memory", "ct", "loads+stores+pc", "ct-nonspecstore", "ctr",
            "arch", "tct", "tcto", "ct-ni"
        ],
        "executor": ["x86-64-intel", "x86-64-amd", "arm64"],
        'executor_mode': [
            'P+P',
            'F+R',
            'E+R',
            'PP+P',
            'TSC',
            # 'GPR' is intentionally left out
        ],
        'faults_allowlist': [
            'div-by-zero',
            'div-overflow',
            'opcode-undefined',
            'breakpoint',
            'debug-register',
            'non-canonical-access',
            'user-to-kernel-access',
        ],
        "analyser": ["bitmaps", "sets", "mwu", "chi2"],
        "coverage_type": ["none", "model_instructions"],
        "logging_modes": [
            "info",
            "stat",
            "dbg_generator",
            "dbg_timestamp",
            "dbg_violation",
            "dbg_dump_htraces",
            "dbg_dump_ctraces",
            "dbg_dump_traces_unlimited",
            "dbg_model",
            "dbg_coverage",
            "dbg_priming",
            "dbg_executor_raw",
            "dbg_isa_filter",
        ],
    }

    # ==============================================================================================
    # Internal
    _borg_shared_state: Dict[Any, Any] = {}
    _no_generation: bool = False
    _handled_faults: List[str]  # set by ISA-specific config.py
    _generator_fault_to_fault_name: Dict[str, str]  # set by ISA-specific config.py
    _actors: ActorsConf
    _actor_default: ActorConf
    _config_path: str = ""

    def __init__(self) -> None:
        # implementation of Borg pattern
        setattr(self, '__dict__', self._borg_shared_state)
        if not getattr(self, '_actors', None):
            self._actors = OrderedDict()

    def load(self, config_path: str, include_dir: str = "") -> None:
        self._config_path = config_path
        config_update: Dict[str, Any] = {}
        with open(config_path, "r") as f:
            loader = IncludeLoader(f, include_dir)
            try:
                config_update = loader.get_single_data()
            except yaml.scanner.ScannerError as e:  # type: ignore
                raise ConfigException(
                    f"Error parsing the configuration file {config_path}:\nError: {e}") from e
            finally:
                loader.dispose()  # type: ignore
        self._load_from_dict(config_update)
        self._value_sanity_check()

    def _load_from_dict(self, config_update: Dict[str, Any]) -> None:
        # make sure to set the architecture-dependent defaults first
        if 'instruction_set' in config_update:
            self.instruction_set = config_update['instruction_set']
            self.set_to_arch_defaults()
            config_update.pop('instruction_set')

        # recursively load included files
        file_keys = []
        for k, v in config_update.items():
            if "file_" in k:
                self._load_from_dict(v)
                file_keys.append(k)
        for k in file_keys:  # remove the `file_*` keys as they have already been processed
            config_update.pop(k)

        # set the rest of the options
        for var, value in config_update.items():
            # print(f"CONF: setting {var} to {value}")
            if var == "faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                self.safe_set(var, value)
                continue
            if var == "instruction_blocklist_append":
                self.instruction_blocklist.extend(value)
                continue
            if var == "actors":
                self.set_actor_properties(value)
                continue
            if var == "instruction_categories":
                backend = config_update.get("model_backend", self.model_backend)
                if backend == "unicorn":
                    options_name = "unicorn_instruction_categories"
                elif backend == "dynamorio":
                    options_name = "dr_instruction_categories"
                else:
                    options_name = "dr_instruction_categories"
                self.safe_set(var, value, options_name)

            self.safe_set(var, value)

    def safe_set(self, name: str, value: Any, options_name: str = "") -> None:
        assert name not in ["instruction_set"]

        # sanity checks
        if name[0] == "_":
            raise ConfigException(f"Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            raise ConfigException(f"Unknown configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            raise ConfigException(f"Wrong type of the configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")

        if options_name:
            self._check_options(options_name, value)
        else:
            self._check_options(name, value)
        setattr(self, name, value)

    def _check_options(self, name: str, value: Any) -> None:
        if name not in self._option_values:
            return
        options = self._option_values[name]

        invalid_value = None
        if isinstance(value, str):
            invalid_value = value if value not in options else None
        elif isinstance(value, List):
            for v in value:
                if v in options:
                    continue
                if isinstance(v, Dict):
                    for k in v:
                        if k not in options:
                            break
                    else:
                        continue
                invalid_value = v
                break
        else:
            raise ConfigException(f"Unexpected type of config variable {name}")

        if invalid_value:
            raise ConfigException(f"Unknown value '{invalid_value}' of config variable '{name}'\n"
                                  f"Possible options: {options}")
        return

    def _value_sanity_check(self) -> None:
        """
        Check if the configuration values make sense
        """
        if self.data_generator_entropy_bits > 32:
            raise ConfigException("data_generator_entropy_bits must be less or equal to 32 bits")
        if self.min_successors_per_bb > self.max_successors_per_bb:
            raise ConfigException("min_successors_per_bb is larger than max_successors_per_bb")

    def set_to_arch_defaults(self) -> None:
        """ Set config options according to the architecture-specific defaults """

        config: ModuleType
        if self.instruction_set == "x86-64":
            config = x86_config
        elif self.instruction_set == "arm64":
            config = arm64_config
        else:
            raise ConfigException(f"Unknown architecture {self.instruction_set}")

        config_defaults = {}
        for c in dir(config):
            if c.startswith("__"):
                continue
            values = getattr(config, c)
            if type(values) not in [bool, int, float, str, dict, list]:
                continue
            config_defaults[c] = values

        if "_option_values" not in config_defaults:
            raise ConfigException("ISA-specific config.py must define _option_values")

        for name, value in config_defaults.items():
            if name == "faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                continue
            if name == "_actor_default":
                self._actor_default = deepcopy(value)
                self._actors = OrderedDict()
                self._actors['main'] = deepcopy(value)
                continue
            if name == "_option_values":
                for k, v in value.items():
                    self._option_values[k] = v
                continue

            setattr(self, name, value)

    def update_handled_faults_with_generator_faults(self, new: List[str]) -> None:
        for gen_fault in new:
            if not gen_fault:
                continue
            if gen_fault not in self._generator_fault_to_fault_name:
                raise ConfigException(f"Unknown generator fault {gen_fault}")
            fault = self._generator_fault_to_fault_name[gen_fault]
            if fault not in self._handled_faults:
                self._handled_faults.append(fault)

    def set_actor_properties(self, new: List[Dict[str, List[Dict[ActorConfKey, Any]]]]) -> None:
        for actor_dict in new:
            name = next(iter(actor_dict))
            self._check_options("actor", actor_dict[name])
            update = {k: v for tmp_dict in actor_dict[name] for k, v in tmp_dict.items()}

            if name == "main":
                if update.get('mode', 'host') != 'host':
                    raise ConfigException("The main actor must be in 'host' mode")
                if update.get('privilege_level', 'kernel') != 'kernel':
                    raise ConfigException("The main actor must have 'kernel' privilege_level")

            if name in self._actors:
                entry = self._actors[name]
            else:
                entry = deepcopy(self._actor_default)
                entry["name"] = name

            for k, v in update.items():
                if k == "mode" and v not in self._option_values["actor_mode"]:
                    raise ConfigException(f"Unsupported actor mode {v}")
                if k == "privilege_level" and v not in self._option_values["actor_privilege_level"]:
                    raise ConfigException(f"Unsupported actor privilege_level {v}")

                if k == "data_properties":
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_properties"]:
                                raise ConfigException(
                                    f"Unsupported actor data_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "data_ept_properties":
                    if update.get('mode', 'host') != 'guest':
                        raise ConfigException("data_ept_properties can only be used in guest mode")
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_ept_properties"]:
                                raise ConfigException(
                                    f"Unsupported actor data_ept_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "instruction_blocklist" or k == "fault_blocklist":
                    if v:
                        entry[k].update(v)
                    continue

                entry[k] = v
            self._actors[name] = entry

    def disable_generation(self) -> None:
        """ Disable random-generation mode """
        self._no_generation = True

    def is_generation_enabled(self) -> bool:
        """ Check if the generation is globally enabled """
        return not self._no_generation

    def get_actors_conf(self) -> ActorsConf:
        """ Get the configuration dictionary describing all actors """
        return self._actors


CONF = Conf()
CONF.set_to_arch_defaults()
