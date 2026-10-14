"""
File: Global Revizor configuration.

All of Revizor reads its settings from the shared, live `Conf` instance `CONF`, either
as plain attributes (`CONF.program_size`) or through accessor methods (e.g.,
`get_actors_conf()`, `get_handled_faults()`). Writes are plain attribute assignments
and are validated immediately, whether they come from a YAML file or from code: an
unknown option name, a wrong type, a disallowed value, or an option that the current
architecture does not support raises `ConfigException`. Cross-option constraints are
checked by `validate()`, which `load()` calls automatically. Tests save and restore the
complete state with `snapshot()`/`restore()`.

Every option is declared exactly once, as a typed class attribute of `Conf` whose value
is the default and whose docstring describes it. Enumerated options take their allowed
values from `_BASE_OPTION_VALUES` (extended with arch-specific entries), and
`_X86_ONLY_OPTIONS` lists the arch-restricted ones. Architecture-dependent data --
default instruction categories, known-leak groups, the actor template, fault mappings,
and allowed-value extensions -- lives in the pure-data modules
`rvzr.arch.{x86,arm64}.config`, each exporting one frozen `ArchConf` instance (the
dataclass itself is defined in the leaf module `rvzr.arch.arch_conf` to avoid an import
cycle). Assigning `instruction_set` re-applies these arch defaults. Derived state is
computed on demand; for example, `get_handled_faults()` combines the arch baseline with
the current `faults_allowlist`.

Config files are YAML mappings, loaded by `Conf.load()` in two phases:

1. `_ConfLoader` flattens the file into an ordered stream of (key, value) pairs:
   `file: !include` entries are expanded in place (includes may nest; each target is
   resolved against the including file's directory first, then the include directory),
   and duplicate keys are preserved.
2. If the stream sets `instruction_set`, its last occurrence is applied first,
   re-applying the arch defaults; the remaining pairs are then applied strictly in
   stream order, so later entries override earlier ones. Two options accumulate
   instead of overriding: `instruction_blocklist_append` extends
   `instruction_blocklist`, and `actors` entries merge by actor name.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import difflib
import os
from copy import deepcopy
from typing import (Any, Dict, List, Literal, Optional, Set, Tuple, TypedDict, cast, get_args,
                    get_origin, get_type_hints)

import yaml

# pure-data modules; they do not import rvzr.config (no cycle)
from .arch.arch_conf import ArchConf, PageConf, PagePropertyName
from .arch.x86.config import ARCH_CONF as _X86_ARCH_CONF
from .arch.arm64.config import ARCH_CONF as _ARM64_ARCH_CONF

__all__ = [
    "CONF",
    "Conf",
    "ConfigException",
    "ActorConf",
    "ActorsConf",
    "ActorName",
    "PageConf",
    "PagePropertyName",
]

_ARCH_CONFS: Dict[str, ArchConf] = {
    _X86_ARCH_CONF.isa: _X86_ARCH_CONF,
    _ARM64_ARCH_CONF.isa: _ARM64_ARCH_CONF,
}

# ==================================================================================================
# Public types
# ==================================================================================================
ActorName = str


class ActorConf(TypedDict):
    """ Configuration of a single actor. All keys are always present. """
    name: ActorName  # equal to the actor's key in ActorsConf; not settable from YAML
    mode: str  # 'host' or 'guest'
    privilege_level: str  # 'kernel' or 'user'
    observer: bool
    data_properties: PageConf
    data_ept_properties: PageConf
    instruction_blocklist: Set[str]
    fault_blocklist: Set[str]


ActorsConf = Dict[ActorName, ActorConf]
""" Ordered collection of actors; 'main' always exists and is first; an actor's position
    is its actor ID """

InstructionSetName = Literal["x86-64", "arm64"]
assert set(get_args(InstructionSetName)) == set(_ARCH_CONFS), \
    "InstructionSetName must match the registered arch configs"

_ConfSnapshot = Dict[str, object]  # opaque; produced by Conf.snapshot()


# ==================================================================================================
# Errors
# ==================================================================================================
class ConfigException(SystemExit):
    """ Configuration error. Inherits SystemExit so that an uncaught error terminates
        the program with a readable message instead of a traceback. Raised by this
        module for invalid config files/writes, and by other modules for config
        problems detected after loading (those typically pass option=None). """

    def __init__(self, message: str, option: Optional[str] = None) -> None:
        if option is not None:
            super().__init__(f"CONFIG ERROR: Invalid value of config option `{option}`\n"
                             f"Issue: {message}")
        else:
            super().__init__(f"CONFIG ERROR: {message}")


# ==================================================================================================
# Allowed values
# ==================================================================================================
_X86_ONLY_OPTIONS = frozenset({
    'x86_executor_enable_ssbp_patch',
    'x86_executor_enable_prefetcher',
    'x86_enable_hpa_gpa_collisions',
    'x86_generator_align_locks',
})
""" Options that are rejected when the current ISA is not x86-64 """

# Allowed values of the arch-independent enumerated options; the arch-dependent ones
# ('suppress_known_leaks', 'faults_allowlist', 'actor_*') are added by
# Conf.get_option_values() from the current ArchConf. Options without an entry accept
# any value of the right type.
_BASE_OPTION_VALUES: Dict[str, List[str]] = {
    'fuzzer': ['basic', 'architectural', 'archdiff'],
    'logging_modes': [
        'info',
        'stat',
        'dbg_timestamp',
        'dbg_violation',
        'dbg_dump_htraces',
        'dbg_dump_ctraces',
        'dbg_dump_traces_unlimited',
        'dbg_executor_raw',
        'dbg_model',
        'dbg_coverage',
        'dbg_generator',
        'dbg_priming',
        'dbg_isa_filter',
    ],
    'generator': ['random'],
    'instruction_set':
        list(get_args(InstructionSetName)),
    'data_generator': ['random'],
    'contract_execution_clause': [
        'seq',
        'no_speculation',
        'seq-assist',
        'cond',
        'conditional_br_misprediction',
        'bpas',
        'nullinj-fault',
        'nullinj-assist',
        'delayed-exception-handling',
        'div-zero',
        'div-overflow',
        'meltdown',
        'fault-skip',
        'noncanonical',
        'vspec-ops-div',
        'vspec-ops-memory-faults',
        'vspec-ops-memory-assists',
        'vspec-ops-gp',
        'vspec-all-div',
        'vspec-all-memory-faults',
        'vspec-all-memory-assists',
    ],
    'contract_observation_clause': [
        'none',
        'l1d',
        'memory',
        'pc',
        'ct',
        'loads+stores+pc',
        'ct-nonspecstore',
        'ctr',
        'arch',
        'tct',
        'tcto',
        'ct-ni',
    ],
    'model_backend': ['dummy', 'unicorn', 'dynamorio'],
    'executor': ['x86-64-intel', 'x86-64-amd', 'arm64'],
    'executor_mode': [
        'P+P',
        'F+R',
        'E+R',
        'PP+P',
        'TSC',
        # 'GPR' is intentionally left out; it is enabled via the mismatch-check mode
    ],
    'analyser': ['chi2', 'mwu', 'sets', 'bitmaps'],
    'coverage_type': ['none', 'model_instructions'],
    'actor': [
        'mode',
        'privilege_level',
        'data_properties',
        'data_ept_properties',
        'observer',
        'instruction_blocklist',
        'fault_blocklist',
    ],
}


# ==================================================================================================
# Configuration state
# ==================================================================================================
class Conf:
    """
    Global fuzzing configuration.

    Reads: all options are plain attributes (`CONF.program_size`).
    Writes: plain attribute assignment, validated by `__setattr__`; assigning
    `instruction_set` additionally re-applies the arch-dependent defaults.
    """

    # ==============================================================================================
    # Option catalogue (name, type, default, and description of every public option).
    # Mutable defaults are deep-copied into the instance by __init__.

    # --- Fuzzer ---
    fuzzer: str = "basic"
    """ fuzzer: type of the fuzzing algorithm """
    enable_priming: bool = True
    """ enable_priming: whether to check violations with priming """
    enable_speculation_filter: bool = False
    """ enable_speculation_filter: if True, discard test cases that don't trigger speculation """
    enable_observation_filter: bool = False
    """ enable_observation_filter: if True, discard test cases that don't leave speculative
    traces """
    enable_fast_path_model: bool = True
    """ enable_fast_path_model: if enabled, the same contract trace will be used
    for all inputs in the same taint-based input class """
    color: bool = False
    """ color: if enabled, the console output is colored """
    logging_modes: List[str] = ["info", "stat"]
    """ logging_modes: list of enabled logging modes """
    multiline_output: bool = False
    """ multiline_output: if enabled, each log message is printed on a new line instead of
    overwriting the current one """

    # --- Program generator ---
    generator: str = "random"
    """ generator: type of the program generator """
    instruction_set: InstructionSetName = "x86-64"
    """ instruction_set: ISA under test; auto-detected from /proc/cpuinfo by default """
    instruction_categories: List[str] = []
    """ instruction_categories: list of instruction categories to use for generating programs;
    defaults to the arch config's category list """
    instruction_blocklist: List[str] = []
    """ instruction_blocklist: list of instructions that will NOT be used for generating programs;
    filters out instructions from instruction_categories, but not from instruction_allowlist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    instruction_allowlist: List[str] = []
    """ instruction_allowlist: list of instructions to use for generating programs;
    combined with instruction_categories; has priority over instruction_blocklist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    # `instruction_blocklist_append` is a deprecated file-only alias that extends
    # instruction_blocklist; it is handled by the loader and has no attribute
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
    """ min_successors_per_bb: min. number of successors for each basic block in generated
    programs.
    Note: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successors is
    required for correctness """
    max_successors_per_bb: int = 2
    """ max_successors_per_bb: max. number of successors for each basic block in generated
    programs.
    Note: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successors is
    required for correctness """
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
    suppress_known_leaks: List[str] = []
    """ suppress_known_leaks: named groups of instructions whose only known effect is a
    well-known, uninteresting leak; the instructions in the listed groups are excluded from
    generated programs. Defaults to all groups defined for the architecture
    (x86-64: [fpvi, div64]; arm64: []); set to an empty list to disable the suppression """

    # --- Data generator ---
    data_generator: str = "random"
    """ data_generator: type of the input generator """
    data_generator_seed: int = 10
    """ data_generator_seed: input generation seed; will use a random seed if set to zero """
    data_generator_entropy_bits: int = 31
    """ data_generator_entropy_bits: entropy of the random values created by the input
    generator """
    input_gen_probability_of_special_value: float = 0.05
    """ input_gen_probability_of_special_value: probability of generating a special value
    (zero or maximum value) when setting a register value in the input generator. This is used
    to test fast paths in the microarchitecture """
    inputs_per_class: int = 2
    """ inputs_per_class: number of inputs per input class """

    # --- Contract / model ---
    contract_execution_clause: List[str] = ["seq"]
    """ contract_execution_clause: execution clauses of the contract under test; several clauses
    combine into a more permissive contract """
    contract_observation_clause: str = "ct"
    """ contract_observation_clause: observation clause of the contract under test """
    model_backend: str = "unicorn"
    """ model_backend: the backend used to collect contract traces on generated test cases """
    model_min_nesting: int = 1
    """ model_min_nesting: number of nested mispredictions simulated on the fast path of
    the fuzzer """
    model_max_nesting: int = 30
    """ model_max_nesting: max. number of nested mispredictions simulated by the model """
    model_max_spec_window: int = 250
    """ model_max_spec_window: size of the speculation window in the model """

    # --- Executor ---
    executor: str = "x86-64-intel"
    """ executor: executor type; auto-detected from /proc/cpuinfo by default """
    executor_mode: str = "P+P"
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

    # --- Analyser ---
    analyser: str = "chi2"
    """ analyser: type of the analyser """
    analyser_subsets_is_violation: bool = False
    """ analyser_subsets_is_violation: [only for analyser='sets' or analyser='bitmaps']
    if False, the analyser will not label hardware traces as mismatching if they form
    a subset relation """
    analyser_outliers_threshold: float = 0.1
    """ analyser_outliers_threshold: [only for analyser='sets' or analyser='bitmaps']
    analyser will ignore the htraces that appear in less than this percentage of the repetitions.
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

    # --- Misc ---
    coverage_type: str = "none"
    """ coverage_type: coverage type """
    minimizer_retries: int = 1
    """ minimizer_retries: number of attempts to reproduce the violation when minimizing """

    # --- x86-64 only (rejected, from file and programmatically, when ISA is arm64) ---
    x86_executor_enable_ssbp_patch: bool = True
    """ x86_executor_enable_ssbp_patch: enable a patch against Speculative Store Bypass """
    x86_executor_enable_prefetcher: bool = False
    """ x86_executor_enable_prefetcher: enable all prefetchers """
    x86_enable_hpa_gpa_collisions: bool = False
    """ x86_enable_hpa_gpa_collisions: enable collisions between HPA and GPA;
    useful for testing Foreshadow-like leaks """
    x86_generator_align_locks: bool = True
    """ x86_generator_align_locks: align all generated locks to 8 bytes """

    # ==============================================================================================
    # Internal state (underscore-prefixed names bypass __setattr__ validation and are
    # excluded from introspection by unit_docs)
    _actors: ActorsConf
    _config_path: Optional[str]
    _no_generation: bool
    _arch: ArchConf  # arch data of the current instruction_set

    # ==============================================================================================
    # Lifecycle

    def __init__(self) -> None:
        self._config_path = None
        self._no_generation = False
        self._actors = {}

        # copy the class-level defaults into the instance, so that they are never mutated;
        # bypasses __setattr__ because validation needs _arch, which is not set yet
        for name in _OPTION_TYPES:
            object.__setattr__(self, name, deepcopy(getattr(Conf, name)))

        isa, executor = _detect_target()
        self._arch = _ARCH_CONFS[isa]  # must exist before the first validated write below
        self.instruction_set = isa  # re-applies the arch defaults
        self.executor = executor

    def __setattr__(self, name: str, value: object) -> None:
        if name.startswith('_'):  # internal state; not an option
            object.__setattr__(self, name, value)
            return
        self._validate_option_value(name, value)
        object.__setattr__(self, name, value)
        if name == 'instruction_set':
            self._apply_arch_defaults()

    def _apply_arch_defaults(self) -> None:
        """ Reset the arch-dependent defaults and the actor set according to the
            current `instruction_set` """
        arch = _ARCH_CONFS[self.instruction_set]
        self._arch = arch
        self.instruction_categories = list(arch.instruction_categories)
        self.suppress_known_leaks = list(arch.known_leak_groups)
        self._actors = {'main': self.get_actor_template()}

    # ==============================================================================================
    # Validation of option values

    def _validate_option_value(self, name: str, value: object) -> None:
        """
        Check a single (option, value) pair: known name, exact type, allowed values,
        and arch restrictions.
        :raises ConfigException: when any check fails
        """
        if name not in _OPTION_TYPES:
            raise ConfigException(_unknown_option_msg(name, list(_OPTION_TYPES)))

        if name in _X86_ONLY_OPTIONS and self.instruction_set != "x86-64":
            raise ConfigException(
                f"option is x86-64-only, but the instruction set is `{self.instruction_set}`",
                option=name)

        self._check_type(name, value)

        allowed = self.get_option_values().get(name)
        if allowed is not None:
            items = value if isinstance(value, list) else [value]
            for item in items:
                if item not in allowed:
                    detail = (f"Allowed values: {', '.join(allowed)}"
                              if allowed else "no values are allowed on this architecture")
                    raise ConfigException(
                        f"`{item}` is not an allowed value\n{detail}", option=name)

    def _check_type(self, name: str, value: object, reported_name: Optional[str] = None) -> None:
        """ Check that the value exactly matches the option's declared type; as the
            only relaxation, ints are accepted where floats are expected.
            Errors name `reported_name` when it differs from the schema entry (e.g.,
            for the `instruction_blocklist_append` alias) """
        reported = reported_name or name
        expected = _OPTION_TYPES[name]
        if get_origin(expected) is Literal:
            expected = str  # membership is enforced by the allowed-values check
        if get_origin(expected) is list:
            (elem_type,) = get_args(expected)
            if not isinstance(value, list):
                raise ConfigException(
                    f"expected a list of {elem_type.__name__}, got `{value!r}`", option=reported)
            for item in value:
                if not _type_matches(item, elem_type):
                    raise ConfigException(
                        f"expected list elements of type {elem_type.__name__}, got `{item!r}`",
                        option=reported)
        elif not _type_matches(value, expected):
            raise ConfigException(
                f"expected a value of type {expected.__name__}, got `{value!r}`", option=reported)

    def validate(self) -> None:
        """
        Check cross-option constraints: value ranges, fault mappings, and actor
        invariants. Called automatically at the end of load(); may be called explicitly
        after a series of programmatic writes.
        :raises ConfigException: when a constraint is violated
        """
        if self.data_generator_entropy_bits > 32:
            raise ConfigException(
                "entropy must be at most 32 bits", option='data_generator_entropy_bits')
        if self.min_successors_per_bb > self.max_successors_per_bb:
            raise ConfigException(
                f"min_successors_per_bb ({self.min_successors_per_bb}) is larger than "
                f"max_successors_per_bb ({self.max_successors_per_bb})",
                option='min_successors_per_bb')
        self.get_handled_faults()  # raises if an allowlist entry is unmapped on this arch
        self._validate_actor_invariants()

    def _validate_actor_invariants(self) -> None:
        """ Check constraints that span several actor properties """
        main = self._actors['main']
        if main['mode'] != 'host' or main['privilege_level'] != 'kernel':
            raise ConfigException(
                "the main actor must have mode=host and privilege_level=kernel", option='actors')
        ept_template = dict(self._arch.data_ept_properties_template)
        for actor in self._actors.values():
            if actor['mode'] != 'guest' and actor['data_ept_properties'] != ept_template:
                raise ConfigException(
                    f"data_ept_properties set on non-guest actor `{actor['name']}`",
                    option='actors')

    # ==============================================================================================
    # File loading

    def load(self, config_path: str, include_dir: str = ".") -> None:
        """
        Load a YAML config file on top of the current configuration.

        The file is flattened into an ordered stream of (key, value) pairs, with
        includes expanded in place and duplicate keys preserved. If the stream sets
        `instruction_set`, its last occurrence is applied first (re-applying the arch
        defaults); the remaining pairs are applied in stream order, so later pairs
        override earlier ones. Accumulating options are the exception to "later wins":
        `instruction_blocklist_append` extends the blocklist, and `actors` entries
        merge per actor. Null items (`- `) are dropped from top-level list options and
        from actors' blocklists. If loading fails, the configuration is left unchanged.

        :param config_path: path to the YAML config file
        :param include_dir: fallback directory for resolving `!include` entries
        :raises ConfigException: for syntax errors, unknown options, invalid values
        """
        pairs = _ConfLoader(include_dir).flatten(config_path)

        saved_state = self.snapshot()
        try:
            isa_values = [v for key, v in pairs if key == 'instruction_set']
            if isa_values:
                self._set_option_from_file('instruction_set', isa_values[-1])

            for key, value in pairs:
                if key == 'instruction_set':
                    continue  # already applied
                self._set_option_from_file(key, value)

            self.validate()
        except ConfigException:
            self.restore(saved_state)
            raise

        self._config_path = config_path

    def _set_option_from_file(self, key: str, value: object) -> None:
        """ Apply a single (key, value) pair coming from a config file """
        file_only_keys = ['actors', 'instruction_blocklist_append']
        if key not in _OPTION_TYPES and key not in file_only_keys:
            raise ConfigException(_unknown_option_msg(key, list(_OPTION_TYPES) + file_only_keys))

        if key == 'actors':
            self._merge_actors(value)
            return

        if isinstance(value, list):
            value = [item for item in value if item is not None]

        if key == 'instruction_blocklist_append':  # deprecated alias of instruction_blocklist
            self._check_type(
                'instruction_blocklist', value, reported_name='instruction_blocklist_append')
            self.instruction_blocklist = self.instruction_blocklist + cast(List[str], value)
            return

        setattr(self, key, value)

    # ==============================================================================================
    # Actors

    def get_actors_conf(self) -> ActorsConf:
        """
        Get the (live, mutable) ordered actor collection. 'main' is always present and
        first; an actor's position is its ID.
        """
        return self._actors

    def get_actor_template(self, name: ActorName = "main") -> ActorConf:
        """
        Get a fresh copy of the arch's default actor configuration with the given name,
        for programmatically building additional actors.
        """
        return ActorConf(
            name=name,
            mode="host",
            privilege_level="kernel",
            observer=False,
            data_properties=dict(self._arch.data_properties_template),
            data_ept_properties=dict(self._arch.data_ept_properties_template),
            instruction_blocklist=set(),
            fault_blocklist=set(),
        )

    def _merge_actors(self, actors_yaml: object) -> None:
        """ Validate and apply one `actors:` YAML value; existing actors (incl. 'main')
            are updated in place, new actors are appended """
        if not isinstance(actors_yaml, list):
            raise ConfigException("expected a list of actor descriptions", option='actors')

        for actor_entry in actors_yaml:
            name, props = _unpack_single_key_map(actor_entry)
            if not isinstance(props, list):
                raise ConfigException(
                    f"properties of actor `{name}` must be a list", option='actors')

            if name not in self._actors:
                self._actors[name] = self.get_actor_template(name)
            actor = self._actors[name]

            for prop_entry in props:
                prop, value = _unpack_single_key_map(prop_entry)
                self._set_actor_property(actor, prop, value)

    def _set_actor_property(self, actor: ActorConf, prop: str, value: object) -> None:
        """ Validate and apply a single actor property from a config file """
        name = actor['name']
        if prop == 'name':
            raise ConfigException(
                f"`name` of actor `{name}` is derived from its key and cannot be set",
                option='actors')
        if prop not in _BASE_OPTION_VALUES['actor']:
            raise ConfigException(
                f"unknown property `{prop}` of actor `{name}`\n"
                f"Allowed properties: {', '.join(_BASE_OPTION_VALUES['actor'])}",
                option='actors')

        if prop == 'mode':
            if not isinstance(value, str) or value not in self._arch.actor_modes:
                raise ConfigException(
                    f"`{value!r}` is not a supported mode of actor `{name}`\n"
                    f"Supported modes: {', '.join(self._arch.actor_modes)}",
                    option='actors')
            actor['mode'] = value
        elif prop == 'privilege_level':
            if not isinstance(value, str) or value not in self._arch.actor_privilege_levels:
                raise ConfigException(
                    f"`{value!r}` is not a supported privilege level of actor `{name}`\n"
                    f"Supported levels: {', '.join(self._arch.actor_privilege_levels)}",
                    option='actors')
            actor['privilege_level'] = value
        elif prop == 'observer':
            if not isinstance(value, bool):
                raise ConfigException(
                    f"`observer` of actor `{name}` must be a boolean", option='actors')
            actor['observer'] = value
        elif prop == 'instruction_blocklist':
            actor['instruction_blocklist'].update(self._parse_str_list(value, prop, name))
        elif prop == 'fault_blocklist':
            faults = self._parse_str_list(value, prop, name)
            for fault in faults:
                if fault not in self._arch.fault_class_map:
                    raise ConfigException(
                        f"unknown fault `{fault}` in `fault_blocklist` of actor `{name}`\n"
                        f"Allowed values: {', '.join(self._arch.fault_class_map)}",
                        option='actors')
            actor['fault_blocklist'].update(faults)
        elif prop == 'data_properties':
            self._merge_page_props(actor['data_properties'], value,
                                   self._arch.allowed_data_properties, prop, name)
        else:  # data_ept_properties
            self._merge_page_props(actor['data_ept_properties'], value,
                                   self._arch.allowed_data_ept_properties, prop, name)

    def _merge_page_props(self, target: PageConf, value: object, allowed: Tuple[PagePropertyName,
                                                                                ...], prop: str,
                          actor_name: str) -> None:
        """ Validate and apply a page-property list (`- <property>: <bool>`) """
        if not isinstance(value, list):
            raise ConfigException(
                f"`{prop}` of actor `{actor_name}` must be a list of single-key mappings",
                option='actors')
        for entry in value:
            key, val = _unpack_single_key_map(entry)
            if key not in allowed:
                raise ConfigException(
                    f"unknown page property `{key}` in `{prop}` of actor `{actor_name}`\n"
                    f"Allowed properties: {', '.join(allowed)}",
                    option='actors')
            if not isinstance(val, bool):
                raise ConfigException(
                    f"page property `{key}` of actor `{actor_name}` must be a boolean",
                    option='actors')
            target[key] = val

    def _parse_str_list(self, value: object, prop: str, actor_name: str) -> List[str]:
        """ Validate that an actor property value is a list of strings """
        if not isinstance(value, list):
            raise ConfigException(
                f"`{prop}` of actor `{actor_name}` must be a list", option='actors')
        items = [item for item in value if item is not None]
        for item in items:
            if not isinstance(item, str):
                raise ConfigException(
                    f"`{prop}` of actor `{actor_name}` must contain only strings", option='actors')
        return cast(List[str], items)

    # ==============================================================================================
    # Derived state

    def get_handled_faults(self) -> Set[str]:
        """
        Get the set of fault classes (e.g., 'PF', 'DE', 'UD') that the model and
        executor must handle gracefully. Computed on demand: the arch baseline plus the
        fault classes mapped from the current `faults_allowlist`.
        :raises ConfigException: if an allowlist entry has no mapping on the current arch
        """
        handled = set(self._arch.baseline_handled_faults)
        for fault in self.faults_allowlist:
            fault_class = self._arch.fault_class_map.get(fault)
            if fault_class is None:
                raise ConfigException(
                    f"`{fault}` has no fault-class mapping on {self._arch.isa}",
                    option='faults_allowlist')
            handled.add(fault_class)
        return handled

    def is_generation_enabled(self) -> bool:
        """ Check if program generation is enabled (it is disabled when the fuzzer runs
            with an existing test case, e.g., `fuzz -t`, `reproduce`, `minimize`). """
        return not self._no_generation

    def disable_generation(self) -> None:
        """ Mark program generation as disabled for the rest of the run. """
        self._no_generation = True

    def get_config_path(self) -> Optional[str]:
        """ Get the path of the top-level config file loaded by load(), or None if the
            run uses defaults. Used to store violation artifacts. """
        return self._config_path

    # ==============================================================================================
    # Introspection (used by validation, unit_docs, and error messages)

    def get_option_values(self) -> Dict[str, List[str]]:
        """
        Get the allowed-values table for the current architecture: option name (or
        actor pseudo-option, e.g. 'actor_mode', 'actor_data_properties') -> list of
        permitted values. Only enumerated options have entries.
        """
        values = {key: list(val) for key, val in _BASE_OPTION_VALUES.items()}
        values['suppress_known_leaks'] = list(self._arch.known_leak_groups)
        values['faults_allowlist'] = list(self._arch.fault_class_map)
        values['actor_mode'] = list(self._arch.actor_modes)
        values['actor_privilege_level'] = list(self._arch.actor_privilege_levels)
        values['actor_data_properties'] = list(self._arch.allowed_data_properties)
        values['actor_data_ept_properties'] = list(self._arch.allowed_data_ept_properties)
        return values

    # ==============================================================================================
    # Snapshot / restore (for tests)

    def snapshot(self) -> _ConfSnapshot:
        """ Get a deep copy of the complete configuration state (options, actors,
            derived flags). """
        return deepcopy(self.__dict__)

    def restore(self, state: _ConfSnapshot) -> None:
        """ Restore a state previously returned by snapshot(). """
        state_copy = deepcopy(state)
        self.__dict__.clear()
        self.__dict__.update(state_copy)


# Types of all public options, derived from the annotations of Conf
_OPTION_TYPES: Dict[str, Any] = {
    name: hint for name, hint in get_type_hints(Conf).items() if not name.startswith('_')
}
# _check_type relies on the allowed-values check for Literal membership
assert all(name in _BASE_OPTION_VALUES
           for name, hint in _OPTION_TYPES.items() if get_origin(hint) is Literal), \
    "Literal-typed options must have an entry in _BASE_OPTION_VALUES"


def _type_matches(value: object, expected: Any) -> bool:
    """ Exact type match, except that ints are accepted where floats are expected;
        bools never match int/float (bool is a subclass of int in Python) """
    if expected is bool:
        return isinstance(value, bool)
    if isinstance(value, bool):
        return False
    if expected is int:
        return isinstance(value, int)
    if expected is float:
        return isinstance(value, (int, float))
    return isinstance(value, expected)


def _unknown_option_msg(name: str, candidates: List[str]) -> str:
    """ Build an error message for an unknown option name, with typo suggestions """
    msg = f"unknown configuration option `{name}`"
    matches = difflib.get_close_matches(name, candidates, n=1)
    if matches:
        msg += f"; did you mean `{matches[0]}`?"
    return msg


def _unpack_single_key_map(entry: object) -> Tuple[str, object]:
    """ Unpack a `- <key>: <value>` YAML list entry
        :raises ConfigException: if the entry is not a single-key mapping """
    if not isinstance(entry, dict) or len(entry) != 1:
        raise ConfigException(f"expected a single-key mapping, got `{entry!r}`", option='actors')
    key, value = next(iter(entry.items()))
    if not isinstance(key, str):
        raise ConfigException(f"expected a string key, got `{key!r}`", option='actors')
    return key, value


def _detect_target() -> Tuple[InstructionSetName, str]:
    """ Detect the host's ISA and executor from /proc/cpuinfo;
        fall back to x86-64/Intel if detection fails """
    try:
        with open('/proc/cpuinfo', 'r') as cpuinfo_file:
            cpuinfo = cpuinfo_file.read()
    except OSError:
        return "x86-64", "x86-64-intel"
    if "AuthenticAMD" in cpuinfo:
        return "x86-64", "x86-64-amd"
    if "GenuineIntel" in cpuinfo:
        return "x86-64", "x86-64-intel"
    if "CPU implementer" in cpuinfo:
        return "arm64", "arm64"
    return "x86-64", "x86-64-intel"


# ==================================================================================================
# YAML loader
# ==================================================================================================
class _Include:
    """ Marker produced by the `!include` YAML tag """

    def __init__(self, target: str) -> None:
        self.target = target

    def __repr__(self) -> str:
        return f"!include {self.target}"


def _contains_include(value: object) -> bool:
    """ Check for `!include` markers nested inside a constructed YAML value """
    if isinstance(value, _Include):
        return True
    if isinstance(value, list):
        return any(_contains_include(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_include(item) for item in value.values())
    return False


class _YamlLoader(yaml.SafeLoader):
    """ SafeLoader with the `!include` tag """


def _construct_include(loader: _YamlLoader, node: yaml.Node) -> _Include:
    if not isinstance(node, yaml.ScalarNode):
        raise ConfigException("the argument of !include must be a file path")
    return _Include(str(loader.construct_scalar(node)))


_YamlLoader.add_constructor('!include', _construct_include)


class _ConfLoader:
    """
    Reads a YAML config file and flattens it into an ordered stream of (key, value)
    pairs for Conf.load(). Performs no option validation; only include resolution and
    YAML syntax checks.
    """

    def __init__(self, include_dir: str) -> None:
        self._include_dir = include_dir
        self._include_stack: Set[str] = set()

    def flatten(self, config_path: str) -> List[Tuple[str, object]]:
        """
        Parse `config_path` and return its (key, value) pairs in document order, with
        every `file: !include <path>` pair replaced in place by the flattened pairs of
        the included file (recursively). Duplicate keys are all preserved, in order.

        Includes are resolved against the including file's directory first, then the
        include directory, at every nesting level.

        :raises ConfigException: missing file, missing or circular include, YAML
            syntax error, non-mapping top level
        """
        if not os.path.isfile(config_path):
            raise ConfigException(f"config file `{config_path}` does not exist")
        real_path = os.path.realpath(config_path)
        if real_path in self._include_stack:
            raise ConfigException(f"circular include of `{config_path}`")

        self._include_stack.add(real_path)
        try:
            result: List[Tuple[str, object]] = []
            for key, value in self._read_pairs(config_path):
                if isinstance(value, _Include):
                    if key != 'file':
                        raise ConfigException(
                            "!include is only allowed as the value of a `file:` key", option=key)
                    include_path = self._resolve_include(value.target, os.path.dirname(config_path))
                    result.extend(self.flatten(include_path))
                elif key == 'file':
                    raise ConfigException(
                        f"the `file:` key requires an `!include` value, got `{value!r}`")
                else:
                    if _contains_include(value):
                        raise ConfigException(
                            "!include is only allowed as the value of a top-level `file:` key",
                            option=key)
                    result.append((key, value))
            return result
        finally:
            self._include_stack.remove(real_path)

    def _read_pairs(self, path: str) -> List[Tuple[str, object]]:
        """ Parse one YAML file into an ordered list of top-level (key, value) pairs,
            preserving duplicate keys (which yaml.safe_load would silently drop) """
        with open(path, 'r') as yaml_file:
            loader = _YamlLoader(yaml_file)
            try:
                node = loader.get_single_node()
                if node is None:
                    return []
                if not isinstance(node, yaml.MappingNode):
                    raise ConfigException(f"the top level of `{path}` is not a mapping")
                pairs: List[Tuple[str, object]] = []
                for key_node, value_node in node.value:
                    key = self._construct(loader, key_node)
                    if not isinstance(key, str):
                        raise ConfigException(f"invalid option name `{key!r}` in `{path}`")
                    value = self._construct(loader, value_node)
                    pairs.append((key, value))
                return pairs
            except yaml.YAMLError as err:
                raise ConfigException(f"failed to parse `{path}`:\n{err}") from err
            finally:
                loader.dispose()  # type: ignore[no-untyped-call]

    @staticmethod
    def _construct(loader: _YamlLoader, node: yaml.Node) -> object:
        """ Build the Python value of a YAML node (the stubs leave it untyped) """
        return loader.construct_object(node, deep=True)  # type: ignore[no-untyped-call]

    def _resolve_include(self, target: str, file_dir: str) -> str:
        """ Resolve an include target: the including file's directory first, then the
            include directory """
        if os.path.isabs(target):
            if os.path.isfile(target):
                return target
            raise ConfigException(f"included file `{target}` does not exist")
        candidates = [os.path.join(file_dir, target), os.path.join(self._include_dir, target)]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        raise ConfigException(f"included file `{target}` not found; searched: "
                              f"{', '.join(candidates)}")


# ==================================================================================================
# The global configuration instance
# ==================================================================================================
CONF = Conf()
