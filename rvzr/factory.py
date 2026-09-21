"""
File: Configuration factory; constructs objects based on the configuration options.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Dict, Type, List, TYPE_CHECKING, Any, Optional, Union

from . import data_generator, analyser, executor, fuzzer, model, elf_parser
from .model_unicorn import tracer, speculator_abc, interpreter, model as uc_model
from .model_unicorn.speculators import SeqSpeculator, SequentialAssistSpeculator, \
    StoreBpasSpeculator, X86CondSpeculator, ARM64CondSpeculator, X86CondBpasSpeculator, \
    X86Meltdown, X86UnicornDEH, ARM64UnicornDEH, X86UnicornNull, X86UnicornNullAssist, \
    X86NonCanonicalAddress, VspecDIVSpeculator, VspecAllDIVSpeculator, \
    VspecMemoryFaultsSpeculator, VspecMemoryAssistsSpeculator, VspecGPSpeculator, \
    VspecAllMemoryFaultsSpeculator, VspecAllMemoryAssistsSpeculator
from .model_dynamorio import model as dr_model
from .postprocessing.minimizer import Minimizer

from .arch.x86 import asm_parser as x86_asm_parser, \
    executor as x86_executor, fuzzer as x86_fuzzer, generator as x86_generator, \
    target_desc as x86_target_desc, get_spec as x86_get_spec
from .arch.arm64 import asm_parser as arm64_asm_parser, \
    executor as arm64_executor, fuzzer as arm64_fuzzer, generator as arm64_generator, \
    target_desc as arm64_target_desc, get_spec as arm64_get_spec
from .config import CONF, ConfigException

if TYPE_CHECKING:
    from .isa_spec import InstructionSet
    from .target_desc import TargetDesc
    from .code_generator import CodeGenerator
    from .asm_parser import AsmParser
    from .sandbox import BaseAddrTuple


class FactoryException(SystemExit):
    """ Exception raised by the factory functions """

    def __init__(self, options: Dict[str, Type[Any]], key: str, conf_option_name: str) -> None:
        super().__init__(
            f"ERROR: unknown value `{key}` of `{conf_option_name}` configuration option.\n"
            "  Available options are:\n  - " + "\n  - ".join(options.keys()))


# ==================================================================================================
# Common enumerations
# ==================================================================================================
_TARGET_DESC: Dict[str, Type[TargetDesc]] = {
    "x86-64": x86_target_desc.X86TargetDesc,
    "arm64": arm64_target_desc.ARM64TargetDesc,
}


# ==================================================================================================
# Fuzzer Construction
# ==================================================================================================
def get_fuzzer(instruction_set_path: str, working_directory: str, existing_test_case: str,
               input_paths: Optional[List[str]]) -> fuzzer.Fuzzer:
    """ Construct a fuzzer based on the configuration options in the CONF object. """

    if CONF.fuzzer == "architectural":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchitecturalFuzzer(instruction_set_path, working_directory,
                                                     existing_test_case, input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64ArchitecturalFuzzer(instruction_set_path, working_directory,
                                                         existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "archdiff":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchDiffFuzzer(instruction_set_path, working_directory,
                                                existing_test_case, input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64ArchDiffFuzzer(instruction_set_path, working_directory,
                                                    existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "basic":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86Fuzzer(instruction_set_path, working_directory, existing_test_case,
                                        input_paths)
        if CONF.instruction_set == "arm64":
            return arm64_fuzzer.ARM64Fuzzer(instruction_set_path, working_directory,
                                            existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    raise ConfigException("ERROR: unknown value of `fuzzer` configuration option")


# ==================================================================================================
# Executor Construction
# ==================================================================================================
_EXECUTORS = {
    'x86-64-intel': x86_executor.X86IntelExecutor,
    'x86-64-amd': x86_executor.X86AMDExecutor,
    'arm64': arm64_executor.ARM64Executor,
}


def get_executor(enable_mismatch_check_mode: bool = False) -> executor.Executor:
    """ Construct an executor based on the configuration options in the CONF object. """
    key: str = CONF.executor
    if key not in _EXECUTORS:
        raise FactoryException(_EXECUTORS, key, "executor")
    return _EXECUTORS[key](enable_mismatch_check_mode)


# ==================================================================================================
# Model Construction
# ==================================================================================================
_TRACERS: Dict[str, Type[tracer.UnicornTracer]] = {
    "none": tracer.NoneTracer,
    "l1d": tracer.L1DTracer,
    "pc": tracer.PCTracer,
    "memory": tracer.MemoryTracer,
    "ct": tracer.CTTracer,
    "loads+stores+pc": tracer.CTTracer,
    "ct-nonspecstore": tracer.CTNonSpecStoreTracer,
    "arch": tracer.ArchTracer,
    "tct": tracer.TruncatedCTTracer,
    "tcto": tracer.TruncatedCTWithOverflowsTracer,
    "ct-ni": tracer.ActorNITracer,
}

_SPECULATORS_GENERIC: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    "seq": SeqSpeculator,
    "no_speculation": SeqSpeculator,
    "bpas": StoreBpasSpeculator,
    "cond-bpas": X86CondBpasSpeculator,
    "seq-assist": SequentialAssistSpeculator,
}

_SPECULATORS_X86: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    **_SPECULATORS_GENERIC,
    "cond": X86CondSpeculator,
    "conditional_br_misprediction": X86CondSpeculator,
    "delayed-exception-handling": X86UnicornDEH,
    "nullinj-fault": X86UnicornNull,
    "nullinj-assist": X86UnicornNullAssist,
    "meltdown": X86Meltdown,
    "noncanonical": X86NonCanonicalAddress,
    "vspec-ops-div": VspecDIVSpeculator,
    "vspec-ops-memory-faults": VspecMemoryFaultsSpeculator,
    "vspec-ops-memory-assists": VspecMemoryAssistsSpeculator,
    "vspec-ops-gp": VspecGPSpeculator,
    "vspec-all-div": VspecAllDIVSpeculator,
    "vspec-all-memory-faults": VspecAllMemoryFaultsSpeculator,
    "vspec-all-memory-assists": VspecAllMemoryAssistsSpeculator,
}

_SPECULATORS_ARM64: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    **_SPECULATORS_GENERIC,
    "cond": ARM64CondSpeculator,
    "conditional_br_misprediction": ARM64CondSpeculator,
    "delayed-exception-handling": ARM64UnicornDEH,
}


def _get_exec_clause_name() -> str:
    """ Determine the name of the execution clause based on the configuration options """
    if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
        clause_name = "cond-bpas"
    elif "conditional_br_misprediction" in CONF.contract_execution_clause and \
            "nullinj-fault" in CONF.contract_execution_clause:
        clause_name = "cond-nullinj-fault"
    elif len(CONF.contract_execution_clause) == 1:
        clause_name = CONF.contract_execution_clause[0]
    else:
        raise ConfigException(
            "ERROR: unknown value of `contract_execution_clause` configuration option")
    return clause_name


def _get_x86_unicorn_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                           enable_mismatch_check_mode: bool) -> model.Model:
    target_desc = _TARGET_DESC[CONF.instruction_set]()
    tracer_cls = _TRACERS[obs_clause_name]
    speculator_cls = _SPECULATORS_X86[exec_clause_name]
    interpreter_cls = interpreter.X86ExtraInterpreter
    model_ = uc_model.X86UnicornModel(bases, target_desc, speculator_cls, tracer_cls,
                                      interpreter_cls, enable_mismatch_check_mode)
    return model_


def _get_arm64_unicorn_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                             enable_mismatch_check_mode: bool) -> model.Model:
    target_desc = _TARGET_DESC[CONF.instruction_set]()
    tracer_cls = _TRACERS[obs_clause_name]
    speculator_cls = _SPECULATORS_ARM64[exec_clause_name]
    interpreter_cls = interpreter.ARMExtraInterpreter
    model_ = uc_model.ARM64UnicornModel(bases, target_desc, speculator_cls, tracer_cls,
                                        interpreter_cls, enable_mismatch_check_mode)
    return model_


def _get_dr_model(bases: BaseAddrTuple, obs_clause_name: str, exec_clause_name: str,
                  enable_mismatch_check_mode: bool) -> model.Model:
    # DR backend is not implemented in python, so we have to call its API
    # to check if the contract is supported
    obs_clauses = dr_model.DynamoRIOModel.get_supported_obs_clauses()
    exec_clauses = dr_model.DynamoRIOModel.get_supported_exec_clauses()

    if obs_clause_name not in obs_clauses:
        raise ConfigException(f"ERROR: unsupported observation clause `{obs_clause_name}`.\n"
                              f"  Available options are:\n  - " + "\n  - ".join(obs_clauses))
    if exec_clause_name not in exec_clauses:
        raise ConfigException(f"ERROR: unsupported execution clause `{exec_clause_name}`.\n"
                              f"  Available options are:\n  - " + "\n  - ".join(exec_clauses))
    model_ = dr_model.DynamoRIOModel(bases, enable_mismatch_check_mode=enable_mismatch_check_mode)
    model_.configure_clauses(obs_clause_name, exec_clause_name)
    return model_


def get_model(bases: BaseAddrTuple, enable_mismatch_check_mode: bool = False) -> model.Model:
    """ Construct a model based on the configuration options in the CONF object. """
    obs_clause_name = CONF.contract_observation_clause
    exec_clause_name = _get_exec_clause_name()

    if CONF.instruction_set == "x86-64":
        if CONF.model_backend == "unicorn":
            return _get_x86_unicorn_model(bases, obs_clause_name, exec_clause_name,
                                          enable_mismatch_check_mode)
        if CONF.model_backend == "dynamorio":
            return _get_dr_model(bases, obs_clause_name, exec_clause_name,
                                 enable_mismatch_check_mode)
        if CONF.model_backend == "dummy":
            return model.DummyModel(bases, enable_mismatch_check_mode)

        raise ConfigException("ERROR: unknown value of `model_backend` configuration option")

    if CONF.instruction_set == "arm64":
        if CONF.model_backend == "unicorn":
            return _get_arm64_unicorn_model(bases, obs_clause_name, exec_clause_name,
                                            enable_mismatch_check_mode)
        if CONF.model_backend == "dynamorio":
            raise ConfigException("ERROR: DynamoRIO backend is not supported for ARM64")
        if CONF.model_backend == "dummy":
            return model.DummyModel(bases, enable_mismatch_check_mode)

        raise ConfigException("ERROR: unknown value of `model_backend` configuration option")

    raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")


# ==================================================================================================
# Program Generator Construction and Related Classes
# ==================================================================================================
_GENERATORS: Dict[str, Type[CodeGenerator]] = {
    "x86-64": x86_generator.X86Generator,
    "arm64": arm64_generator.ARM64Generator,
}

_ASM_PARSERS: Dict[str, Type[AsmParser]] = {
    'x86-64': x86_asm_parser.X86AsmParser,
    'arm64': arm64_asm_parser.ARM64AsmParser,
}

_ELF_PARSERS: Dict[str, Type[elf_parser.ELFParser]] = {
    'x86-64': elf_parser.ELFParser,
    'arm64': elf_parser.ELFParser,
}


def get_program_generator(seed: int, instruction_set: InstructionSet) -> CodeGenerator:
    """
    Produce a ProgramGenerator object based on the configuration options in the CONF object.
    """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser_ = _ELF_PARSERS[key](target_desc)
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    generator = _GENERATORS[key](seed, instruction_set, target_desc, asm_parser, elf_parser_)
    return generator


def get_asm_parser(instruction_set: InstructionSet) -> AsmParser:
    """ Produce an AsmParser object based on the configuration options in the CONF object. """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    return asm_parser


def get_elf_parser() -> elf_parser.ELFParser:
    """ Produce an ELFParser object based on the configuration options in the CONF object. """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser_ = _ELF_PARSERS[key](target_desc)
    return elf_parser_


# ==================================================================================================
# Input Data Generator Construction
# ==================================================================================================
_DATA_GENERATORS: Dict[str, Type[data_generator.DataGenerator]] = {
    'random': data_generator.DataGenerator,
}


def get_data_generator(seed: int) -> data_generator.DataGenerator:
    """ Produce an DataGenerator object based on the configuration options in the CONF object. """
    key: str = CONF.data_generator
    if key not in _DATA_GENERATORS:
        raise FactoryException(_DATA_GENERATORS, key, "data_generator")
    return _DATA_GENERATORS[key](seed)


# ==================================================================================================
# Analyser Construction
# ==================================================================================================
_ANALYZERS: Dict[str, Type[analyser.Analyser]] = {
    'bitmaps': analyser.MergedBitmapAnalyser,
    'sets': analyser.SetAnalyser,
    'mwu': analyser.MWUAnalyser,
    'chi2': analyser.ChiSquaredAnalyser,
}


def get_analyser() -> analyser.Analyser:
    """ Construct an analyser based on the configuration options in the CONF object. """
    key: str = CONF.analyser
    if key not in _ANALYZERS:
        raise FactoryException(_ANALYZERS, key, "analyser")
    return _ANALYZERS[key]()


# ==================================================================================================
# Minimizer Construction
# ==================================================================================================
_MINIMIZERS: Dict[str, Type[Minimizer]] = {
    'violation': Minimizer,
}


def get_minimizer(fuzzer_: fuzzer.Fuzzer, instruction_set: InstructionSet) -> Minimizer:
    """ Construct a minimizer based on the configuration options in the CONF object. """
    key: str = "violation"  # expansion point for future; currently hardcoded
    if key not in _MINIMIZERS:
        raise FactoryException(_MINIMIZERS, key, "minimizer")
    return _MINIMIZERS[key](fuzzer_, instruction_set)


# ==================================================================================================
# Spec Downloader Construction
# ==================================================================================================
Downloader = Union[x86_get_spec.Downloader, arm64_get_spec.Downloader]

_SPEC_DOWNLOADERS: Dict[str, Type[Downloader]] = {
    'x86-64': x86_get_spec.Downloader,
    'arm64': arm64_get_spec.Downloader,
}


def get_downloader(arch: str, extensions: List[str], out_file: str) -> Downloader:
    """ Construct a class that downloads an ISA spec for the given architecture. """
    key: str = arch
    if key not in _SPEC_DOWNLOADERS:
        raise FactoryException(_SPEC_DOWNLOADERS, key, "downloader")
    return _SPEC_DOWNLOADERS[key](extensions, out_file)
