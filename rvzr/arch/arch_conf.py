"""
File: Schema of per-architecture configuration data.

Each supported architecture provides one frozen `ArchConf` instance (see
`rvzr.arch.{x86,arm64}.config`), consumed by `rvzr.config` when the instruction set is
selected. This module is a leaf: it must not import anything from `rvzr`, so that the
arch config modules stay importable by `rvzr.config` without a cycle.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from dataclasses import dataclass
from typing import Dict, FrozenSet, Literal, Mapping, Tuple

PagePropertyName = Literal['present', 'writable', 'user', 'write-through', 'cache-disable',
                           'accessed', 'dirty', 'executable', 'reserved_bit', 'randomized']
PageConf = Dict[PagePropertyName, bool]
""" Mapping of page-table-entry properties to their values; keys may be absent if the
    architecture does not define them (e.g., no 'write-through' on arm64) """


@dataclass(frozen=True)
class ArchConf:
    """ Architecture-dependent configuration data: option defaults, allowed-value
        extensions, the actor template, and fault mappings. Pure data; all collections
        are immutable. """

    isa: str
    """ Name of the instruction set, as used in the `instruction_set` option """

    instruction_categories: Tuple[str, ...]
    """ Default value of the `instruction_categories` option """

    known_leak_groups: Tuple[str, ...]
    """ Allowed values of the `suppress_known_leaks` option; also its default
        (all groups are suppressed by default) """

    baseline_handled_faults: FrozenSet[str]
    """ Fault classes that the model and executor handle even with an empty
        `faults_allowlist` """

    fault_class_map: Mapping[str, str]
    """ Mapping of generator fault names (`faults_allowlist` entries) to the fault
        classes raised at runtime; also defines the allowed values of `faults_allowlist`
        and of the actors' `fault_blocklist` """

    actor_modes: Tuple[str, ...]
    """ Allowed values of the actors' `mode` property """

    actor_privilege_levels: Tuple[str, ...]
    """ Allowed values of the actors' `privilege_level` property """

    allowed_data_properties: Tuple[PagePropertyName, ...]
    """ Allowed keys of the actors' `data_properties` property """

    allowed_data_ept_properties: Tuple[PagePropertyName, ...]
    """ Allowed keys of the actors' `data_ept_properties` property """

    data_properties_template: Mapping[PagePropertyName, bool]
    """ Default `data_properties` of a new actor """

    data_ept_properties_template: Mapping[PagePropertyName, bool]
    """ Default `data_ept_properties` of a new actor """
