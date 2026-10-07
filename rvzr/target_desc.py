"""
File: Architectural details of the target platform,
such as register sizes, register names, and CPU description.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-few-public-methods
# justification: this is a collection of descriptor classes

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, NamedTuple, Literal, TYPE_CHECKING
import subprocess

from rvzr.config import PagePropertyName

if TYPE_CHECKING:
    from .tc_components.instruction import Instruction, RegSize

# ==================================================================================================
# Custom Types
# ==================================================================================================
Vendor = Literal["Intel", "AMD", "ARM", "Unknown"]
RegName = str
RegNormalizedName = str
RegUnicornID = int
PTEBitName = Literal["present", "writable", "non_writable", "user", "write-through",
                     "cache-disable", "accessed", "dirty", "reserved_bit", "executable",
                     "non_executable", "valid"]
PTEBitOffset = int
PTEBitNameMapper = Dict[PagePropertyName, Tuple[PTEBitName, bool]]


# ==================================================================================================
# Use-case Specific Descriptors
# ==================================================================================================
class CPUDesc(NamedTuple):
    """ CPU description. """

    vendor: Vendor
    model: int
    family: int
    stepping: int


class MacroSpec(NamedTuple):
    """ Macro specification. """

    type_: int
    name: str
    args: Tuple[str, str, str, str]


class UnicornTargetDesc:
    """ Target description in the context of a Unicorn-based model """

    usable_registers: List[RegUnicornID]
    """ List of Unicorn register IDs that are used by test cases on the target platform. """

    usable_simd128_registers: List[RegUnicornID]
    """ List of Unicorn SIMD register IDs that are used by test cases on the target platform. """

    reg_str_to_constant: Dict[RegName, RegUnicornID]
    """ Mapping from register names to their Unicorn constants. """

    reg_norm_to_constant: Dict[RegNormalizedName, RegUnicornID]
    """ Mapping from normalized register names to their Unicorn constants. """

    barriers: List[str]
    """ List of instruction names that are considered as speculation barriers """

    flags_register: RegUnicornID
    """ Unicorn register ID of the flags register """

    pc_register: RegUnicornID
    """ Unicorn register ID of the program counter register """

    sp_register: RegUnicornID
    """ Unicorn register ID of the stack pointer register """

    actor_base_register: RegUnicornID
    """ Unicorn register ID of the register that holds the base address of the active actor """


# ==================================================================================================
# Main Target Description
# ==================================================================================================
class TargetDesc(ABC):
    """ Abstract class defining the interface to target description classes. """

    cpu_desc: CPUDesc
    """ Target CPU description. """

    # List of macro specifications. All macros are cross-platform, hence the same for all targets.
    macro_specs: Dict[str, MacroSpec] = {
        # macros with negative IDs are used for generation
        # and are not supposed to reach the final binary
        "random_instructions":
            MacroSpec(-1, "random_instructions", ("int", "int", "", "")),

        # macros with positive IDs are used for execution and can be interpreted by executor/model
        "function":
            MacroSpec(0, "function", ("", "", "", "")),
        "measurement_start":
            MacroSpec(1, "measurement_start", ("", "", "", "")),
        "measurement_end":
            MacroSpec(2, "measurement_end", ("", "", "", "")),
        "fault_handler":
            MacroSpec(3, "fault_handler", ("", "", "", "")),
        "switch":
            MacroSpec(4, "switch", ("actor_id", "function_id", "", "")),
        "set_k2u_target":
            MacroSpec(5, "set_k2u_target", ("actor_id", "function_id", "", "")),
        "switch_k2u":
            MacroSpec(6, "switch_k2u", ("actor_id", "", "", "")),
        "set_u2k_target":
            MacroSpec(7, "set_u2k_target", ("actor_id", "function_id", "", "")),
        "switch_u2k":
            MacroSpec(8, "switch_u2k", ("actor_id", "", "", "")),
        "set_h2g_target":
            MacroSpec(9, "set_h2g_target", ("actor_id", "function_id", "", "")),
        "switch_h2g":
            MacroSpec(10, "switch_h2g", ("actor_id", "", "", "")),
        "set_g2h_target":
            MacroSpec(11, "set_g2h_target", ("actor_id", "function_id", "", "")),
        "switch_g2h":
            MacroSpec(12, "switch_g2h", ("actor_id", "", "", "")),
        "landing_k2u":
            MacroSpec(13, "landing_k2u", ("", "", "", "")),
        "landing_u2k":
            MacroSpec(14, "landing_u2k", ("", "", "", "")),
        "landing_h2g":
            MacroSpec(15, "landing_h2g", ("", "", "", "")),
        "landing_g2h":
            MacroSpec(16, "landing_g2h", ("", "", "", "")),
        "set_data_permissions":
            MacroSpec(18, "set_data_permissions", ("actor_id", "int", "int", ""))
        # FIXME: macro IDs should not be hardcoded but rather received from the executor
        # or at least we need a test that will check that the IDs match
    }

    uc_target_desc: UnicornTargetDesc
    """ Target description in the context of a Unicorn-based model """

    register_sizes: Dict[RegName, RegSize]
    """ Dictionary mapping register names to their sizes in bits. """

    registers_by_size: Dict[RegSize, List[RegName]]
    """ Dictionary with lists of all registers for a given size. """

    reg_normalized: Dict[RegName, RegNormalizedName]
    """ Mapping from full register names to normalized size-independent names. E.g., rax -> A"""

    reg_denormalized: Dict[RegNormalizedName, Dict[RegSize, RegName]]
    """ Reverse mapping from normalized names to full register names.
    E.g., A -> {64: rax, 32: eax, 16: ax, 8: al} """

    page_property_to_pte_bit_name: PTEBitNameMapper
    """
    Dictionary mapping architecture-independent page property names to architecture-specific
    page table entry bit names together with a bit indicating whether the property is inverted.
    E.g.,
        'writable' -> ('writable', False)
        'executable' -> ('non_executable', True)
    """

    pte_bits: Dict[PTEBitName, Tuple[PTEBitOffset, bool]]
    """
    Dictionary mapping page table entry field names to their bit offsets and their default values.
    """

    page_property_to_vm_pte_bit_name: PTEBitNameMapper
    """
    Dictionary mapping architecture-independent page property names to architecture-specific
    VM page table entry bit names. This is the unified mapping for both Intel EPT and AMD NPT.
    """

    vm_pte_bits: Dict[PTEBitName, Tuple[PTEBitOffset, bool]]
    """
    Dictionary mapping VM page table entry field names to their bit offsets
    and their default values. This is the unified interface for various types of host-to-guest
    page tables, such as Intel EPT and AMD NPT.
    """

    branch_conditions: Dict[str, List[str]]
    """ Dictionary mapping branch instructions to their condition codes. """

    mem_index_registers: List[RegName]
    """ List of register that can be used as memory index registers. """

    @classmethod
    def get_vendor(cls) -> Vendor:
        """ Read the CPU vendor from lscpu """
        output = subprocess.check_output("lscpu", shell=True)
        if b"Intel" in output:
            return "Intel"
        if b"AMD" in output:
            return "AMD"
        if b"ARM" in output:
            return "ARM"
        return "Unknown"

    @staticmethod
    @abstractmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        """ Check if the instruction is an unconditional branch. """

    @staticmethod
    @abstractmethod
    def is_call(inst: Instruction) -> bool:
        """ Check if the instruction is a call. """

    def get_macro_spec_from_type(self, type_: int) -> MacroSpec:
        """
        Get the macro specification of a given macro type.
        :param type_: macro type
        :return: macro specification
        """
        for macro_spec in self.macro_specs.values():
            if macro_spec.type_ == type_:
                return macro_spec
        raise KeyError(f"Unknown macro type: {type_}")
