"""
File: Speculator for speculation upon non-canonical address accesses

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING
import re
from .fault_speculator_abc import FaultSpeculator

if TYPE_CHECKING:
    from rvzr.target_desc import TargetDesc
    from rvzr.model_unicorn.model import UnicornModel
    from rvzr.model_unicorn.taint_tracker import UnicornTaintTracker


class X86NonCanonicalAddress(FaultSpeculator):
    """
    Load from non-canonical address
    """

    faulty_instruction_addr: int = -1
    address_register: int = -1
    register_value: int = -1

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__(target_desc, model, taint_tracker)
        self._errno_that_trigger_speculation = {6, 7}

    def _speculate_fault(self, errno: int) -> int:
        if not self._fault_triggers_speculation(errno):
            return 0

        self._checkpoint(self._model.state.fault_handler_addr)
        self.faulty_instruction_addr = self._curr_instruction_addr
        return self._curr_instruction_addr

    def _speculate_instruction(self, address: int, size: int) -> None:
        super()._speculate_instruction(address, size)

        if not self._in_speculation:
            return

        model = self._model
        if self.address_register != -1:
            model.emulator.reg_write(self.address_register, self.register_value)
            self.address_register = -1
            return

        if self.faulty_instruction_addr != address:
            return

        # Fix non-canonical address
        for mem_op in model.state.current_instruction.get_mem_operands(True):
            registers = re.split(r"\+|-|\*| ", mem_op.value)
            if len(registers) > 1:
                continue

            uc_reg = self._target_desc.uc_target_desc.reg_str_to_constant[registers[0]]
            load_address: int = model.emulator.reg_read(uc_reg)  # type: ignore
            is_canonical: bool = (
                load_address > 0xFFFF800000000000 or load_address < 0x00007FFFFFFFFFFF)
            if not is_canonical:
                self.address_register = uc_reg
                self.register_value = load_address

                if load_address & (1 << 47):  # bit 48 is 1 => high address
                    load_address = load_address | 0xFFFF800000000000
                else:  # bit 48 is 0 => low address
                    load_address = load_address & 0x00007FFFFFFFFFF
                model.emulator.reg_write(uc_reg, load_address)
                return
        return

    def reset(self) -> None:
        self.faulty_instruction_addr = -1
        self.address_register = -1
        self.register_value = -1
        return super().reset()
