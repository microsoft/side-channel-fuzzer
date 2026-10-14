"""
File: Implementation of executor for x86 architecture

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import Dict, Final

from rvzr.executor import Executor, km_write
from rvzr.config import CONF, ConfigException
from rvzr.target_desc import TargetDesc

FAULT_IDS: Final[Dict[str, int]] = {
    'DE': 0,
    'DB': 1,
    'NMI': 2,
    'BP': 3,
    'OF': 4,
    'BR': 5,
    'UD': 6,
    'NM': 7,
    'DF': 8,
    'OLD_MF': 9,
    'TS': 10,
    'NP': 11,
    'SS': 12,
    'GP': 13,
    'PF': 14,
    'SPURIOUS': 15,
    'MF': 16,
    'AC': 17,
    'MC': 18,
    'XF': 19,
    'IRET': 32
}


class X86Executor(Executor):
    """ Base x86 implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        self._handled_faults_bitmap: int = self._identify_handled_faults()
        super().__init__(enable_mismatch_check_mode)

    def _set_vendor_specific_features(self) -> None:
        km_write("1" if CONF.x86_executor_enable_ssbp_patch else "0",
                 "/sys/rvzr_executor/enable_ssbp_patch")
        km_write("1" if CONF.x86_executor_enable_prefetcher else "0",
                 "/sys/rvzr_executor/enable_prefetcher")
        km_write("1" if CONF.x86_enable_hpa_gpa_collisions else "0",
                 "/sys/rvzr_executor/enable_hpa_gpa_collisions")
        km_write(str(self._handled_faults_bitmap), "/sys/rvzr_executor/handled_faults")

    def _identify_handled_faults(self) -> int:
        handled_faults_bitmap = 0
        for fault in CONF.get_handled_faults():
            if fault in FAULT_IDS:
                handled_faults_bitmap |= (1 << FAULT_IDS[fault])
        return handled_faults_bitmap


class X86IntelExecutor(X86Executor):
    """ Intel-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "Intel":
            raise ConfigException(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")


class X86AMDExecutor(X86Executor):
    """ AMD-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "AMD":
            raise ConfigException(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")
