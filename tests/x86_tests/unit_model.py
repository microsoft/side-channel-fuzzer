"""
File: Collection of unit tests for x86 model backends.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from typing import Callable, List, Optional, Tuple, Union, Any, Dict
from copy import deepcopy
from pathlib import Path
from functools import wraps

from rvzr.model_dynamorio.model import DynamoRIOModel
from rvzr.model_unicorn.model import X86UnicornModel

from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTrace
from rvzr.factory import get_model
from rvzr.config import CONF, ConfigException, Conf
from rvzr.logs import update_logging_after_config_change

from .model_common import Inst, InstList, InputBuilder, \
    MAIN_OFFSET, FAULTY_OFFSET, MEM_DEFAULT_VALUE, \
    REG_DEFAULT_VALUE, MEM_FAULTY_DEFAULT_VALUE, RSP_DEFAULT_VALUE, CODE_BASE, DATA_BASE, Backend, \
    RAX, RBX, RCX, RDX, RSI, RDI

ModelType = Union[DynamoRIOModel, X86UnicornModel]

TEST_PATH = Path(__file__).resolve()
TEST_DIR = TEST_PATH.parent

PF_MASK = 0xfffffffffffffffe

# Test values
TEST_MEM_VALUE_A = 42
TEST_MEM_VALUE_B = 0x42
POISON_VALUE = 0xDEADBEEF


def skip_for_backend(backend: Backend, reason: str = "not supported") -> Callable[[Any], Any]:
    """Decorator to skip tests for specific backends.

    :param backend: Backend to skip ('dr' or 'uc')
    :param reason: Reason for skipping (default: "not supported")

    Usage:
        @skip_for_backend("dr")
        def test_something(self):
            ...
    """

    def decorator(test_func: Callable[[Any], Any]) -> Callable[[Any], Any]:

        @wraps(test_func)
        def wrapper(self: '_SharedX86Model') -> Any:
            if self._backend == backend:
                raise unittest.SkipTest(reason)
            return test_func(self)

        return wrapper

    return decorator


class _SharedX86Model(unittest.TestCase):
    """Base class with common test infrastructure for x86 model backends."""

    _prev_obs_clause: Optional[str] = None
    _prev_exec_clause: Optional[List[str]] = None
    _prev_backend: Optional[str] = None
    _prev_conf: Optional[Conf] = None
    _backend: Backend
    _backend_long: str

    # Exclude this parent class from test discovery
    @classmethod
    def setUpClass(cls) -> None:
        if cls is _SharedX86Model:
            raise unittest.SkipTest("Skipping base class")

    @classmethod
    def _configure_class(cls,
                         backend_long: str,
                         additional_config: Optional[Dict[str, Any]] = None) -> None:
        """Configure test class with backend-specific settings.

        :param backend_long: Full backend name ('dynamorio' or 'unicorn')
        :param additional_config: Optional dict of additional CONF attributes to set
        """
        cls._prev_conf = deepcopy(CONF)
        CONF.model_backend = backend_long
        CONF._no_generation = True
        CONF.logging_modes = []

        # Apply additional backend-specific configuration
        if additional_config:
            for attr, value in additional_config.items():
                setattr(CONF, attr, value)

        update_logging_after_config_change()

    @classmethod
    def _teardown_class(cls) -> None:
        """Restore configuration to pre-test state."""
        if cls._prev_conf is not None:
            for attr, value in cls._prev_conf.__dict__.items():
                setattr(CONF, attr, value)

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self._input_builder = InputBuilder()

    def setUp(self) -> None:
        """Save configuration state before each test to prevent leakage between tests."""
        self._save_conf()

    def tearDown(self) -> None:
        """Restore configuration state after each test."""
        self._restore_conf()

    @staticmethod
    def _get_default_ct_trace() -> List[int]:
        """Get default CT trace (empty for base)."""
        trace: List[int] = []
        return trace

    def _save_conf(self) -> None:
        self._prev_obs_clause = CONF.contract_observation_clause
        self._prev_exec_clause = CONF.contract_execution_clause
        self._prev_backend = CONF.model_backend

    def _restore_conf(self) -> None:
        assert self._prev_obs_clause is not None and \
               self._prev_exec_clause is not None and \
               self._prev_backend is not None
        CONF.contract_observation_clause = self._prev_obs_clause
        CONF.contract_execution_clause = self._prev_exec_clause
        CONF.model_backend = self._prev_backend

    def _get_model(self,
                   obs_clause: str,
                   exec_clause: List[str],
                   data_bases: Tuple[int, int],
                   enable_mismatch_check: bool = False) -> ModelType:
        raise NotImplementedError()

    def _get_trace(self,
                   test_case: InstList,
                   input_data: List[InputData],
                   obs_clause: str = "ct",
                   exec_clause: Optional[List[str]] = None,
                   data_bases: Tuple[int, int] = (DATA_BASE, CODE_BASE),
                   nesting: int = 1,
                   enable_mismatch_check: bool = False,
                   pte_mask: int = 0) -> List[CTrace]:
        if exec_clause is None:
            exec_clause = ["seq"]

        model = self._get_model(obs_clause, exec_clause, data_bases, enable_mismatch_check)
        tc = test_case.to_test_case()
        if pte_mask != 0:
            tc.find_actor(name="main").data_properties &= pte_mask  # type: ignore
        model.load_test_case(tc)
        ctraces = model.trace_test_case(input_data, nesting=nesting)
        return ctraces

    def _tc_branch_load(self) -> InstList:
        return InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("jz .l1", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
                Inst(".l1:", 0, 0, 0),
            ],
            backend=self._backend,
        )

    def _tc_nested_cond(self) -> InstList:
        return InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),  # 8
                Inst("jz .l2", 2, 0, 0),  # 11 0xb
                Inst(".l0:", 0, 0, 0),  # 13
                Inst("mov qword ptr [r14], 1", 7, MAIN_OFFSET + 0, 1),  # 13  0xd
                Inst("jz .l2", 2, 0, 0),  # 20 0x14
                Inst(".l1:", 0, 0, 0),  # 22 0x16
                Inst("mov qword ptr [r14], 2", 7, MAIN_OFFSET + 0, 1),  # 22 0x16
                Inst("mov rbx, 1", 7, 0, 0),  # 29  0x1d
                Inst(".l2:", 0, 0, 0),  # 36  0x24
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),  # 36
            ],
            backend=self._backend,
        )

    def _tc_faulty_load(self, backend: Optional[Backend] = None) -> InstList:
        return InstList(
            [
                Inst("mov rax, qword ptr [r14 + 0x1000]", 7, FAULTY_OFFSET, 0),
                Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 3, 0),
                Inst("mov rbx, qword ptr [r14 + rbx]", 4, MAIN_OFFSET + REG_DEFAULT_VALUE, 0),
            ],
            backend=backend if backend is not None else self._backend,
        )

    def _tc_indirect(self) -> InstList:
        return InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("jz .end", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("lea rax,qword ptr [rip+.l3]", 7, 0, 0),
                Inst("call rax", 2, 0, 0),
                Inst(".l1:", 0, 0, 0),
                Inst("xor rax, rax", 3, 0, 0),
                Inst("mov rax, qword ptr [rax]", 3, MAIN_OFFSET + 0, 1),
                Inst("call rax", 2, 0, 0),
                Inst(".l2:", 0, 0, 0),
                Inst("jmp .end", 2, 0, 0),
                Inst(".l3:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
                Inst("ret", 1, 0, 0),
                Inst(".end:", 0, 0, 0),
            ],
            backend=self._backend,
        )

    def test_no_trace(self) -> None:
        # Test that tracing with no inputs returns an empty list
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
            ],
            backend=self._backend,
        )
        input_data: List[InputData] = []
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=input_data,
        )
        self.assertEqual(len(ctraces), 0)

    def test_mismatch_check_mode(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
            ],
            backend=self._backend,
        )
        input_ = InputData()
        input_[0]['gpr'][RAX] = 1
        input_[0]['gpr'][RBX] = 2
        input_[0]['gpr'][RCX] = 3
        input_[0]['gpr'][RDX] = 4
        input_[0]['gpr'][RSI] = 5
        input_[0]['gpr'][RDI] = 6

        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            enable_mismatch_check=True,
        )

        reg_values = ctraces[0].get_untyped()
        self.assertEqual(reg_values, [0, 2, 3, 4, 5, 6])

    def test_mismatch_check_mode_2(self) -> None:
        test_case = InstList(
            [
                Inst("mov qword ptr [r14], 42", 3, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()

        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            enable_mismatch_check=True,
        )

        reg_values = ctraces[0].get_untyped()
        self.assertEqual(reg_values, [test_case[1].mem_value] + [REG_DEFAULT_VALUE] * 5)

    @skip_for_backend("dr")
    def test_l1d_seq(self) -> None:
        test_case = InstList(
            [
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            obs_clause="l1d",
        )

        expected_trace = test_case.get_expected_observations([0], False, True, False)
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)
        self.assertEqual(str(ctraces[0]), "^" + "." * 63)

    def test_ct_seq(self) -> None:
        # Test that the tracing functions create RDBF and RCBF files
        test_case = self._tc_branch_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
        )
        expected_trace = test_case.get_expected_observations([0, 1, 4], True, True, False)
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_checkpoint_rollback_registers(self) -> None:
        test_case = self._tc_branch_load()
        input_ = InputData()
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            exec_clause=["cond"],
            enable_mismatch_check=True)
        reg_values = ctraces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], 0)

    def test_checkpoint_rollback_memory(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("jz .l1", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("mov qword ptr [r14], 1", 7, MAIN_OFFSET + 0, 1),
                Inst(".l1:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
            ],
            backend=self._backend,
        )
        input_ = InputData()
        input_[0]['main'][0] = TEST_MEM_VALUE_B
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            exec_clause=["cond"],
            enable_mismatch_check=True)
        reg_values = ctraces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], TEST_MEM_VALUE_B)

    def test_checkpoint_rollback_nested(self) -> None:
        test_case = self._tc_nested_cond()
        input_ = InputData()
        input_[0]['main'][0] = TEST_MEM_VALUE_B
        input_[0]['gpr'][RBX] = 0x1
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            exec_clause=["cond"],
            nesting=2,
            enable_mismatch_check=True)

        reg_values = ctraces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], TEST_MEM_VALUE_B)
        self.assertEqual(reg_values[1], 1)

    def test_ct_cond(self) -> None:
        test_case = self._tc_nested_cond()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            exec_clause=["cond"],
        )
        self.assertEqual(len(ctraces), 1)

        expected_trace = test_case.get_expected_observations(
            [
                0,
                1,  # first misprediction
                3,
                4,  # no misprediction on the second branch (nesting = 1)
                9,  # first rollback
                9,  # exit
            ],
            True,
            True,
            False)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_cond_double(self) -> None:
        test_case = self._tc_nested_cond()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            test_case=test_case,
            input_data=[input_],
            exec_clause=["cond"],
            nesting=2,
        )
        self.assertEqual(len(ctraces), 1)

        expected_trace = test_case.get_expected_observations(
            [
                0,
                1,  # first misprediction
                3,
                4,  # second misprediction
                6,
                7,
                9,  # first rollback
                9,  # second rollback
                9,  # exit
            ],
            True,
            True,
            False)
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_rollback_on_fence(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("jz .l1", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
                Inst("lfence", 2, 0, 0),
                Inst("mov rax, qword ptr [r14 + 2]", 5, MAIN_OFFSET + 2, 2),
                Inst(".l1:", 0, 0, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["cond"],
            test_case=test_case,
            input_data=[input_],
        )
        self.assertEqual(len(ctraces), 1)

        expected_trace = test_case.get_expected_observations([0, 1, 3, 4, 6], True, True, False)
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_bpas(self) -> None:
        test_case = InstList(
            [
                Inst("mov qword ptr [r14], 42", 7, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
                Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + TEST_MEM_VALUE_A, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["bpas"],
            test_case=test_case,
            input_data=[input_],
        )

        expected_trace: List[int] = []
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)

        # speculative
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(test_case[1].mem_address)
        rax = MEM_DEFAULT_VALUE
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(test_case[3].pc_offset)

        # after rollback
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(test_case[1].mem_address)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_cond_bpas(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("mov qword ptr [r14], 42", 7, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
                Inst("jz .l1", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, TEST_MEM_VALUE_A),
                Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + TEST_MEM_VALUE_A, 0),
                Inst(".l1:", 0, 0, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["cond", "bpas"],
            test_case=test_case,
            input_data=[input_],
            nesting=2,
        )

        end = test_case[7]
        expected_trace: List[int] = []
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(test_case[1].mem_address)

        # the store is bypassed and the branch is mispredicted at the same instruction
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[4].pc_offset)
        expected_trace.append(test_case[4].mem_address)
        expected_trace.append(test_case[5].pc_offset)
        expected_trace.append(MAIN_OFFSET + MEM_DEFAULT_VALUE)
        expected_trace.append(end.pc_offset)

        # after rollback of the misprediction; the store is still bypassed
        expected_trace.append(end.pc_offset)

        # after rollback of the bypass; the store is visible, the branch is mispredicted again
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[4].pc_offset)
        expected_trace.append(test_case[4].mem_address)
        expected_trace.append(test_case[5].pc_offset)
        expected_trace.append(test_case[5].mem_address)
        expected_trace.append(end.pc_offset)

        # after rollback of the second misprediction
        expected_trace.append(end.pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_fault_handling(self) -> None:
        test_case = self._tc_faulty_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            test_case=test_case, input_data=[input_], nesting=1, pte_mask=PF_MASK)

        # Fault at instruction 0: PC, mem_addr, and RSP (fault handler stack)
        expected_trace = test_case.get_expected_observations([0], True, True, False)
        expected_trace.append(RSP_DEFAULT_VALUE)  # Stack pointer from fault handler
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_deh(self) -> None:
        # Test X86UnicornDEH with CTTracer (Delayed Exception Handling)
        test_case = self._tc_faulty_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["delayed-exception-handling"],
            test_case=test_case,
            input_data=[input_],
            pte_mask=PF_MASK)

        # DEH: fault at 0, continue speculatively to 2, then handle fault
        expected_trace: List[int] = []
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)
        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_nullinj_assist(self) -> None:
        test_case = self._tc_faulty_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["nullinj-assist"],
            test_case=test_case,
            input_data=[input_],
            pte_mask=PF_MASK)

        # Complex trace: fault, re-execute with null injection, speculate, rollback, re-execute
        # Manual construction needed due to complex execution flow
        expected_trace: List[int] = []
        # fault
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        rax = 0
        # execute with speculative rax
        expected_trace.append(test_case[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)  # measurement_end
        # rollback and re-execute without a fault
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(test_case[1].mem_address)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)  # measurement_end

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_nullinj_term(self) -> None:
        # Test X86UnicornNull with CTTracer (null injection with termination)
        test_case = self._tc_faulty_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["nullinj-fault"],
            test_case=test_case,
            input_data=[input_],
            pte_mask=PF_MASK)

        # Complex trace: fault, re-execute with null injection, speculate (no rollback)
        expected_trace: List[int] = []
        # fault
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        rax = 0
        # execute with speculative rax (terminates without rollback)
        expected_trace.append(test_case[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)  # end nop

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_ct_meltdown(self) -> None:
        # Test X86Meltdown with CTTracer (Meltdown vulnerability)
        test_case = self._tc_faulty_load(backend="uc")
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            exec_clause=["meltdown"], test_case=test_case, input_data=[input_], pte_mask=PF_MASK)

        # Meltdown: fault, re-execute with leaked value, speculate
        expected_trace: List[int] = []
        # fault
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        # re-execute with changed permissions and inject leaked value into rax
        expected_trace.append(test_case[0].pc_offset)
        expected_trace.append(test_case[0].mem_address)
        rax = MEM_FAULTY_DEFAULT_VALUE
        # execute with speculative rax containing leaked data
        expected_trace.append(test_case[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(test_case[2].pc_offset)
        expected_trace.append(test_case[2].mem_address)
        expected_trace.append(test_case[3].pc_offset)  # measurement_end

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("dr")
    def test_arch_seq(self) -> None:
        test_case = self._tc_branch_load()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(obs_clause="arch", test_case=test_case, input_data=[input_])
        self.assertEqual(len(ctraces), 1)

        # ArchTracer observes PC, memory addresses, and values
        # Plus initial register state (7 registers)
        reg_state = [REG_DEFAULT_VALUE] * 7
        trace_observations = test_case.get_expected_observations([0, 1, 4], True, True, True)
        expected_trace = reg_state + trace_observations

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @skip_for_backend("uc")
    def test_ind(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("lea rax,qword ptr [rip+.l0]", 7, 0, 0),
                Inst("call rax", 2, 0, 0),
                Inst(".end:", 0, 0, 0),
                Inst("jmp .l2", 2, 0, 0),
                Inst(".l0:", 0, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
                Inst("ret", 1, 0, 0),
                Inst(".l2:", 0, 0, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(obs_clause="ind", test_case=test_case, input_data=[input_])
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []
        # Call (src and dest)
        expected_trace.append(test_case[3].pc_offset)
        expected_trace.append(test_case[6].pc_offset)
        # Ret (src and dest)
        expected_trace.append(test_case[8].pc_offset)
        expected_trace.append(test_case[4].pc_offset)

        # Node: last two rets are inserted by the instrumentation: ignore them
        self.assertEqual(ctraces[0].get_untyped()[:-2], expected_trace)

    @skip_for_backend("uc")
    def test_ind_spec(self) -> None:
        test_case = self._tc_indirect()
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(
            obs_clause="ind", exec_clause=["cond"], test_case=test_case, input_data=[input_])
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []

        # Call (src and dest)
        expected_trace.append(test_case[5].pc_offset)
        expected_trace.append(test_case[13].pc_offset)
        # Ret (src and dest)
        expected_trace.append(test_case[14].pc_offset)
        expected_trace.append(test_case[6].pc_offset)

        # Node: last two rets are inserted by the instrumentation: ignore them
        self.assertEqual(ctraces[0].get_untyped()[:-2], expected_trace)

    @skip_for_backend("uc")
    def test_ind_poison(self) -> None:
        test_case = self._tc_indirect()
        input_ = self._input_builder.get_default_input()

        model = self._get_model("ind", ["cond"], (DATA_BASE, CODE_BASE))
        model.poison_value = POISON_VALUE  # type: ignore

        tc = test_case.to_test_case()
        model.load_test_case(tc)

        ctraces = model.trace_test_case([input_], 1)
        code_base_addr = model.layout.code_start()
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []

        # Call (src and dest)
        expected_trace.append(test_case[5].pc_offset)
        expected_trace.append(test_case[13].pc_offset)
        # Ret (src and dest)
        expected_trace.append(test_case[14].pc_offset)
        expected_trace.append(test_case[6].pc_offset)
        # Second call: this is reachable only if speculation doesn't get rolled-back on the
        # previous faulty load.
        expected_trace.append(test_case[9].pc_offset)
        # The call should be trying to jump to the poison value
        expected_trace.append(model.poison_value - code_base_addr)  # type: ignore

        # Node: last two rets are inserted by the instrumentation: ignore them
        self.assertEqual(ctraces[0].get_untyped()[:-2], expected_trace)

    @skip_for_backend("uc")
    def test_silent_store(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("xor rbx, rbx", 3, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, MEM_DEFAULT_VALUE),
                Inst("mov rbx, qword ptr [r14 + 64]", 4, MAIN_OFFSET + 64, MEM_DEFAULT_VALUE),
                Inst("mov qword ptr [r14], 0", 7, MAIN_OFFSET + 0, 0),
                Inst("mov qword ptr [r14 + 64], rbx", 4, MAIN_OFFSET + 64, MEM_DEFAULT_VALUE),
                Inst("mov qword ptr [r14], 0", 7, MAIN_OFFSET + 0, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(obs_clause="ss", test_case=test_case, input_data=[input_])
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []
        expected_trace.append(test_case[0].pc_offset)  # measurement_start
        expected_trace.append(test_case[1].pc_offset)  # xor
        expected_trace.append(test_case[2].pc_offset)  # xor
        expected_trace.append(test_case[3].pc_offset)  # load
        expected_trace.append(test_case[4].pc_offset)  # load
        expected_trace.append(test_case[5].pc_offset)  # store
        expected_trace.append(test_case[6].pc_offset)  # store
        expected_trace.append(test_case[6].mem_address)  # redundant non-zero store
        expected_trace.append(test_case[7].pc_offset)  # store
        expected_trace.append(test_case[7].mem_address)  # redundant zero store

        # Node: last two insts are inserted by the instrumentation: ignore them
        self.assertEqual(ctraces[0].get_untyped()[:-2], expected_trace)

    @skip_for_backend("uc")
    def test_silent_store_0(self) -> None:
        test_case = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
                Inst("xor rbx, rbx", 3, 0, 0),
                Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, MEM_DEFAULT_VALUE),
                Inst("mov rbx, qword ptr [r14 + 64]", 4, MAIN_OFFSET + 64, MEM_DEFAULT_VALUE),
                Inst("mov qword ptr [r14], 0", 7, MAIN_OFFSET + 0, 0),
                Inst("mov qword ptr [r14 + 64], rbx", 4, MAIN_OFFSET + 64, MEM_DEFAULT_VALUE),
                Inst("mov qword ptr [r14], 0", 7, MAIN_OFFSET + 0, 0),
            ],
            backend=self._backend,
        )
        input_ = self._input_builder.get_default_input()
        ctraces = self._get_trace(obs_clause="ss0", test_case=test_case, input_data=[input_])
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []
        expected_trace.append(test_case[0].pc_offset)  # measurement_start
        expected_trace.append(test_case[1].pc_offset)  # xor
        expected_trace.append(test_case[2].pc_offset)  # xor
        expected_trace.append(test_case[3].pc_offset)  # load
        expected_trace.append(test_case[4].pc_offset)  # load
        expected_trace.append(test_case[5].pc_offset)  # store
        expected_trace.append(test_case[6].pc_offset)  # store
        expected_trace.append(test_case[7].pc_offset)  # store
        expected_trace.append(test_case[7].mem_address)  # redundant zero store

        # Node: last two insts are inserted by the instrumentation: ignore them
        self.assertEqual(ctraces[0].get_untyped()[:-2], expected_trace)


class X86DRModelTest(_SharedX86Model):
    """Unit tests for the x86 DynamoRIO backend adaptor."""

    def __init__(self, methodName: str) -> None:
        super().__init__(methodName)
        self._backend = "dr"
        self._backend_long = "dynamorio"

    @classmethod
    def setUpClass(cls) -> None:
        cls._configure_class("dynamorio")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_class()

    def setUp(self) -> None:
        self._skip_if_not_installed()
        super().setUp()

    def _skip_if_not_installed(self) -> None:
        try:
            DynamoRIOModel._check_if_installed()
        except FileNotFoundError:
            self.skipTest("DynamoRIO is not installed")

    def _get_model(self,
                   obs_clause: str,
                   exec_clause: List[str],
                   data_bases: Tuple[int, int],
                   enable_mismatch_check: bool = False) -> DynamoRIOModel:
        CONF.contract_observation_clause = obs_clause
        CONF.contract_execution_clause = exec_clause
        CONF.model_backend = "dynamorio"
        model = get_model(data_bases, enable_mismatch_check_mode=enable_mismatch_check)
        assert isinstance(model, DynamoRIOModel)
        return model

    def test_clause_configuration(self) -> None:
        # Create a model instance
        model = self._get_model("ct", ["seq"], (DATA_BASE, CODE_BASE))
        self.assertEqual(model._obs_clause_name, "ct")
        self.assertEqual(model._exec_clause_name, "seq")

        # Set new clauses (invalid)
        with self.assertRaises(ConfigException) as e:
            _ = self._get_model("invalid", ["seq"], (DATA_BASE, CODE_BASE))
        self.assertIn("unsupported observation clause", str(e.exception))
        self.assertIn("- ct", str(e.exception))

        with self.assertRaises(ConfigException) as e:
            _ = self._get_model("ct", ["invalid"], (DATA_BASE, CODE_BASE))
        self.assertIn("unsupported execution clause", str(e.exception))
        self.assertIn("- seq", str(e.exception))

        # Set new clauses (invalid, alt interface)
        model = DynamoRIOModel((DATA_BASE, CODE_BASE))
        with self.assertRaises(ValueError):
            model.configure_clauses("invalid", "seq")
        with self.assertRaises(ValueError):
            model.configure_clauses("ct", "invalid")

        self._restore_conf()

    def test_load_test_case(self) -> None:
        model = self._get_model("ct", ["seq"], (DATA_BASE, CODE_BASE))
        inst = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
            ],
            backend=self._backend,
        )
        tc = inst.to_test_case()
        model.load_test_case(tc)

        # Check that a temporary file was created and that it contains the test case
        self.assertIsNotNone(model._files.rcbf)
        assert model._files.rcbf is not None
        with open(model._files.rcbf, "rb") as f:
            rcbf_data = f.read()
        self.assertNotEqual(len(rcbf_data), 0)

        self._restore_conf()

    def test_tc_dispatch(self) -> None:
        # Test that the tracing functions create RDBF and RCBF files

        model = self._get_model("ct", ["seq"], (DATA_BASE, CODE_BASE))
        inst = InstList(
            [
                Inst("xor rax, rax", 3, 0, 0),
            ],
            backend=self._backend,
        )
        tc = inst.to_test_case()
        model.load_test_case(tc)
        _ = model.trace_test_case([InputData()], 1)

        # RDBF
        self.assertIsNotNone(model._files.rdbf)
        assert model._files.rdbf is not None
        with open(model._files.rdbf, "rb") as f:
            rdbf_data = f.read()
        self.assertNotEqual(len(rdbf_data), 0)
        # FIXME: the next two statements should be a part of test_case_data tests
        self.assertEqual(rdbf_data[0], 1)  # number of actors
        self.assertEqual(rdbf_data[8], 1)  # number of inputs

        # RCBF
        self.assertIsNotNone(model._files.rcbf)
        assert model._files.rcbf is not None
        with open(model._files.rcbf, "rb") as f:
            rcbf_data = f.read()
        self.assertEqual(rcbf_data[0], 1)  # number of actors

        # Check that loading another test case with a different input overwrites the files
        inst = self._tc_branch_load()
        tc = inst.to_test_case()
        input_ = InputData()
        input_[0]["main"][0] = TEST_MEM_VALUE_A
        model.load_test_case(tc)
        _ = model.trace_test_case([input_], 1)

        with open(model._files.rcbf, "rb") as f:
            rcbf_data2 = f.read()
        self.assertNotEqual(len(rcbf_data2), 0)
        self.assertNotEqual(rcbf_data, rcbf_data2)

        with open(model._files.rdbf, "rb") as f:
            rdbf_data2 = f.read()
        self.assertNotEqual(len(rdbf_data2), 0)
        self.assertNotEqual(rdbf_data, rdbf_data2)

        self._restore_conf()


class UnicornModelTest(_SharedX86Model):
    """Unit tests for the x86 Unicorn backend adaptor."""

    def __init__(self, methodName: str) -> None:
        super().__init__(methodName)
        self._backend = "uc"
        self._backend_long = "unicorn"

    @classmethod
    def setUpClass(cls) -> None:
        cls._configure_class("unicorn", {
            'instruction_set': 'x86-64',
            'data_generator_seed': 10,
        })

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_class()

    def _get_model(self,
                   obs_clause: str,
                   exec_clause: List[str],
                   data_bases: Tuple[int, int],
                   enable_mismatch_check: bool = False) -> X86UnicornModel:
        CONF.contract_observation_clause = obs_clause
        CONF.contract_execution_clause = exec_clause
        CONF.model_backend = "unicorn"
        model = get_model(data_bases, enable_mismatch_check_mode=enable_mismatch_check)
        assert isinstance(model, X86UnicornModel)
        return model


if __name__ == '__main__':
    unittest.main()
