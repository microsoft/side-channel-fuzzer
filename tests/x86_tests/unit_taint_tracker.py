"""
File: collection of tests for the taint tracking logic in all model backends

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from abc import ABC
from typing import Any, Dict, List, Tuple, Union

import numpy as np

from rvzr.model_unicorn.model import X86UnicornModel
from rvzr.model_dynamorio.model import DynamoRIOModel
from rvzr.tc_components.test_case_data import InputData, InputTaint
from rvzr.traces import CTrace
from rvzr.factory import get_data_generator, get_model
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change

from .model_common import Inst, InstList, DATA_BASE, CODE_BASE, Backend, \
    RAX, RBX, RCX, FLAGS, XMM0, InputBuilder


# ==================================================================================================
# Tests
# ==================================================================================================
class _SharedTaintTrackerTest(ABC, unittest.TestCase):
    """Abstract base class for X86 taint tracking tests.

    Subclasses must define:
        _backend: Backend type ("dr" or "uc")
        _model_backend_name: Model backend name ("dynamorio" or "unicorn")
    """

    _prev_conf: Dict[str, Any]
    _backend: Backend
    _model_backend_name: str

    # Exclude this parent class from test discovery
    @classmethod
    def setUpClass(cls) -> None:
        if cls is _SharedTaintTrackerTest:
            raise unittest.SkipTest("Skipping base class")
        # Validate that subclass defines required attributes
        if not hasattr(cls, '_backend') or not hasattr(cls, '_model_backend_name'):
            raise TypeError(
                f"{cls.__name__} must define class attributes '_backend' and '_model_backend_name'")
        # Save and configure settings for taint tracking tests
        cls._prev_conf = CONF.snapshot()
        CONF.instruction_set = "x86-64"
        CONF.model_backend = cls._model_backend_name
        CONF.disable_generation()
        CONF.logging_modes = []
        update_logging_after_config_change()

    @classmethod
    def tearDownClass(cls) -> None:
        # Restore configuration
        CONF.restore(cls._prev_conf)

    def __init__(self, methodName: str) -> None:
        super().__init__(methodName)
        self._input_builder = InputBuilder()

    def _get_model(self) -> Union[DynamoRIOModel, X86UnicornModel]:
        """Create a model configured for taint tracking."""
        CONF.contract_observation_clause = "ct"
        CONF.contract_execution_clause = ["seq"]
        CONF.model_backend = self._model_backend_name
        model = get_model((DATA_BASE, CODE_BASE), enable_mismatch_check_mode=False)
        assert isinstance(model, (DynamoRIOModel, X86UnicornModel))
        return model

    def _trace_with_taints(self, test_case: InstList,
                           inputs: List[InputData]) -> Tuple[List[CTrace], List[InputTaint]]:
        """Helper to load test case and trace with taints."""
        model = self._get_model()
        tc = test_case.to_test_case()
        model.load_test_case(tc)
        ctraces, taints = model.trace_test_case_with_taints(inputs, nesting=1)
        return ctraces, taints

    def _run_taint_test(self, instructions: List[Inst], input_: InputData) -> InputTaint:
        """Run a taint test and return the taint result for the first input.

        :param instructions: List of instructions to execute
        :param input_: Input data to use for the test
        :return: Taint information for the first input
        """
        test_case = InstList(instructions, backend=self._backend)
        _, taints = self._trace_with_taints(test_case, [input_])
        return taints[0]

    def test_basic_taint(self) -> None:
        instructions = [
            Inst("mov rax, qword ptr [r14 + rax]", 3, 0, 0),
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX)
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['gpr'][RAX])

    def test_reg_to_reg(self) -> None:
        instructions = [
            Inst("add rax, rbx", 0, 0, 0),
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX, RBX)
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['gpr'][RAX])
        self.assertTrue(taint[0]['gpr'][RBX])

    def test_mem_to_reg(self) -> None:
        instructions = [
            Inst("mov rbx, qword ptr [r14 + rbx]", 0, 0, 0),  # main[0] -> RBX
            Inst("mov rax, rbx", 0, 0, 0),  # RBX -> RAX
            Inst("and rax, 0b1", 0, 0, 0),
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),  # RAX tainted
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX, RBX)
        taint = self._run_taint_test(instructions, input_)
        self.assertFalse(taint[0]['gpr'][RAX])
        self.assertTrue(taint[0]['gpr'][RBX])
        self.assertTrue(taint[0]['main'][0])

    def test_load_to_store(self) -> None:
        instructions = [
            Inst("mov qword ptr [r14], rax", 0, 0, 0),  # RAX -> main[0]
            Inst("mov rbx, qword ptr [r14]", 0, 0, 0),  # main[0] -> RBX
            Inst("mov rax, qword ptr [r14 + rbx]", 0, 0, 0),  # RBX tainted
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX, RBX)
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['gpr'][RAX])
        self.assertFalse(taint[0]['gpr'][RBX])

    def test_unaligned_memory_access_taints_both_qwords(self) -> None:
        # Memory accesses spanning 8-byte boundaries must taint both qwords
        instructions = [
            Inst("mov rax, qword ptr [r14 + 0x4]", 0, 0, 0),  # main[0:1] -> RAX
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),  # RAX tainted
        ]
        input_ = self._input_builder.get_input_with_zeroed_memory(main=0)
        input_[0]['main'][1] = 0
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['main'][0])
        self.assertTrue(taint[0]['main'][1])

    def test_simd_register_dependencies_are_tracked(self) -> None:
        # Taint tracking should work for SIMD (XMM) registers
        instructions = [
            Inst("movaps xmm0, xmm1", 0, 0, 0),  # XMM1 -> XMM0
            Inst("movaps xmmword ptr [r14], xmm0", 0, 0, 0),  # XMM0 -> main[0]
            Inst("mov rax, qword ptr [r14]", 0, 0, 0),  # main[0] -> RAX
            Inst("and rax, 0b1", 0, 0, 0),
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),  # RAX tainted
        ]
        input_ = InputData()
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['simd'][XMM0])

    def test_32bit_writes_preserve_64bit_dependencies(self) -> None:
        # Writing to 32-bit registers (eax) should preserve dependencies from 64-bit (rax)
        instructions = [
            Inst("mov rax, rbx", 0, 0, 0),  # RBX -> RAX
            Inst("mov eax, ecx", 0, 0, 0),  # ECX -> EAX (RAX must remain dependent on RBX)
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),  # RAX tainted
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX, RBX, RCX)
        taint = self._run_taint_test(instructions, input_)
        self.assertFalse(taint[0]['gpr'][RAX])
        self.assertTrue(taint[0]['gpr'][RBX])
        self.assertTrue(taint[0]['gpr'][RCX])

    def test_lea_address_computation_propagates_taint(self) -> None:
        # LEA computes addresses; operands used in address calculation should be tainted
        instructions = [
            Inst("lea rax, qword ptr [rbx]", 0, 0, 0),  # RBX -> RAX
            Inst("mov rax, qword ptr [r14 + rax]", 0, 0, 0),  # RAX tainted
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX, RBX)
        taint = self._run_taint_test(instructions, input_)
        self.assertFalse(taint[0]['gpr'][RAX])
        self.assertTrue(taint[0]['gpr'][RBX])

    def test_control_flow_dependency_taints_condition(self) -> None:
        # Data used in conditional branches creates control-flow dependencies
        instructions = [
            Inst("mov rax, qword ptr [r14 + 0x0]", 0, 0, 0),  # main[0] -> RAX
            Inst("cmp rax, 0", 0, 0, 0),  # RAX -> flags
            Inst("je .label", 0, 0, 0),  # Conditional branch on flags
            Inst(".label:", 0, 0, 0),
        ]
        input_ = self._input_builder.get_input_with_zeroed_gprs(RAX)
        taint = self._run_taint_test(instructions, input_)
        self.assertTrue(taint[0]['gpr'][FLAGS])
        self.assertTrue(taint[0]['main'][0])
        self.assertFalse(taint[0]['gpr'][RAX])


class X86DRTaintTrackerTest(_SharedTaintTrackerTest):
    """Unit tests for the x86 DynamoRIO backend adaptor."""

    _backend: Backend = "dr"
    _model_backend_name: str = "dynamorio"

    def _skip_if_not_installed(self) -> None:
        try:
            DynamoRIOModel._check_if_installed()  # type: ignore
        except FileNotFoundError:
            self.skipTest("DynamoRIO is not installed")

    def setUp(self) -> None:
        self._skip_if_not_installed()

    def test_simd_taints_preserve_all_qwords(self) -> None:
        cases = [("pmovmskb edi, xmm1", qword) for qword in range(2)]
        cases += [("vpmovmskb edi, ymm1", qword) for qword in range(4)]
        for extract_mask, qword in cases:
            with self.subTest(extract_mask=extract_mask, qword=qword):
                instructions = [
                    Inst(extract_mask, 0, 0, 0),
                    Inst(f"shr rdi, {qword * 8}", 0, 0, 0),
                    Inst("and rdi, 0x1fff", 0, 0, 0),
                    Inst("mov rax, qword ptr [r14 + rdi]", 0, 0, 0),
                ]
                test_case = InstList(instructions, backend=self._backend)
                original = InputData()
                original.linear_view(0)[:] = 0
                changed = original.copy()
                changed[0]['simd'][4 + qword] = 0x80
                model = self._get_model()
                model.load_test_case(test_case.to_test_case())
                traces, taints = model.trace_test_case_with_taints([original, changed], nesting=1)
                self.assertNotEqual(traces[0], traces[1])
                self.assertTrue(taints[0][0]['simd'][4 + qword])

                boosted = get_data_generator(42).generate_boosted([original], [taints[0]], 2)
                self.assertEqual(model.trace_test_case(boosted, nesting=1), [traces[0], traces[0]])

    def test_partial_simd_write_preserves_upper_alias_dependencies(self) -> None:
        instructions = [
            Inst("vmovdqu ymm0, ymm1", 0, 0, 0),
            Inst("movq xmm0, rax", 0, 0, 0),
            Inst("vmovdqu ymmword ptr [r14], ymm0", 0, 0, 0),
            Inst("mov rcx, qword ptr [r14]", 0, 0, 0),
            Inst("and rcx, 0x1fff", 0, 0, 0),
            Inst("mov rdx, qword ptr [r14 + rcx]", 0, 0, 0),
            Inst("mov rbx, qword ptr [r14 + 24]", 0, 0, 0),
            Inst("and rbx, 0x1fff", 0, 0, 0),
            Inst("mov rcx, qword ptr [r14 + rbx]", 0, 0, 0),
        ]
        test_case = InstList(instructions, backend=self._backend)
        input_ = InputData()
        input_.linear_view(0)[:] = 0
        _, taints = self._trace_with_taints(test_case, [input_])
        self.assertTrue(taints[0][0]['gpr'][RAX])
        self.assertTrue(taints[0][0]['simd'][7])

    def test_non_temporal_load_propagates_memory_dependencies(self) -> None:
        instructions = [
            Inst("movntdqa xmm1, xmmword ptr [r14]", 0, 0, 0),
            Inst("pmovmskb edi, xmm1", 0, 0, 0),
            Inst("and rdi, 0x1fff", 0, 0, 0),
            Inst("mov rax, qword ptr [r14 + rdi]", 0, 0, 0),
        ]
        test_case = InstList(instructions, backend=self._backend)
        original = InputData()
        original.linear_view(0)[:] = 0
        changed = original.copy()
        changed[0]['main'][1] = 0x80
        model = self._get_model()
        model.load_test_case(test_case.to_test_case())
        traces, taints = model.trace_test_case_with_taints([original, changed], nesting=1)
        self.assertNotEqual(traces[0], traces[1])
        self.assertTrue(taints[0][0]['main'][0])
        self.assertTrue(taints[0][0]['main'][1])
        boosted = get_data_generator(42).generate_boosted([original], [taints[0]], 2)
        self.assertEqual(model.trace_test_case(boosted, nesting=1), [traces[0], traces[0]])

    def test_batch_taints_match_isolated_inputs(self) -> None:
        instructions = [
            Inst("and rax, 0x1ff8", 0, 0, 0),
            Inst("mov rbx, qword ptr [r14 + rax]", 0, 0, 0),
            Inst("and rbx, 0x1ff8", 0, 0, 0),
            Inst("mov rcx, qword ptr [r14 + rbx]", 0, 0, 0),
        ]
        test_case = InstList(instructions, backend=self._backend)
        first = InputData()
        first.linear_view(0)[:] = 0
        second = first.copy()
        second[0]['gpr'][RAX] = 16
        for inputs in ([first, second], [second, first]):
            _, batch_taints = self._trace_with_taints(test_case, inputs)
            for input_, batch_taint in zip(inputs, batch_taints):
                _, isolated_taints = self._trace_with_taints(test_case, [input_])
                np.testing.assert_array_equal(
                    batch_taint.linear_view(0), isolated_taints[0].linear_view(0))


class UnicornTaintTrackerTest(_SharedTaintTrackerTest):
    """Unit tests for the x86 Unicorn backend adaptor."""

    _backend: Backend = "uc"
    _model_backend_name: str = "unicorn"


if __name__ == '__main__':
    unittest.main()
