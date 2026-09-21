""" File: Collection of minimization passes that analyse the test case without modifying it.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List
from typing_extensions import assert_never

from ..model_unicorn import model as uc_model, tracer as uc_tracer, \
    interpreter as uc_interpreter
from ..model_unicorn.speculators import SeqSpeculator
from ..sandbox import CodeArea
from ..arch.x86.target_desc import X86TargetDesc
from ..arch.arm64.target_desc import ARM64TargetDesc
from ..config import CONF

from .instruction_passes import BaseInstructionMinimizationPass

if TYPE_CHECKING:
    from ..traces import Violation, CTraceEntry
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_code import TestCaseProgram
    from ..target_desc import TargetDesc


def _get_seq_model(data_start: int, code_start: int) -> uc_model.UnicornModel:
    """
    This is a partial duplicate of the code in factory.py,
    but we cannot import factory.py here due to circular imports.
    """
    model_cls: type[uc_model.UnicornModel]
    target_desc: TargetDesc
    interpreter: type[uc_interpreter.ExtraInterpreter]
    if CONF.instruction_set == "x86-64":
        model_cls = uc_model.X86UnicornModel
        target_desc = X86TargetDesc()
        interpreter = uc_interpreter.X86ExtraInterpreter
    elif CONF.instruction_set == "arm64":
        model_cls = uc_model.ARM64UnicornModel
        target_desc = ARM64TargetDesc()
        interpreter = uc_interpreter.ARMExtraInterpreter
    else:
        assert_never(CONF.instruction_set)

    bases = (data_start, code_start)
    model = model_cls(bases, target_desc, SeqSpeculator, uc_tracer.CTTracer, interpreter)
    return model


class AddViolationCommentsPass(BaseInstructionMinimizationPass):
    """
    An instrumentation pass that iterates over the test case and adds comments
    with the memory addresses of the loads and stores that caused the violation.
    """
    name = "Violation Comment Insertion"
    violation: Violation

    def set_violation(self, violation: Violation) -> None:
        self.violation = violation

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        # pylint: disable=too-many-branches, too-many-locals
        # justification: needs FIXME - this function was written in a hurry and needs refactoring

        # reproduce the violation to get violating input IDs
        v_inputs = [m.input_ for m in self.violation.measurements[:2]]
        v_input_ids = [m.input_id for m in self.violation.measurements[:2]]

        # create a model that will collect PC and memory traces
        data_start, code_start = 0x2000000, 0x1000000
        model = _get_seq_model(data_start, code_start)

        # collect traces
        model.tracer.enable_tracing = True  # start tracing from the very beginning
        model.load_test_case(test_case)
        ctraces_obj = model.trace_test_case(v_inputs, 30)
        ctraces: List[List[CTraceEntry]] = [t.get_typed() for t in ctraces_obj]

        # select loads and stores form the traces
        ctrace_maps = []
        for ctrace in ctraces:
            ctrace_map = {}
            for v1, v2, v3 in zip(ctrace, ctrace[1:], ctrace[2:]):
                if v1.type_ == 'pc' and v2.type_ == 'mem':
                    pc = v1.value
                    ld_addr = v2.value
                    st_addr = v3.value if v3.type_ == 'mem' else 0
                    ctrace_map[pc] = (ld_addr, st_addr)
            ctrace_maps.append(ctrace_map)

        # get the contents of the asm file
        lines = []
        with open(test_case.asm_path(), "r") as f:
            lines = list(enumerate(f))

        # to simplify the next step, get a dictionary mapping assembly lines to PCs
        line_num_to_pc = {}
        for func in test_case.iter_functions():
            actor_id = func.get_owner().get_id()
            actor_start_pc = model.layout.get_code_addr(CodeArea.MAIN, actor_id)
            for bb in func:
                for inst in list(bb) + bb.terminators:
                    pc = actor_start_pc + inst.section_offset() - code_start
                    line_num = inst.line_num()
                    if line_num != 0:
                        line_num_to_pc[line_num] = pc

        # add a comment with the load/store addresses to the assembly
        with open(test_case.asm_path(), 'w') as f:
            for i, line in lines:
                f.write(line)
                if i not in line_num_to_pc:
                    continue
                pc = line_num_to_pc[i]
                if pc not in ctrace_maps[0] or pc not in ctrace_maps[1]:
                    continue

                ld, st, cl, of = [0, 0], [0, 0], [0, 0], [0, 0]
                iid = v_input_ids
                for i in range(2):
                    ld[i], st[i] = ctrace_maps[i][pc]
                    cl[i] = (ld[i] % 0x1000) // 64
                    of[i] = (ld[i] % 0x1000) % 64

                if st[0] != 0 or st[1] != 0:
                    f.write(
                        f"{self._comment_symbol} "
                        f"mem access: [{iid[0]}] {hex(ld[0])}-{hex(st[0])} CL {cl[0]}:{of[0]} | "
                        f"[{iid[1]}] {hex(ld[1])}-{hex(st[1])} CL {cl[1]}:{of[1]}\n")
                else:
                    f.write(f"{self._comment_symbol} "
                            f"mem access: [{iid[0]}] {hex(ld[0])} CL {cl[0]}:{of[0]} | "
                            f"[{iid[1]}] {hex(ld[1])} CL {cl[1]}:{of[1]}\n")

                if st[0] == 0xff8 or st[1] == 0xff8:
                    f.write(f"{self._comment_symbol} exception?\n")

        return test_case

    def modify_instruction(self, _: List[str], __: int) -> List[str]:
        return []  # unused

    def verify_modification(self, _: TestCaseProgram, __: List[InputData]) -> bool:
        return True  # unused
