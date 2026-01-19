"""
File: A script that downloads the x86 instruction set from the Side Channel Fuzzer repository
      and parses it into a JSON file that can be used by the generator.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import sys
import json
import subprocess
from typing import List, Optional, Literal
from xml.etree import ElementTree as ET

# ==================================================================================================
# x86-specific constants
# ==================================================================================================
REG_SIZE = {
    "rax": 64,
    "rbx": 64,
    "rcx": 64,
    "rdx": 64,
    "r11": 64,
    "rip": 64,
    "rsp": 64,
    "rbp": 64,
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "ax": 16,
    "dx": 16,
    "bp": 16,
    "sp": 16,
    "al": 8,
    "ah": 8,
    "cl": 8,
    "spl": 8,
    "tmm0": 0,
    "mxcsr": 32,
    'es': 16,
    'ss': 16,
    'ds': 16,
    'fs': 16,
    'gs': 16,
    'cr0': 64,
    'cr3': 64,
    'cr4': 64,
    'cr8': 64,
    'xcr0': 64,
    'dr0': 64,
    'dr1': 64,
    'dr2': 64,
    'dr3': 64,
    'dr6': 64,
    'dr7': 64,
    'gdtr': 80,
    'ldtr': 96,
    'idtr': 80,
    'tr': 16,
    'msrs': 64,
    'x87control': 16,
    'x87pop': 16,
    'x87status': 16,
    'tsc': 64,
    "tscaux": 64,
    "fsbase": 64,
    "gsbase": 64,
}
REG_SIZE.update({f"mm{i}": 64 for i in range(8)})
REG_SIZE.update({f"xmm{i}": 128 for i in range(16)})
REG_SIZE.update({f"ymm{i}": 256 for i in range(16)})
# REG_SIZE.update({f"zmm{i}": 512 for i in range(32)})

# A list of instructions that have RIP as an operand but should
# not be considered as control-flow instructions by the generator
NON_CONTROL_FLOW_INST = ["int", "int1", "int3", "into"]

# ==================================================================================================
# Lists of x86 extensions
# ==================================================================================================

# Instructions that can be tested without any repercussions
# This list for our default model backend (Unicorn)
SAFE_EXTENSIONS = [
    "BASE",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE4a",
    "CLFLUSHOPT",
    "CLFSH",
    "SSE",
    "RDTSCP",
    "LONGMODE",
]

# Instructions that can be tested without any repercussions
# on the new (experimental) backend, DynamoRIO
SAFE_EXTENSIONS_DR = [
    "3DNOW_PREFETCH",
    "3DNOW",
    "ADOX_ADCX",
    "AES",
    "AVX_VNNI",
    "AVX",
    "AVX2",
    "AVX2GATHER",
    "AVX512EVEX",
    "AVX512VEX",
    "AVXAES",
    "BASE",
    "BMI1",
    "BMI2",
    "CLFLUSHOPT",
    "CLFSH",
    "FMA",
    "FMA4",
    "GFNI",
    "LONGMODE",
    "LZCNT",
    "MCOMMIT",
    "MMX",
    "MOVBE",
    "MOVDIR",
    "PCLMULQDQ",
    "PCONFIG",
    "PKU",
    "PREFETCHWT1",
    "PTWRITE",
    "RDPID",
    "RDPRU",
    "RDRAND",
    "RDSEED",
    "RDWRFSGS",
    "SERIALIZE",
    "SHA",
    "SMAP",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE4a",
    "SSSE3",
    "TBM",
    "UINTR",
    "VAES",
    "VPCLMULQDQ",
    "XOP",
]

# Instructions that can potentially crash the system if the fuzzer is misconfigured
ALL_EXTENSIONS = SAFE_EXTENSIONS + [
    "VTX",
    "SVM",
    "SMX",
    "WBNOINVD",
    "XSAVE",
    "XSAVEOPT",
    "XSAVES",
    "SGX",
    "ENQCMD",
    "INVPCID",
    "KEYLOCKER",
    "MONITOR",
    "PAUSE",
    "RDRAND",
    "RDSEED",
    "RDWRFSGS",
    "HRESET",
    "SMAP",
    "AMD_INVLPGB",
    "SNP",
]

# ==================================================================================================
# Internal Classes that represent the parsed XML data
# ==================================================================================================
OP_TYPE = Literal["REG", "MEM", "AGEN", "IMM", "LABEL", "FLAGS"]


class _XMLOperandSpec:
    """
    A class that represents an operand parsed from the XML file
    """
    values: List[str]
    type_: OP_TYPE
    xtype: str
    width: int
    is_signed: bool = True
    comment: str
    src: bool = False
    dest: bool = False
    magic: bool = False

    def to_json(self) -> str:
        """ Converts the operand to a JSON string """
        values_lower = []
        for v in self.values:
            values_lower.append(v.lower())
        self.values = values_lower
        return json.dumps(self, default=vars)


class _XMLInstructionSpec:
    """ A class that represents an instruction parsed from the XML file """
    name: str
    category: str = ""
    is_control_flow: bool = False
    operands: List[_XMLOperandSpec]
    implicit_operands: List[_XMLOperandSpec]

    def __init__(self) -> None:
        self.operands = []
        self.implicit_operands = []

    def __str__(self) -> str:
        return f"{self.name} {self.is_control_flow} {self.category} " \
            f"{len(self.operands)} {len(self.implicit_operands)}"

    def to_json(self) -> str:
        """ Converts the instruction to a JSON string """
        s = "{"
        s += f'"name": "{self.name.lower()}", "category": "{self.category}", '
        s += f'"is_control_flow": {str(self.is_control_flow).lower()},\n'
        s += '  "operands": [\n    '
        s += ',\n    '.join([o.to_json() for o in self.operands])
        s += '\n  ],\n'
        if self.implicit_operands:
            s += '  "implicit_operands": [\n    '
            s += ',\n    '.join([o.to_json() for o in self.implicit_operands])
            s += '\n  ]'
        else:
            s += '  "implicit_operands": []'
        s += "\n}"
        return s


# ==================================================================================================
# Classes that parse the XML file and convert it to JSON
# ==================================================================================================
class _ParseFailed(Exception):
    """ An exception that is raised when parsing fails """


class XMLSpecParser:
    """ A class that parses the XML file and converts it to JSON """
    n_instructions_in_xml: int = 0
    _tree: ET.Element
    _instructions: List[_XMLInstructionSpec]
    _current_spec: _XMLInstructionSpec

    def __init__(self, extensions: List[str]) -> None:
        self.extensions = extensions
        self._instructions = []

    def __len__(self) -> int:
        return len(self._instructions)

    def parse_file(self, filename: str) -> None:
        """ Parsed the XML file and saves a list of _XMLInstructionSpec objects """

        # Get a tree from the XML file
        parser = ET.ElementTree()
        tree = parser.parse(filename)
        if not tree:
            print("No input. Exiting")
            sys.exit(1)
        self._tree = tree
        self.n_instructions_in_xml = len(list(self._tree.iter('instruction')))

        # Check if the requested extensions are available
        self._check_extension_list()

        # Parse all nodes in the tree
        for instruction_node in self._tree.iter('instruction'):
            instruction_spec = self._parse_node(instruction_node)  # pylint: disable=e1128
            if instruction_spec is not None:
                self._instructions.append(instruction_spec)

    def save_as_json(self, filename: str) -> None:
        """ Saves the parsed instructions as a JSON file """
        json_str = "[\n" + ",\n".join([i.to_json() for i in self._instructions]) + "\n]"
        # print(json_str)
        with open(filename, "w+") as f:
            f.write(json_str)

    def _parse_node(self, node: ET.Element) -> Optional[_XMLInstructionSpec]:
        # pylint: disable=too-many-branches  # Justified because it's a parser

        # Check if the node should be skipped
        if self._node_is_not_supported(node):
            return None
        if node.attrib['extension'] not in self.extensions:
            return None

        # Create a new instruction spec
        instruction = _XMLInstructionSpec()

        # Parse instruction attributes
        instruction.category = f"{node.attrib['extension']}-{node.attrib['category']}"
        instruction.name = node.attrib['asm'].removeprefix("{load} ")\
            .removeprefix("{store} ").removeprefix("{disp32} ").lower()

        try:
            for op_node in node.iter('operand'):
                # Create a new operand spec based on the node type
                op_type = op_node.attrib['type']
                if op_type == 'reg':
                    parsed_op = self._parse_reg_operand(op_node)
                elif op_type == 'mem':
                    parsed_op = self._parse_mem_operand(op_node)
                elif op_type == 'agen':
                    op_node.text = node.attrib['agen']
                    parsed_op = self._parse_agen_operand(op_node)
                elif op_type == 'imm':
                    parsed_op = self._parse_imm_operand(op_node)
                elif op_type == 'relbr':
                    parsed_op = self._parse_label_operand(op_node)
                elif op_type == 'flags':
                    parsed_op = self._parse_flags_operand(op_node)
                else:
                    raise _ParseFailed("Unknown operand type " + op_type)

                # Add the operand to the instruction
                if op_node.attrib.get('suppressed', '0') == '1':
                    instruction.implicit_operands.append(parsed_op)
                else:
                    instruction.operands.append(parsed_op)

                # Set additional operand attributes
                if op_node.attrib.get('implicit', '0') == '1':
                    parsed_op.magic = True

                # Set additional instruction attributes based on the operand
                if parsed_op.type_ == "REG":
                    text = getattr(op_node, 'text', '').lower()
                    if text == "rip" and instruction.name not in NON_CONTROL_FLOW_INST:
                        instruction.is_control_flow = True
                elif parsed_op.type_ == "LABEL":
                    instruction.is_control_flow = True

        except _ParseFailed as e:
            # If parsing fails, skip the instruction
            print(f"WARN: Skipping instruction {instruction.name} due to `{e}`")
            return None

        return instruction

    def _node_is_not_supported(self, node: ET.Element) -> bool:
        return node.attrib.get('sae', '') == '1' or \
            node.attrib.get('roundc', '') == '1' or \
            node.attrib.get('zeroing', '') == '1'

    def _parse_reg_operand(self, op: ET.Element) -> _XMLOperandSpec:
        assert op.text is not None

        spec = _XMLOperandSpec()
        spec.type_ = "REG"
        if op.attrib.get('xtype', '') != '':
            spec.xtype = op.attrib.get('xtype', '')

        spec.values = op.text.lower().split(',')
        if spec.values[0] not in REG_SIZE:
            raise _ParseFailed(f"Unsupported register operand {spec.values[0]}")

        spec.src = op.attrib.get('r', "0") == "1"
        spec.dest = op.attrib.get('w', "0") == "1"

        spec.width = int(op.attrib.get('width', 0))
        if spec.width == 0:
            spec.width = REG_SIZE[spec.values[0]]

        return spec

    @staticmethod
    def _parse_mem_operand(op: ET.Element) -> _XMLOperandSpec:
        assert op.attrib is not None

        # asserts are for unsupported instructions
        if op.attrib.get('VSIB', '0') != '0':
            raise _ParseFailed("Vector SIB memory addressing is not supported")
        # assert op.attrib.get('VSIB', '0') == '0'  # asm += '[' + op.attrib.get('VSIB') + '0]'
        if op.attrib.get('memory-suffix', '') != '':
            raise _ParseFailed(f"Unsupported memory suffix {op.attrib.get('memory-suffix', '')}")

        choices = []
        if op.attrib.get('base', ''):
            choices = [op.attrib.get('base', '')]

        spec = _XMLOperandSpec()
        spec.type_ = "MEM"
        spec.values = choices
        spec.src = op.attrib.get('r', "0") == "1"
        spec.dest = op.attrib.get('w', "0") == "1"
        spec.width = int(op.attrib.get('width', '0'))
        return spec

    @staticmethod
    def _parse_agen_operand(_: ET.Element) -> _XMLOperandSpec:
        spec = _XMLOperandSpec()
        spec.type_ = "AGEN"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 64
        return spec

    @staticmethod
    def _parse_imm_operand(op: ET.Element) -> _XMLOperandSpec:
        assert op.attrib is not None

        spec = _XMLOperandSpec()
        spec.type_ = "IMM"
        if op.attrib.get('implicit', '0') == '1':
            assert op.text is not None
            spec.values = [op.text]
        else:
            spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = int(op.attrib.get('width', '0'))
        if op.attrib.get('s', '1') == '0':
            spec.is_signed = False
        return spec

    @staticmethod
    def _parse_label_operand(_: ET.Element) -> _XMLOperandSpec:
        spec = _XMLOperandSpec()
        spec.type_ = "LABEL"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 0
        return spec

    @staticmethod
    def _parse_flags_operand(op: ET.Element) -> _XMLOperandSpec:
        spec = _XMLOperandSpec()
        spec.type_ = "FLAGS"
        spec.values = [
            op.attrib.get("flag_CF", ""),
            op.attrib.get("flag_PF", ""),
            op.attrib.get("flag_AF", ""),
            op.attrib.get("flag_ZF", ""),
            op.attrib.get("flag_SF", ""),
            op.attrib.get("flag_TF", ""),
            op.attrib.get("flag_IF", ""),
            op.attrib.get("flag_DF", ""),
            op.attrib.get("flag_OF", ""),
        ]
        spec.src = False
        spec.dest = False
        spec.width = 0
        return spec

    def add_missing(self) -> None:  # pylint: disable=too-many-statements
        """ Adds the instructions specs that are missing from the XML file we use """
        extensions = self.extensions
        if not extensions or "CLFSH" in extensions:
            for width in [8, 16, 32, 64]:
                inst = _XMLInstructionSpec()
                inst.name = "clflush"
                inst.category = "CLFSH-MISC"
                inst.is_control_flow = False
                op = _XMLOperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self._instructions.append(inst)

        if not extensions or "CLFLUSHOPT" in extensions:
            for width in [8, 16, 32, 64]:
                inst = _XMLInstructionSpec()
                inst.name = "clflushopt"
                inst.category = "CLFLUSHOPT-CLFLUSHOPT"
                inst.is_control_flow = False
                op = _XMLOperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self._instructions.append(inst)

        if not extensions or "BASE" in extensions:
            inst = _XMLInstructionSpec()
            inst.name = "int1"
            inst.category = "BASE-INTERRUPT"
            inst.is_control_flow = False
            op1 = _XMLOperandSpec()
            op1.type_, op1.src, op1.dest, op1.width = "REG", False, True, 64
            op1.values = ["rip"]
            op2 = _XMLOperandSpec()
            op2.type_, op2.src, op2.dest, op2.width = "FLAGS", False, False, 0
            op2.values = ["", "", "", "", "", "w", "w", "", ""]
            inst.implicit_operands = [op1, op2]
            self._instructions.append(inst)

    def _check_extension_list(self) -> None:
        # get a list of all available extensions
        available_extensions = set()
        for instruction_node in self._tree.iter('instruction'):
            available_extensions.add(instruction_node.attrib['extension'])

        # check if the requested extensions are available
        for ext in self.extensions:
            if ext not in available_extensions:
                print(f"ERROR: Unknown extension {ext}")
                print("\nAvailable extensions:")
                print(list(available_extensions))


class Downloader:
    """ A class that downloads the x86 instruction set and converts it to JSON """

    def __init__(self, extensions: List[str], out_file: str) -> None:
        if "ALL_SUPPORTED" in extensions:
            extensions.extend(SAFE_EXTENSIONS)
            extensions = list(set(extensions))
            extensions.remove("ALL_SUPPORTED")
        elif "ALL_SUPPORTED_DR" in extensions:
            extensions.extend(SAFE_EXTENSIONS_DR)
            extensions = list(set(extensions))
            extensions.remove("ALL_SUPPORTED_DR")
        elif "ALL_AND_UNSAFE" in extensions:
            extensions.extend(ALL_EXTENSIONS)
            extensions = list(set(extensions))
            extensions.remove("ALL_AND_UNSAFE")
        self.extensions = extensions
        self.out_file = out_file
        self._transformer = XMLSpecParser(self.extensions)

    def run(self) -> None:
        """ Downloads the XML file and converts it to JSON """

        print("> Downloading complete instruction spec...")
        subprocess.run(
            "curl -L -o x86_instructions.xml "
            "https://github.com/microsoft/side-channel-fuzzer/releases/download/"
            "v1.3.0/x86_instructions.xml",
            shell=True,
            check=True)

        print("\n> Filtering and transforming the instruction spec...")
        try:
            self._transformer.parse_file("x86_instructions.xml")
            self._transformer.add_missing()
            self._transformer.save_as_json(self.out_file)
        finally:
            subprocess.run("rm x86_instructions.xml", shell=True, check=True)

        n_parsed = len(self._transformer)
        n_all = self._transformer.n_instructions_in_xml
        print(f"Produced base.json with {n_parsed} instructions (out of {n_all} possible)")


# NOTE: for reference, the complete list of all categories available in the XML file is:
# "3DNOW-3DNOW", "ADOX_ADCX-ADOX_ADCX", "AES-AES", "AVXAES-AES", "AMX_BF16-AMX_TILE",
# "AMX_INT8-AMX_TILE", "AMX_TILE-AMX_TILE", "AVX2-AVX2", "AVX2GATHER-AVX2GATHER",
# "AVX512EVEX-AVX512_4FMAPS", "AVX512EVEX-AVX512_4VNNIW", "AVX512EVEX-AVX512_BITALG",
# "AVX512EVEX-AVX512", "AVX512EVEX-AVX512_VBMI", "AVX512EVEX-AVX512_VP2INTERSECT", "AVX-AVX",
# "BASE-BINARY", "BASE-BITBYTE", "SSE4a-BITBYTE", "AVX512EVEX-BLEND", "BMI1-BMI1", "BMI2-BMI2",
# "AVX-BROADCAST", "AVX2-BROADCAST", "AVX512EVEX-BROADCAST", "BASE-CALL", "CET-CET",
# "CLDEMOTE-CLDEMOTE", "CLFLUSHOPT-CLFLUSHOPT", "CLWB-CLWB", "CLZERO-CLZERO", "BASE-CMOV",
# "AVX512EVEX-COMPRESS", "BASE-COND_BR", "RTM-COND_BR", "AVX512EVEX-CONFLICT", "AVX-CONVERT",
# "AVX512EVEX-CONVERT", "BASE-CONVERT", "F16C-CONVERT", "LONGMODE-CONVERT", "SSE-CONVERT",
# "SSE2-CONVERT", "AVX-DATAXFER", "AVX2-DATAXFER", "AVX512EVEX-DATAXFER", "BASE-DATAXFER",
# "LONGMODE-DATAXFER", "MMX-DATAXFER", "MOVBE-DATAXFER", "SSE-DATAXFER", "SSE2-DATAXFER",
# "SSE3-DATAXFER", "SSE4a-DATAXFER", "ENQCMD-ENQCMD", "AVX512EVEX-EXPAND", "X87-FCMOV",
# "BASE-FLAGOP", "FMA4-FMA4", "AVX512EVEX-FP16", "AVX512EVEX-GATHER", "AVX512EVEX-GFNI",
# "GFNI-GFNI", "HRESET-HRESET", "AVX512EVEX-IFMA", "BASE-INTERRUPT", "BASE-IO",
# "BASE-IOSTRINGOP", "KEYLOCKER-KEYLOCKER", "KEYLOCKER_WIDE-KEYLOCKER_WIDE",
# "AVX512VEX-KMASK", "TDX-LEGACY", "AVX-LOGICAL", "AVX2-LOGICAL", "AVX512EVEX-LOGICAL",
# "BASE-LOGICAL", "MMX-LOGICAL", "RTM-LOGICAL", "SSE2-LOGICAL", "SSE4-LOGICAL",
# "AVX-LOGICAL_FP", "AVX512EVEX-LOGICAL_FP", "SSE-LOGICAL_FP", "SSE2-LOGICAL_FP",
# "LZCNT-LZCNT", "BASE-MISC", "CLFSH-MISC", "INVPCID-MISC", "MCOMMIT-MISC", "MONITOR-MISC",
# "MONITORX-MISC", "PAUSE-MISC", "SSE-MISC", "SSE2-MISC", "3DNOW-MMX", "MMX-MMX",
# "SSE2-MMX", "SSSE3-MMX", "MOVDIR-MOVDIR", "MPX-MPX", "BASE-NOP", "PCLMULQDQ-PCLMULQDQ",
# "PCONFIG-PCONFIG", "PKU-PKU", "BASE-POP", "LONGMODE-POP", "3DNOW_PREFETCH-PREFETCH",
# "SSE-PREFETCH", "PREFETCHWT1-PREFETCHWT1", "PTWRITE-PTWRITE", "BASE-PUSH", "LONGMODE-PUSH",
# "RDPID-RDPID", "RDPRU-RDPRU", "RDRAND-RDRAND", "RDSEED-RDSEED", "RDWRFSGS-RDWRFSGS",
# "BASE-RET", "LONGMODE-RET", "BASE-ROTATE", "AVX512EVEX-SCATTER", "BASE-SEGOP", "BASE-SEMAPHORE",
# "LONGMODE-SEMAPHORE", "SERIALIZE-SERIALIZE", "BASE-SETCC", "SGX-SGX", "SHA-SHA",
# "BASE-SHIFT", "SMAP-SMAP", "SSE-SSE", "SSE2-SSE", "SSE3-SSE", "SSE4-SSE", "SSSE3-SSE",
# "BASE-STRINGOP", "LONGMODE-STRINGOP", "AVX-STTNI", "BASE-SYSCALL", "LONGMODE-SYSCALL",
# "BASE-SYSRET", "LONGMODE-SYSRET", "AMD_INVLPGB-SYSTEM", "BASE-SYSTEM", "LONGMODE-SYSTEM",
# "RDTSCP-SYSTEM", "SMX-SYSTEM", "SNP-SYSTEM", "SVM-SYSTEM", "WBNOINVD-SYSTEM", "TBM-TBM",
# "TSX_LDTRK-TSX_LDTRK", "UINTR-UINTR", "BASE-UNCOND_BR", "RTM-UNCOND_BR", "AVX512EVEX-VAES",
# "VAES-VAES", "AVX512EVEX-VBMI2", "AVX_VNNI-VEX", "AVX512EVEX-VFMA", "FMA-VFMA",
# "VIA_PADLOCK_AES-VIA_PADLOCK", "VIA_PADLOCK_RNG-VIA_PADLOCK", "VIA_PADLOCK_SHA-VIA_PADLOCK",
# "AVX512EVEX-VPCLMULQDQ", "VPCLMULQDQ-VPCLMULQDQ", "VMFUNC-VTX", "VTX-VTX", "WAITPKG-WAITPKG",
# "BASE-WIDENOP", "SSE3-X87_ALU", "X87-X87_ALU", "XOP-XOP", "XSAVE-XSAVE", "XSAVEC-XSAVE",
# "XSAVES-XSAVE", "XSAVEOPT-XSAVEOPT"
