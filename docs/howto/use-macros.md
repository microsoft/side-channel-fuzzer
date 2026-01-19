# How To Use Macros

This document explains the concept of macros in Revizor and describes how to create test cases that use macros.

Note that macros are especially useful in the template-based mode of Revizor, so if you are not familiar, check out the [Template-Based Mode](../howto/use-templates.md) documentation as well.

## What is a macro?

Macros in Revizor are special pseudo-instructions that provide a flexible way to insert complex operations into test cases. They appear as labels of a special format in the assembly code but are dynamically expanded into actual implementations during execution by the model and the executor.

Macros solve two key challenges, especially in the context of multi-domain testing:

* Structuring: Enable insertion of pre-defined instruction sequences (like domain transitions or microarchitectural isolation primitives) within randomized test contexts
* Unification: Allow the same test case template to be instantiated differently across executor and model stages, accommodating differences in ISA support.

## Why use macros?

Macros exist to provide extra flexibility and convenience when creating test case. There are certain operations that are cumbersome or impractical to express directly in assembly code, and macros serve to abstract away these complexities.


## Macro Definition and Usage

### Assembly Syntax

Macros use standard assembly syntax of a label with the `.macro` prefix:

```assembly
.macro.macro_name.argument1.argument2.argument3.argument4:
```

A macro can take at most four arguments. The arguments are strictly static; Revizor does not support dynamic arguments in macros, such as registers or memory addresses.


### Example Usage

A user can create a test case program where only a subset of instruction is measured by using `measurement_start` and `measurement_end` macros:

```asm
.intel_syntax noprefix
.section .data.main

... ; non-measured code here

.macro.measurement_start:

... ; measured code here

.macro.measurement_end:

... ; non-measured code here

.test_case_exit:
```

Revizor will automatically replace the macros with no-op operations of an ISA-dependent size, and record the location and the arguments of the macros in the test case metadata. When the executor and the model run the test case, they will recognize these macros and execute the corresponding logic. Note that the logic can be configurable, e.g., when the user has set `executor_mode: P+P` (prime+probe), the `measurement_start` macro will correspond the Prime stage of the measurement, and `measurement_end` will correspond to the Probe stage.

See [Implementation Overview](#implementation-overview) for details on how macros are implemented in the executor and model.

## Implementation Overview

### Internal Representation of Macros

Revizor internally replaces all macros with a no-op placeholder of a fixed size (8 bytes for x86-64, 12 bytes for ARM64). This placeholder is used to maintain the original instruction flow while allowing the executor and model to recognize and handle macros dynamically. The macro location, type, and arguments are stored in the test case metadata, namely in the `SYMBOL TABLE` section of the [RCBF File Format](../ref/binary-formats.md), where `owner` is set to the actor ID of the actor that contains the macro, `offset` is the offset of the macro placeholder in the code section of the actor, `id` is the macro type (defined in [executor_km/include/macro_expansion.h](https://github.com/microsoft/side-channel-fuzzer/blob/main/src/x86/executor/include/macro_loader.h)), and `args` is a compressed representation of the macro arguments.

### Macros in Executor

Each actor's code section contains a dedicated memory region for macros, and the implementation is copied there during test case initialization. The executor copies the implementations of all macros into this section, and it replaces the macro placeholders with direct jumps to the corresponding implementations. The executor also inserts a return jump at the end of each macro implementation to return control flow back to the original instruction sequence.

For example, if we have a simple test case like this:

```asm
.macro.measurement_start:
... ; some code here
.macro.measurement_end:
.test_case_exit:
```

The executor with expand it as follows:

```asm
jump measurement_start_impl
lfence
.l1:
... ; some code here
jump measurement_end_impl
lfence
.l2:
.test_case_exit:

.macro_code_section:
measurement_start_impl:
... ; sequence of instructions that implements the macro
jump .l1  ; jump to the end of the macro section

measurement_end_impl:
... ; sequence of instructions that implements the macro
jump .l2  ; jump to the end of the macro section
```

Note that the executor also inserts LFENCE barriers after each macro jump. This is to ensure that the macro execution does not trigger straight-line speculation, which could interfere with the measurement process.


### Macros in Model

In the model, macros are implemented as dynamic callbacks. The model executes a hook function on every instruction execution, checking if the current instruction matches an entry in the symbol table. If a match is found, the model invokes the corresponding callback function to emulate the macro behavior.
