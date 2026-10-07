# ISA Constraints

This document describes how Revizor decides which parts of an ISA specification may be used
when generating test-case programs: which instructions, instruction categories, registers, and
operand types are filtered out, who owns each filtering rule, and how the rules are combined.

## Overview

The pool of instructions available to the program generator is the ISA descriptor file
(e.g., `base.json`) reduced by two kinds of filters:

1. **User intent**, expressed in the config (e.g., `instruction_categories`)
2. **Built-in constraints**, expressed in code as `InstructionPoolConstraints` objects:
    restrictions that do not depend on user intent, such as instructions
    that a model backend cannot emulate faithfully.

The two are deliberately independent: setting `instruction_blocklist` or `register_blocklist`
in a config does not disable the built-in constraints. The only way to override a built-in
constraint is an explicit allowlist entry, which triggers a warning.

## Data flow

`rvzr/factory.py:get_effective_constraints` is the single place where config options are
converted into constraints. It looks up the per-arch capability tables by the selected
architecture and model backend, merges them with the contract table and the policy constraints,
nd folds the user *register* lists into the result:
`blocked_registers = (merged ∪ register_blocklist) − register_allowlist`.

The user *instruction* lists do not fold into the merged result: `instruction_allowlist`
overrides category filtering, which is inherently per-spec, so both instruction lists are
applied inside `rvzr/isa_spec.py:InstructionSet` instead.

## See also

- [ISA Specification](architecture/isa.md) — how the ISA descriptor file is loaded
- [Test Case Code Generation](architecture/code.md) — how the instruction pool is used
- [Configuration File Reference](../ref/config.md) — the user-facing filtering options
