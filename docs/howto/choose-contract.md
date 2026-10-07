# How to Choose a Contract

This guide helps you select the appropriate [contract](../glossary.md#speculation-contract) for your fuzzing campaign. The contract determines which microarchitectural leaks Revizor will report as violations, making it a critical configuration choice that affects both what you find and how efficiently you find it.

!!! note "Prerequisites"
    Before choosing a contract, you should understand what contracts are and how they work. Read the [Contracts](../topics/contracts.md) topic guide if you need background on contract structure and purpose.


## Standard Fuzzing with CT-SEQ

Use CT-SEQ for most fuzzing campaigns. This contract assumes nothing about the target CPU except the presence of CPU caches, making it a zero-knowledge baseline for detecting unknown vulnerabilities. With CT-SEQ, Revizor reports any information leaks beyond the most trivial non-speculative cache accesses.

Configure CT-SEQ by setting the [observation clause](../glossary.md#observation-clause) to `ct` and the [execution clause](../glossary.md#execution-clause) to `seq`:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - seq
```

CT-SEQ provides the strictest security guarantees and will detect the widest range of vulnerabilities. Start with this contract unless you have specific reasons to use a different one.

## Continuing After Finding a Violation

When you find a violation with CT-SEQ and want to continue testing for additional vulnerabilities, you have two approaches.

The simpler and more efficient approach is to blocklist the instruction that triggered the violation. Use the [`instruction_blocklist`](../ref/config.md#instruction_blocklist) configuration option to exclude specific instructions from testing. For example, if a branch misprediction caused the violation, blocklist all conditional branch instructions:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - seq
instruction_blocklist:
  - jne
  - je
  # add other branch instructions
```

This approach lets you continue using CT-SEQ's fast and efficient detection while avoiding repeated reports of the same root cause.

Alternatively, you can incorporate the newly discovered speculation source into the contract by switching to a different execution clause. For violations caused by branch mispredictions, switch to the COND execution clause:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - cond
```

The CT-COND contract models speculative execution from branch mispredictions as expected behavior. Revizor will no longer report violations from this source, allowing you to search for other types of leaks in the same instruction set.

## Testing with Exceptions

If your fuzzing campaign includes code that may raise exceptions such as page faults or general protection faults, these exceptions will likely cause trivial violations under CT-SEQ. Modern CPUs implement out-of-order execution, which means instructions after a faulting instruction may begin executing before the CPU recognizes the exception. These subsequent instructions can leak information not predicted by CT-SEQ's strictly sequential model.

These violations typically represent known artifacts of out-of-order execution rather than genuine security issues. To suppress such trivial reports, use the CT-DEH contract instead. This contract models delayed exception handling, allowing instructions after a faulting instruction to execute transiently before the exception is handled:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - deh
```

CT-DEH remains strict about other speculation sources while accommodating the expected behavior around exceptions.

## Testing Cross-Domain Isolation

When testing isolation between security domains such as kernel versus user mode or host versus guest execution, use the Actor Non-Interference contract (CT-NI). This contract changes the security property being tested. Instead of only checking that inputs with identical [contract traces](../glossary.md#contract-trace) produce equivalent [hardware traces](../glossary.md#hardware-trace), CT-NI adds an additional requirement: the hardware traces observed by attacker actors must not depend on data from victim actors.

Configure CT-NI with the following observation clause:

```yaml
contract_observation_clause: ct-ni
```

You must also configure actors properly, designating which actors are observers (attackers) and which are victims. See [Actors](../topics/actors.md) for details on actor configuration.

## Investigating Known Vulnerabilities

When investigating variants of known vulnerabilities, use a contract that models the specific vulnerability class you are studying.

For Spectre V1 variant analysis, use the COND execution clause to model branch mispredictions as expected behavior:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - cond
```

This configuration lets you explore whether other instructions or gadget patterns can be exploited through branch misprediction without being distracted by the original Spectre V1 finding.

For other vulnerability classes, choose the execution clause that models the corresponding speculation mechanism. See the [Configuration Reference](../ref/config.md#contract_execution_clause) for a list of available execution clauses and their intended use cases.

## What's Next?

- Topic: [Contracts](../topics/contracts.md) - Understanding contract structure and behavior
- How-to: [Design a Fuzzing Campaign](design-campaign.md) - Complete campaign planning including contract selection
- Reference: [Configuration Options](../ref/config.md) - Complete list of contract and configuration parameters
- Glossary: [Contract](../glossary.md#speculation-contract), [Observation Clause](../glossary.md#observation-clause), [Execution Clause](../glossary.md#execution-clause)
