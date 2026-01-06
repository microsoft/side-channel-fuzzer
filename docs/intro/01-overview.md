# Revizor at a Glance

## What is Revizor?

Revizor is a security-oriented fuzzer that detects microarchitectural information leaks in CPUs—the vulnerabilities behind attacks like Spectre and Meltdown. It tests processors "blindly," requiring no prior knowledge of specific flaws or hardware internals. Instead, it compares actual CPU behaviour against a [*leakage contract*](../glossary.md#speculation-contract-aka-leakage-contract): a specification defining known sources of information leakage. Any discrepancy reveals a potential vulnerability.

## What Problems Does Revizor Solve?

Modern CPUs achieve their speed through speculative execution, out-of-order processing, complex caching, and other microarchitectural optimizations. These optimizations create side channels—timing variations, cache-state changes, buffer contentions—that can leak sensitive data. Such leaks are notoriously difficult to catch: they cause no crashes, depend on precise timing, and emerge only under specific conditions. Revizor automates the detection of these elusive side-channel leaks.

Specifically, Revizor addresses several key challenges:

* **Automated discovery**: Finding side-channel attacks manually demands deep (often undocumented) microarchitectural knowledge and extensive trial-and-error. Revizor automates this process, systematically exploring the CPU's behaviour by probing the microarchitecture with lots of automatically generated test cases.
* **Variant analysis**: Side-channel vulnerabilities spawn many variants. Revizor can search for new attack vectors that might bypass existing patches.
* **Validation of mitigations**: Vendor patches meant to close side channels have sometimes proven incomplete. Revizor verifies whether fixes actually eliminate the leakage.

## Quick Example: Detecting Spectre V1

To illustrate how Revizor works, consider a simple fuzzing campaign that will lead to a detection of a known vulnerability in most modern CPUs, namely Spectre V1.

!!! info "Prerequisites"
    Before running this example, ensure you have Revizor installed and set up correctly. Follow the [Installation Guide](02-install.md) if you haven't done so already.

We will use a configuration file in `demo/detect-v1.yaml`. This config file tells Revizor to test a small subset of x86-64 ISA (arithmetic instructions + conditional branches) against a contract that states that the CPU should not speculate and should only leak information about loads, stores, and the program counter. As most modern CPUs implement branch prediction, we expect to see a violation of this contract.

Run the fuzzer with the following command:

```bash
$ rvzr fuzz -s base.json -n 1000 -i 100 -c demo/detect-v1.yaml -w ./
```

After a short while, you should see output similar to this:

```
INFO: [prog_gen] Setting program_generator_seed to random value: 562112

INFO: [fuzzer] Starting at 14:00:51
13    ( 2%)| Stats: Cls:100/100,In:200,R:9,SF:5,OF:6,Fst:2...

================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:71  | ID:171|
-----------------------------------------------------------------------------------
^................^..^.....^.....................^.....^......... | 599    | 0     |
^...................^.....^..................................... | 28     | 23    |
^................^..^.....^.......^...^......................... | 0      | 604   |


================================ Statistics ===================================

Test Cases: 14
Inputs per test case: 200.0
Violations: 1
Effectiveness:
  Total Cls: 100.0
  Effective Cls: 100.0
Discarded Test Cases:
  Speculation Filter: 5
  Observation Filter: 6
  Fast Path: 2
  Max Nesting Check: 0
  Tainting Check: 0
  Early Priming Check: 0
  Large Sample Check: 0
  Priming Check: 0

Duration: 52.1
Finished at 14:01:43
```

This message indicates that Revizor found a [violation](../glossary.md#violation) of the specified
contract, and the tool will store the corresponding
[violation artifact](../glossary.md#violation-artifact-aka-contract-counterexample) in
`./violation-<timestamp>/`.

What happened here is that Revizor generated a series of random
[test programs](../glossary.md#test-case-program), executed them on the target CPU and the
reference model that implement the contract, collected the side-channel observations on both sides,
and compared them. In this case, one of the generated test programs produced two different
[hardware traces](../glossary.md#hardware-trace-htrace) for two different inputs while the model
(contract) produced the same trace for both inputs. This discrepancy indicates that the CPU leaked
information through microarchitectural side channels in a way that violates the specified contract.

The corresponding program and the [inputs](../glossary.md#test-case-data-aka-test-case-input) are
stored in the violation artifact (`./violation-<timestamp>/`), and it will contain an assembly file
`program.asm` that surfaced a violation, a sequence of inputs `input_*.bin` to this program, and
some details about the violation in `report.txt`.

If we inspect the assembly code in `program.asm` and do an analysis of the violation, we will most likely find that it is a gadget that implements a typical Spectre V1 pattern: a conditional branch and a speculative memory access that leaks data through the cache. (This is a most likely outcome because the pattern is statistically very common for the given configuration). For example, the program may look like this (simplified for illustration):

```assembly
.section .data.main
...
jnp .bb_0.1  // conditional branch
jmp .exit_0
.bb_0.1:
    ...
    or byte ptr [r14 + rcx], al  // data-dependent memory access
    ...
.exit_0:
.test_case_exit:
```

!!! info "On violation analysis"
    This example was intentionally chosen to have a straightforward output that directly corresponds to a known vulnerability pattern. In practice, analyzing violations can be more complex, especially for novel or less understood leaks. We won't go into the details of the analysis here as it is a relatively complex topic; refer to the [this guide](../howto/root-cause-a-violation.md) if you want to dive into the details.

The power of this approach is that Revizor doesn't need to know the specific vulnerability it's looking for. It simply tests whether the CPU matches the expected security specification. When it finds a discrepancy, that's a potential vulnerability worth investigating.

## What's Next?

Now that you understand what Revizor is and what it does, here are your next steps:

* **Dive Deeper into Concepts**: For a more detailed explanation of the information flow analysis used in Revizor, the concepts of leakage contracts, and other related topics, see the [Core Concepts Guide](03-primer.md).
* **Follow a Tutorial**: Our [step-by-step tutorial series](./04-tutorials.md) guides you through detecting your first vulnerability, understanding the results, and designing effective fuzzing campaigns.
* **Explore the Glossary**: Familiarize yourself with key terms and definitions in the [Glossary](../glossary.md) to better understand Revizor's terminology (we have quite a few unique terms!).
* **Get Help**: If you run into issues or have questions, visit our [FAQ](../faq/general.md) for common questions, or [ask a question](../howto/ask-a-question.md) to reach out to the community.
