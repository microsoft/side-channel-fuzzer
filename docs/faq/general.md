# General FAQ

## Overview

#### What is Revizor? {#what-is-revizor}

:   Revizor is a security-oriented fuzzer designed to detect microarchitectural information leaks in CPUs. It automatically generates random test programs, executes them on real hardware, and compares the observed behavior against a formal model to identify unexpected information leakage through side channels like those exploited by Spectre and Meltdown attacks.

#### Who is Revizor for? {#who-uses-revizor}

:   Revizor is primarily designed for CPU security researchers and hardware vendors interested in identifying and mitigating microarchitectural vulnerabilities. It may also be useful for system developers and security professionals who want to assess the security of the hardware platforms they work with.

#### How does Revizor differ from other hardware fuzzers (e.g., SiliFuzz)? {#how-does-revizor-differ-from-other-hardware-fuzzers}

:   Most of the existing hardware fuzzers focus on finding functional bugs, such as incorrect instruction execution or crashes. Revizor, on the other hand, is specifically designed to find security vulnerabilities related to microarchitectural side channels. It uses a model-based approach to define what information is allowed to leak and tests whether the CPU adheres to these specifications.

:   See [Revizor at a Glance](../intro/01-overview.md) for a more detailed introduction.

#### How is Revizor different from constant-time testing tools (e.g., Microwalk)? {#how-does-revizor-differ-from-ct-testing-tools}

:   Constant-time testing tools like Microwalk focus on verifying that software implementations do not leak sensitive information through timing variations. They analyze the execution of programs to ensure that their timing behavior is independent of secret data.

:   Revizor, in contrast, tests the CPU hardware itself for microarchitectural information leaks. It tests whether the CPU behaves as expected, regardless of the software running on it.

#### What CPUs does Revizor support? {#supported-cpus}

:   Revizor currently supports testing on x86-64 CPUs from Intel and AMD, as well as ARM CPUs.

#### Does Revizor detect only those leaks that are described in the contract? {#leaks-described-in-contract}

:   No! It is a common misconception that Revizor can only find leaks that are explicitly described in the contract. In reality, it is the opposite: The contract defines what the Revizor should *not* report as a leak, which allows the tool to filter out the known types of leakage and focus on finding unexpected leaks that violate the contract. This is how Revizor is able to discover new vulnerabilities even in completely black-box CPUs.

---

## Installing Revizor

#### What operating system is required to run Revizor? {#required-os}

:   You will need Linux.

#### Do I need a specific Linux distribution/version? {#specific-linux-distro}

:    No, Revizor should work on any reasonably recent Linux. If you encounter issues, that's most likely a bug that we would like to hear about. Please report any problems on our [GitHub Issues page](https://github.com/microsoft/side-channel-fuzzer/issues).

#### Does Revizor require root or administrator privileges? {#requires-root}

:   Yes. Revizor's executor is implemented as a kernel module that requires loading into the kernel and accessing hardware performance counters. Both operations require root privileges. Additionally, some system configuration steps recommended for optimal performance (like disabling hyperthreading) require administrative access.

#### Can I run Revizor in a virtual machines? {#run-on-vms}

:   Unfortunately, not. Revizor requires direct access to the CPU's PMU to accurately measure side-channel leakage. Running Revizor inside a virtual machine would introduce additional layers of abstraction and interference that could distort the measurements and lead to inaccurate results. You need to run Revizor on a bare-metal installation of Linux.

---

## Running Revizor

#### Can Revizor affect system stability? {#safety}

:   Although extremely unlikely, Revizor could potentially affect the host operating system. Revizor executes randomly-generated code in kernel space, which means that a misconfiguration or bug can crash the system and potentially lead to data loss. However, it does not intentionally perform any operations that would damage hardware.

:   You should never run Revizor on production machines or systems containing important data without backups. Always use a dedicated testing machine.

#### How long does it take to find a vulnerability? {#time-to-find}

:   This varies significantly, based on the complexity of the experiment. Typical numbers range from minutes to weeks.

#### Can Revizor test my own assembly programs or does it only generate random ones? {#test-custom-programs}

:   Yes, Revizor can test custom assembly programs using the `-t` flag. You can provide your own test case program in assembly format, and Revizor will execute it with randomly-generated inputs to check for contract violations. This is useful when you want to verify specific code patterns or investigate potential vulnerabilities in particular instruction sequences.

:   See the [CLI Reference](../ref/cli.md) for details on the `-t` option.

#### How much computational resources does a typical fuzzing campaign require? {#resource-requirements}

:   Resource requirements vary significantly based on the fuzzing configuration. A typical campaign runs continuously for hours to weeks. The primary variables affecting performance are the number of inputs per test case, sample sizes for hardware measurements, and the complexity of the ISA subset being tested. Larger sample sizes increase accuracy but reduce throughput. Most campaigns run on standard server or workstation hardware without specialized requirements beyond the supported CPU architecture.

:   See [How to Design a Fuzzing Campaign](../howto/design-campaign.md) for guidance on balancing performance and detection effectiveness.

---

## Violations

#### Are false positives common? How does Revizor handle them? {#false-positives}

:   No, unless it is misconfigured. Revizor uses a multi-stage filtering pipeline to eliminate false positives caused by noise and non-deterministic hardware behavior. This removes the vast majority of spurious violations. However, if Revizor is misconfigured (e.g., insufficient sample sizes), false positives can still occur due to noise in hardware measurements. These are relatively easy to identify as they tend to be unstable and non-reproducible.

:   See [How to Interpret Violation Results](../howto/interpret-results.md#evaluating-violation-quality) for guidance on evaluating violation quality and handling false positives.

#### Can Revizor automatically generate exploits or proof-of-concept code? {#generate-exploits}

:   No. Revizor detects violations of the leakage contract by identifying test cases where hardware behavior differs from the contract's predictions. While it provides the test program and inputs that trigger the violation, it does not automatically generate working exploits. The violation artifacts serve as evidence of unexpected leakage and a starting point for manual security analysis. You can use the minimization feature to simplify the test case, making it easier to understand and potentially develop into a proof-of-concept.

:   See [How to Minimize Test Cases](../howto/minimize.md) for details on simplifying violations.

#### How do I know if a detected violation is actually exploitable? {#exploitability}

:   Determining exploitability requires manual analysis of the violation. Start by reproducing the violation to confirm it's stable, then use the minimization feature to simplify the test case. Next, analyze the minimized program to understand what information is leaking and through which side channel. Root-cause analysis involves examining the assembly code, understanding the data dependencies, and determining whether an attacker could control the leaked information to extract sensitive data. Not all violations are practically exploitable, but all indicate deviation from the specified security contract.

:   See [How to Root-Cause a Violation](../howto/root-cause-a-violation.md) for systematic analysis techniques.

#### Is Revizor deterministic? Can I reproduce results? {#reproducibility}

:   Contract traces are fully deterministic—the same program with the same inputs always produces identical contract traces. Hardware traces, however, contain inherent non-determinism due to timing variations, cache state, and other microarchitectural effects. Revizor handles this through statistical analysis of multiple samples. Violations are reproducible when the same test program and inputs consistently show the same distributional differences in hardware traces. The violation artifact includes all necessary files (program, inputs, configuration) to reproduce detected violations, and Revizor provides a dedicated reproduce mode for verification.

:   See [Execution Modes](../ref/modes.md) for details on the reproduce mode.

---

## Development and Contribution

#### Is Revizor actively maintained? {#maintenance-status}

:   Yes. Revizor is actively maintained and continues to receive updates, bug fixes, and new features. The project has an active GitHub repository with recent commits and ongoing development.

#### Can I contribute to Revizor? {#contributing}

:   Yes, we welcome contributions from the community! You can contribute by reporting issues, suggesting new features, improving documentation, or submitting code changes through pull requests. Please refer to our [Contribution Guidelines](../internals/index.md) for instructions on how to get started.

