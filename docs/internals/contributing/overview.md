# Guide to Contributing

This document provides an overview of how to contribute to the Revizor project.

## What can I contribute?

Revizor is an open-source project, and we welcome contributions of all kinds. You don't have to be an expert in hardware security or fuzzing to contribute! Even small contributions are valuable.

Here are some ways you can help:

* :fontawesome-solid-bug: Report Issues: The easiest way to contribute is by reporting issues you encounter while using Revizor. Try following the introductory [guides and tutorials](../../intro/start-here.md), and if you find any issues, bugs, or unclear documentation, please report them on our [GitHub Issues page](https://github.com/microsoft/side-channel-fuzzer/issues).
* :fontawesome-solid-pencil: Improve Documentation: You can also contribute by improving the documentation. If you find any gaps, outdated information -- even typos -- feel free to submit a pull request with your improvements.
* :fontawesome-solid-code: Code Contributions: If you're interested in coding, you can contribute new features, fix bugs, or enhance existing functionality. Check out the [issue tracker](https://github.com/microsoft/side-channel-fuzzer/issues) for open issues and feature requests.
* :fontawesome-solid-lightbulb: New Features: Finally, if you have expertise in hardware security, fuzzing, or related areas, consider contributing new features and enhancements to Revizor (see [ideas for contributions](#ideas-for-contributions) if you need inspiration).

## Reporting Bugs and Issues

To report a bug or an issue, please use the [GitHub Issues page](https://github.com/microsoft/side-channel-fuzzer/issues).

If you're reporting a simple bug, it is sufficient to provide a small description of the problem and the environment in which it occurred (Revizor version, target architecture, OS, etc.).

For more complex issues, especially those related to the fuzzing process, also include the configuration file you've used and the command-line arguments.

The recommended report template is as follows:

```
## Description
A clear and concise description of what the bug is.

## To Reproduce
1. Go to '...'
2. Run '...'
3. See error

## Expected behavior
A clear and concise description of what you expected to happen.

**Environment**
- Revizor version:
- Architecture:
- OS:
...

## Additional context
Add any other context about the problem here.

## Attachments
- Configuration file used:
- Command-line arguments:
- Logs or error messages:
```

## Submitting Patches

To submit a patch, be it to the code or to the documentation, use the following procedure:

* [Fork Revizor on github](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)
* Create a topic branch (`git checkout -b my_branch`)
* Make and commit your changes in the new branch
* Make sure all tests pass (`./tests/runtests.sh <target_ISA>`) and that the code is formatted accordingly to the [Code Style](code-style.md) guidelines.
* Push to your branch (`git push origin my_branch`)
* [Initiate a pull request on github](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request)
* Wait for the PR to get reviewed and merged

#### Contributor License Agreement and Code of Conduct

Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [https://cla.opensource.microsoft.com](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## <a name="ideas-for-contributions"></a> Ideas for Contributions

If you're looking for ideas and inspiration on how you can meaningfully extend and improve Revizor, here are some suggestions:

---

#### Add Support for New Instructions

There are quite many specialized instructions that Revizor does not yet fully support. Implementing support for these instructions can help improve the coverage and effectiveness of the fuzzer. As a bonus, you might discover new type of information leaks in the process.

These include, but are not limited to:

* Floating-point instructions (either x87 or SSE/AVX)
* Segment-based memory accesses or instructions that manipulate segment registers
* Complex control-flow instructions (e.g., `call`, `ret`, indirect jumps)
* MMX instructions

---

#### Make Generators Smarter

Both code and data generators can be improved in various ways to produce more effective test cases. The bar is fairly low here, as current generators are fully random.

Ideas include:

* Bias generators to produce values that are more likely to trigger edge cases (e.g., boundary values, special bit patterns)
* Implement ability to control the frequency of certain instruction types in generated programs
* Implement mutation-based generation strategies that modify existing test cases to explore new behaviors

If you decide to work on any of these or have your own ideas, please discuss them with us first by reaching out on [GitHub Discussions](https://github.com/microsoft/side-channel-fuzzer/discussions) or opening a draft pull request. This way we can ensure that your efforts align with the project's goals and avoid duplication of work.

---

#### Improve Reporting Tools

The current logging and debugging tools in Revizor are relatively basic. Enhancing these utilities for better readability and usability can significantly aid users in understanding fuzzing results and diagnosing issues.

Ideas include:

* Refactor the logging module to output a live dashboard, similar to what is seen in other fuzzers like AFL or libFuzzer
* Improve the debugging output to improve readability when debugging models

---

#### Implement New Measurement Modes

Revizor currently collects side-channel observations primarily through cache measurements or by recording the execution time of test programs. Implementing additional measurement modes can help uncover new types of leaks and improve the fuzzer's effectiveness.

New measurement modes could include:

* Instruction cache measurements (e.g., using I-cache side channels)
* Contention-based measurements (e.g., measuring resource contention on the memory bus)
* Performance counter-based measurements (i.e., reading directly from CPU performance counters)

Beyond that -- if you're brave enough -- you could attempt implementing concurrent measurement modes, for example, by running each actor in a test case on a different core or SMT thread. This is a complex task that requires significant changes to executor, and might require new techniques for dealing with non-determinism and imprecise synchronization. But if successful, it could open up new avenues for discovering cross-core or cross-thread leaks. You might even make a paper out of it.

---

#### Implement Coverage-Guided Fuzzing

Another interesting avenue for exploration is implementing proxy-based coverage metrics. Currently, Revizor runs in a fully random mode, without any feedback being collected in the process of fuzzing. Implementing coverage-guided fuzzing techniques could significantly improve the efficiency of the fuzzer.

Ideas include:

* Proxy-based coverage metrics, where an emulator or a simulator is used as a proxy for the CPU coverage. That is, the fuzzer would run test cases on an emulator, collect the software coverage information (which edges of the emulator code were executed), and use that to guide the generation of new test cases.
* Specification-based coverage metrics, where a formal specification of the instructions (e.g., ARM Architecture Specification Language) is used to determine edge cases in the execution of instructions. The fuzzer would then aim to cover all possible behaviors defined in the specification.


