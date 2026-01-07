# Revizor

![GitHub](https://img.shields.io/github/license/microsoft/sca-fuzzer)
![PyPI](https://img.shields.io/pypi/v/revizor-fuzzer)
![GitHub all releases](https://img.shields.io/github/downloads/microsoft/sca-fuzzer/total)
![GitHub contributors](https://img.shields.io/github/contributors/microsoft/sca-fuzzer)
<!-- ![PyPI - Downloads](https://img.shields.io/pypi/dm/revizor-fuzzer) -->

Revizor is a security-oriented fuzzer for detecting information leaks in CPUs, such as [Spectre and Meltdown](https://meltdownattack.com/).
It tests CPUs against [Leakage Contracts](https://arxiv.org/abs/2006.03841) and searches for unexpected leaks.

<!-- For more details, see our [Paper](https://dl.acm.org/doi/10.1145/3503222.3507729) (open access [here](https://arxiv.org/abs/2105.06872)), and the follow-up papers ([1](https://arxiv.org/pdf/2301.07642.pdf), [2](https://www.usenix.org/conference/usenixsecurity23/presentation/hofmann)). -->

## Getting Started and Documentation

You can find a quick start guide at [Quick Start](https://microsoft.github.io/sca-fuzzer/quick-start/).

For information on how to use Revizor, see [User Documentation](https://microsoft.github.io/sca-fuzzer/user/).

For information on how to contribute to Revizor, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Need Help with Revizor?

If you find a bug in Revizor, don't hesitate to [open an issue](https://github.com/microsoft/sca-fuzzer/issues).

If something is confusing or you need help in using Revizor, we have a [discussion page](https://github.com/microsoft/sca-fuzzer/discussions).

## Citing Revizor

To cite this project, you can use any of the following references:

1. Original paper that introduced the concept of Model-based Relation Testing as well as the Revizor tool:

    Oleksii Oleksenko, Christof Fetzer, Boris Köpf, Mark Silberstein. "[Revizor: Testing Black-box CPUs against Speculation Contracts](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)" in Proceedings of the 27th ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS), 2022.

2. Theoretical foundations of leakage contract:

    Marco Guarnieri, Boris Köpf, Jan Reineke, and Pepe Vila. "[Hardware-software contracts for secure speculation](https://www.microsoft.com/en-us/research/publication/hardware-software-contracts-for-secure-speculation/)" in Proceedings of the 2021 IEEE Symposium on Security and Privacy (SP), 2021.

3. Accessible summary of the two papers above, in a journal format:

    Oleksii Oleksenko, Christof Fetzer, Boris Köpf, Mark Silberstein. "Revizor: Testing Black-box CPUs against Speculation Contracts". In IEEE Micro, 2023.

4. Paper that introduced speculation filtering, observation filtering, and contract-based input generation:

    Oleksii Oleksenko, Marco Guarnieri, Boris Köpf, and Mark Silberstein. "[Hide and Seek with Spectres: Efficient discovery of speculative information leaks with random testing](https://www.microsoft.com/en-us/research/publication/hide-and-seek-with-spectres-efficient-discovery-of-speculative-information-leaks-with-random-testing/)" in Proceedings of the 2023 IEEE Symposium on Security and Privacy (SP), 2022.

5. Paper that introduced exception-based testing (i.e., focus on Meltdown, Foreshadow) into Revizor:

    Jana Hofmann, Emanuele Vannacci, Cédric Fournet, Boris Köpf, and Oleksii Oleksenko. "[Speculation at Fault: Modeling and Testing Microarchitectural Leakage of CPU Exceptions.](https://www.usenix.org/conference/usenixsecurity23/presentation/hofmann)" in Proceedings of 32nd USENIX Security Symposium (USENIX Security), 2023.

6. Paper that introduced testing of cross-VM and user-kernel leaks in Revizor, as well as presented TSA attacks on AMD CPUs:

    Oleksii Oleksenko, Flavien Solt, Cédric Fournet, Jana Hofmann, Boris Köpf, and Stavros Volos. "[Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://www.microsoft.com/en-us/research/wp-content/uploads/2025/07/Enter-Exit-SP26.pdf)" (to be published) in Proceedings of the 2026 IEEE Symposium on Security and Privacy (SP), 2026.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
