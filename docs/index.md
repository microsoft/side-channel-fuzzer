---
title: "Revizor"
hide:
  - navigation
  - toc
---

<style>
.md-typeset h1,
.md-content__button {
    display: none;
}

.hero-section {
    text-align: center;
    max-width: 800px;
    margin: 0 auto;
}

.hero-section img {
    max-width: 320px;
    height: auto;
}

.hero-section p {
    margin: 0;
}

.hero-section .tagline {
    color: var(--md-default-fg-color--light);
    font-size: 1.5rem;
    font-weight: 300;
    margin-top: 1.0rem;
    margin-bottom: 5rem;
}

.grid.cards > ul > li {
    text-align: center;
}

.grid.cards > ul > li > p > strong{
    font-size: 1.1rem;
}

.grid.cards > ul > li > p.text {
    text-align: justify;
    margin: 1rem;
}

.grid.cards > ul > li .md-button {
    margin: 0.25rem;
}

h2 {
    text-align: center;
    margin-top: 3rem;
    margin-bottom: 1rem;
}

h2 > strong {
    font-weight: 700;
    font-size: 1.8rem;
}


</style>

<div class="hero-section" markdown>

<img src="./assets/logo.svg#only-light" alt="Revizor Logo" align="center" width="320px" />
<img src="./assets/logo-light.svg#only-dark" alt="Revizor Logo" align="center" width="320px" />

<p class="tagline">Hardware fuzzing for the age of speculation</p>

</div>

<div class="grid cards" markdown>

-   __:fontawesome-solid-arrow-right: Get Started__

    ---

    <p class="text">
    Welcome to the Revizor documentation! Whether you're a new user looking to get started or a developer interested in contributing, you'll find all the information you need here.
    </p>

    [Start Here](intro/start-here.md){ .md-button .md-button--primary }
    [Learn Revizor](intro/01-overview.md){ .md-button }
    [Ask a Question](howto/ask-a-question.md){ .md-button }
    [Cite Revizor](ref/papers.md){ .md-button }


- __:fontawesome-solid-code: Source Code__

    ---

    <p class="text">
    The Revizor project lives on GitHub. Explore the source code, report issues, and contribute to the project.
    </br></br></br>
    </p>


    [GitHub](https://github.com/microsoft/side-channel-fuzzer){ .md-button }
    [Contributing](internals/contributing/overview.md){ .md-button }
    [Bug Reports](https://github.com/microsoft/side-channel-fuzzer/issues){ .md-button }
    [Explore Docs](structure.md){ .md-button }


- __:fontawesome-solid-comments: Join the Community__

    ---

    <p class="text">
    Join the Revizor community to get help, discuss ideas, suggest features, and share your experiences.
    </br></br></br>
    </p>

    [Zulip Community](https://rvzr.zulipchat.com/){ .md-button }
    [GitHub Discussions](https://github.com/microsoft/side-channel-fuzzer/discussions){ .md-button }

</div>

---

## __:fontawesome-solid-bug: Trophies__{ .trophies-header }

#### Transient Scheduler Attack - L1 Cache (TSA-L1)

=== "Description"
    A speculative leak affecting AMD Family 19h processors where false completions in load instructions can leak data from the L1 data cache across security boundaries. The attack exploits the linear address-based microtag system used for L1 cache lookups - when a load finds a matching microtag entry but the L1 doesn't contain valid data, invalid data from the matching microtag entry is used in a false completion. This leak enables information disclosure between kernel/userspace, hypervisor/guest, across different applications or VMs, and from SEV-SNP VMs to the host.
=== "CVE"
    [CVE-2024-36357](https://nvd.nist.gov/vuln/detail/CVE-2024-36357)
=== "Links"
    * More details in: [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://aka.ms/enter-exit-leak)
    * AMD Security Advisory: [Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)


#### Transient Scheduler Attack - Store Queue (TSA-SQ)

=== "Description"
    A speculative leak affecting AMD Family 19h processors where false completions in Store-To-Load Forwarding operations can leak data from previous store instructions. When a load matches an older store's address but the store data isn't yet available, a false completion occurs using invalid data from a previously executed store that occupied the same store queue entry. This effect enables information leakage from the OS kernel to user applications, hypervisor to guest, and to a lesser extent, between application.
=== "CVE"
    [CVE-2024-36350](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-36350)
=== "Links"
    * More details in: [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://aka.ms/enter-exit-leak)
    * AMD Security Advisory: [Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)

#### Control Register Speculation

=== "Description"
    A speculative leak affecting AMD processors where user processes can speculatively infer control register values even when User Mode Instruction Prevention (UMIP) is enabled. This bypasses intended security boundaries by allowing unprivileged code to access system-level configuration information through speculative channels.
=== "CVE"
    [CVE-2024-36348](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36348)
=== "Links"
    * More details in: [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://aka.ms/enter-exit-leak)
    * AMD Security Advisory: [Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)

#### TSC_AUX Speculation

=== "Description"
    A speculative leak affecting AMD processors affecting AMD processors that permits user processes to infer the Time Stamp Counter Auxiliary (TSC_AUX) register value even when direct reads are disabled.
=== "CVE"
    [CVE-2024-36349](https://nvd.nist.gov/vuln/detail/CVE-2024-36349)
=== "Links"
    * More details in: [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://aka.ms/enter-exit-leak)
    * AMD Security Advisory: [Advisory](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)


#### Divider State Sampling (DSS)

=== "Description"
    A speculative leak where division-by-zero operations can transiently return values that depend on previous division operations. The leaked state persists across privilege boundaries. The discovery of the leak triggered a patch to the Linux kernel as well as other operating systems.
=== "CVE"
    [CVE-2023-20588](https://nvd.nist.gov/vuln/detail/CVE-2023-20588)
=== "Links"
    More details in: [Speculation at Fault](https://www.usenix.org/system/files/usenixsecurity23-hofmann.pdf)

#### String Comparison Overrun (SCO)

=== "Description"
    Revizor discovered that string operations on Intel and AMD CPUs (in particular, string comparison and string scan) can speculatively bypass the bounds of their target strings, which permits the attacker to leak data from out-of-bounds memory locations.
=== "Links"
    More details in: [Hide & Seek with Spectres](https://www.microsoft.com/en-us/research/publication/hide-and-seek-with-spectres-efficient-discovery-of-speculative-information-leaks-with-random-testing/)

#### Zero Dividend Injection (ZDI)

=== "Description"
    64-bit division operations on Intel CPUs can speculative ignore the upper bits of the divisor, thus producing an incorrect computational result. This speculation can potentially impact the security of cryptographic algorithms that use division to implement modulo operations.
=== "Links"
    More details in: [Hide & Seek with Spectres](https://www.microsoft.com/en-us/research/publication/hide-and-seek-with-spectres-efficient-discovery-of-speculative-information-leaks-with-random-testing/)

#### Read-Modify-Write Speculation

=== "Description"
    A new variant of Microarchitectural Data Sampling (MDS) where a store operation to read-only memory triggers speculative behavior. When a read-modify-write instruction (like XADD) attempts to access read-only memory, it speculatively returns stale data from internal CPU buffers, even though the read itself would be permitted.
=== "Links"
    More details in: [Speculation at Fault](https://www.usenix.org/system/files/usenixsecurity23-hofmann.pdf)

#### Non-canonical Store Forwarding

=== "Description"
    A speculative leak where stores to non-canonical addresses can be forwarded to subsequent loads from the canonical versions of those addresses. This means that even though a store operation fails due to an invalid address format, its data can still be transiently accessed by later instructions using a related valid address.
=== "Links"
    More details in: [Speculation at Fault](https://www.usenix.org/system/files/usenixsecurity23-hofmann.pdf)

#### Variable-latency Spectre

=== "Description"
    A variant of Spectre vulnerability where the leakage is caused by the race condition that appears when a speculative memory access is data-dependent on a variable-latency instruction. This race condition can expose the operands of the variable-latency instruction.
=== "Links"
    More details in [the Revizor paper](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)

#### Store-based Spectre V1

=== "Description"
    Several defense proposals (e.g., STT, KLEESpectre) assumed that stores do not modify the cache state until they retire. We used Revizor to validate this assumption, and discovered that is not true on recent Intel CPUs (e.g., CoffeeLake).
=== "Links"
    More details in [the Revizor paper](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)

#### Speculative Store with Forwarding

=== "Description"
    Revizor discovered that two consecutive loads from the same address can speculatively return two different values if one of them receives a forwarded value from a store while the other load experiences a speculative store bypass. This combination exposes more information to the attacker compared to the original store bypass.
=== "Links"
    More details in [the appendix to the Revizor paper](https://www.microsoft.com/en-us/research/publication/revizor-testing-black-box-cpus-against-speculation-contracts/)

<!--
### Reproduced Vulnerabilities

- [Spectre V1 (Bounds Check Bypass, BCB)](https://spectreattack.com/)
- [Spectre V4 (Speculative Store Bypass, SSBP)](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/speculative-store-bypass.html)
- [Meltdown (SMAP variant)](https://meltdownattack.com/)
- [Foreshadow (L1TF)](https://foreshadowattack.eu/)
- [Microarchitectural Data Sampling (MDS)](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/microarchitectural-data-sampling.html)
- [Load Value Injection (LVI), including LVI-Null](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/load-value-injection.html)
 -->
