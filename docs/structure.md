# Revizor Documentation

Everything you need to know about using, understanding, and contributing to Revizor.

## First Steps

Are you new to Revizor? Start here:

* [Revizor at a Glance](intro/01-overview.md): Understand what Revizor is, what problems it solves, and see a quick example of violation detection.
* [Installation Guide](intro/02-install.md): Get Revizor installed on your system and verify your setup.
* [Your First Fuzzing Campaign](intro/tutorials/01-first-fuzz.md): Follow a hands-on tutorial that walks you through running your first test, detecting a violation, and understanding the results.
* [Core Concepts](intro/03-primer.md): Learn about contracts, traces, speculation, and other fundamental concepts needed to use Revizor effectively.
* [Glossary](glossary.md): A quick reference for key terms used throughout the documentation.

---

## Getting Help

Stuck? Need clarification? Here's where to get help.

* [FAQ](faq/general.md) - What is Revizor? How does it work? What's a contract?
* [GitHub Discussions](https://github.com/microsoft/side-channel-fuzzer/discussions) - Ask questions, share experiences, discuss ideas
* [GitHub Issues](https://github.com/microsoft/side-channel-fuzzer/issues) - Report bugs or request features
* [Contributing Guide](https://github.com/microsoft/side-channel-fuzzer/blob/main/CONTRIBUTING.md) - Help improve Revizor
* [Zulip Chat](https://rvzr.zulipchat.com/) - Real-time community support

---

## How the Documentation is Organized

Revizor's documentation is organized into five distinct categories based on your needs:

### Learning-Oriented: Tutorials

Tutorials take you by the hand through a series of steps to complete a project. They are designed for newcomers who want to get started with Revizor. Start here if you're learning.

* [Main Tutorial Series](intro/04-tutorials.md): Follow a series of hands-on tutorials that walk you through running your first tests, detecting violations, and rump up all the way to root-cause analysis and design of custom campaigns.
* [How TSA-SQ Was Detected](intro/tutorials/tsa-sq.md): A practical case study showing how Revizor was used to discover the TSA-SQ vulnerability. For those interested in how Revizor is used in the real world.

---

### Task-Oriented: How-To Guides

How-to guides are recipes that guide you through steps to solve specific problems. They assume you have basic knowledge and want to accomplish something particular.

* [How to Choose a Contract](howto/choose-contract.md) - Select appropriate reference model
* [How to Design a Fuzzing Campaign](howto/design-campaign.md) - Plan effective testing strategies
* [How to Interpret Results](howto/interpret-results.md) - Understand what the outputs mean
* [How to Minimize Violations](howto/minimize.md) - Reduce test cases to essentials
* [How to Root-Cause a Violation](howto/root-cause-a-violation.md) - Analyze and understand detected leaks
* [How to Use Macros](howto/use-macros.md) - Leverage macros for customizing test cases
* [How to Use Templates](howto/use-templates.md) - Create structured test cases with templates

---

### Understanding-Oriented: Topic Guides

Topic guides provide background and explanation to help you understand how Revizor works. They don't contain step-by-step instructions but explain key concepts in depth.

* [Leakage Contracts](topics/contracts.md) - Understanding security specifications
* [Actors and Isolation](topics/actors.md) - Multi-domain testing concepts
* [Leakage Models](topics/models.md) - How the model predicts CPU behavior
* [Test Case Generation](topics/test-case-generation.md) - Code and data generation explained
* [Trace Analysis](topics/trace-analysis.md) - How violations are detected

---

### Information-Oriented: Reference

Reference guides contain technical descriptions of Revizor's components. They're like a dictionary—useful when you know what you're looking for.

* [Command Line Interface](ref/cli.md) - Complete CLI reference
* [Configuration Options](ref/config.md) - All configuration parameters
* [Execution Modes](ref/modes.md) - Fuzz, reproduce, analyze, minimize
* [Macros Reference](ref/macros.md) - Template macro system
* [Minimization Passes](ref/minimization-passes.md) - Available minimization techniques
* [Runtime Statistics](ref/runtime-statistic.md) - Runtime metrics printed during execution
* [Binary Format](ref/binary-formats.md) - (advanced) Revizor's custom binary format
* [Allocated Registers](ref/registers.md) - (advanced) Register allocation details
* [Sandbox](ref/sandbox.md) - (advanced) Sandbox for executing test cases

---

### Contributor-Oriented: Development Guides

Development guides help contributors understand the codebase, architecture, and development practices.

* [Developer Index](internals/index.md)
* [Architecture Overview](internals/architecture/overview.md)
* [Code Style Guidelines](internals/contributing/code-style.md)
* [Git Conventions](internals/contributing/git.md)

---

## Research and Background

Revizor is built on peer-reviewed research in hardware security and formal methods. All papers related to Revizor are listed in the [Research Papers](ref/papers.md) section.

---

## Documentation Feedback

If you find errors, confusing explanations, or missing information in the documentation, please let us know:

* Open an issue with the "documentation" label
* Suggest improvements via pull request
* Discuss on GitHub Discussions
