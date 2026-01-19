# Changelog

All notable changes to Revizor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-10

### TL;DR

This release contains a major refactoring of the codebase, including many of the core modules. This breaks compatibility with previous versions, hence the major version bump.

In addition, several significant enhancements have been made:

- ARM64 is now fully supported.
- New DynamoRIO-based model backend has been added, which vastly improves ISA coverage on x86.
- The documentation has been fully restructured and expanded.

### Added

#### ARM64 Support
- Full hardware tracing support for ARM64 CPUs (#137)
- ARM64 executor, fuzzer, and code generator implementations
- ARM64 test suite with acceptance and unit tests
- ARM64 ISA specification and target description

#### DynamoRIO Model Backend
- New DynamoRIO-based model backend added, which completely re-implements the leakage modeling functionality
- New tracers: indirect memory access (IND) tracer and poisoning of faulty loads (#133)
- Contract-based input generation for DynamoRIO backend (#138)

#### Documentation
- Complete documentation restructure with tutorials, reference guides, and topic guides
- Five comprehensive tutorials covering first fuzzing campaign, vulnerability detection, fault handling, isolation, and extending Revizor
- Detailed primer on contracts and leakage models
- In-depth guides on choosing contracts, designing campaigns, interpreting results, and root-causing violations
- Architecture overview with detailed diagrams
- DynamoRIO backend instrumentation diagrams
- Sandbox and binary format documentation
- Actor and test case generation topics
- Glossary of key terms

#### Demos and Examples
- TSA-L1D demo configuration and template
- TSA-SQ demo files
- Improved detection demos for various Spectre variants

#### Testing and Development
- Unified tests for Unicorn and DynamoRIO backends
- Unit tests for traces, stats, and test case components
- Utility scripts for generating RCBF/RDBF test files
- Interface to run individual testing stages
- Improved test coverage and CI integration

#### Misc. Features
- Special value generation option for input data (not just random values)
- More verbose configuration error messages
- Better visibility for warnings in logger output
- Support for FS/GS segment register instructions in ISA specification
- Input differential minimization for observer actors

### Changed

**WARNING**: This release contains breaking changes! The release introduces a complete refactoring of the code structure, including many of the core modules. See docs/internals/architecture/overview.md for details.

#### Code Structure
- Renamed source directory from src/ to rvzr/ for better compliance with Python packaging standards
- Encapsulated all core components into dedicated modules (sandbox.py, actor.py, etc)
- Moved all test case components into a dedicated directory rvzr/tc_components
- Refactored fuzzer.py to isolate the multi-stage filtering logic into a dedicated class
- Isolated utility classes into dedicated modules stats.py and logs.py
- Unicorn-based backend split into logical classes: Tracer, Speculator, TaintTracker, etc. (rvzr/model_unicorn)
- Reorganized into architecture-specific subdirectories (rvzr/arch/x86, rvzr/arch/arm64)
- Minimizer refactored to encapsulate each pass into a separate class (rvzr/postprocessing)
- Executor KM is now shared between x86 and ARM to avoid code duplication
- Consistent naming conventions for generators across architectures
- Improved code style and formatting

#### Configuration Options
- Many config options have been renamed during the refactoring process
- Refer to the updated documentation (`docs/ref/config.md`)for the new option names and their usage.

#### ISA Spec Format
- Renamed several fields in the json produced by the download_spec command

#### Testing Infrastructure
- Cleaner interface for test scripts
- GitHub Actions aligned with internal test scripts

#### Documentation Structure
- Reorganized into intro/, howto/, ref/, topics/, and internals/ sections
- Split architecture documentation into per-module pages
- Updated navigation structure in MkDocs



### Deprecated

- MPX support

---

## [1.3.2] - 2024-09-12

See git history for changes in version 1.3.2 and earlier.

[1.3.3]: https://github.com/microsoft/side-channel-fuzzer/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/microsoft/side-channel-fuzzer/releases/tag/v1.3.2
