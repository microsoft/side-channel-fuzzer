# Configuration Options

Below is a list of the available configuration options for Revizor, which are passed down to Revizor via a config file.

For an example of how to write the config file, see [demo/big-fuzz.yaml](https://github.com/microsoft/side-channel-fuzzer/tree/main/demo/big-fuzz.yaml).


## <a name="fuzzer"></a> Fuzzing Configuration

#### `fuzzer`

:   <span class="inline-box" title="Default Value">:material-water:`basic`</span> Select the variant of a fuzzer to be used.

    === "Syntax"
        ```yaml
        fuzzer: <mode>
        ```
    === "Available Options"
        `basic` | `architectural` | `archdiff`
    === "Options Explained"
        * `basic` - normal model-based fuzzing. A violation in this mode indicates that the CPU
        exposes more information than predicted by the contract. This option should be used in most
        testing campaigns.
        * `architectural` - self-fuzzing for architectural mismatches between the model and the executor.
        This option should be used for testing the fuzzer itself, i.e., a violation in this
        mode indicates a bug in the fuzzer rather then a bug in the CPU. This is useful when running
        the fuzzer with a previously-untested instruction set, or when a new contract is implemented.
        * `archdiff` - fuzzing for architectural invariants. This is a special mode targeted for
        for semi-microarchitectural violations, similar to ZenBleed. This mode is experimental and
        should be used with caution.

#### `enable_priming`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> This option enables or disables priming. It should be set to True in most cases, as priming is crucial for eliminating false positives.

:    **What is priming?**: Priming solves the following problem: Revizor collects hardware traces for inputs in a sequence,
    and the microarchitectural state is not reset between the inputs. This means that the microarchitectural
    state for the input at, for example, position 100 is different from the state for the input at position 200.
    Accordingly, the hardware traces for these inputs may differ because the measurements are taken in different
    microarchitectural contexts.

:    To address this issue, we use priming, which swaps the inputs in the sequence and re-runs the tests.
    For example, if the original sequence is `(i1 . . . i99,i100,i101 . . . i199,i200)`, the priming
    sequence will be `(i1 . . . i99,i200,i101 . . . i199,i100)`. If the violation persists in this
    sequence, it is a true positive. If the violation disappears, it is a false positive, and it
    will be discarded.

    === "Syntax"
        ```yaml
        enable_priming: <True|False>
        ```

#### `enable_speculation_filter`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> If enabled, Revizor will not consider test cases that do not trigger speculation.

:    This option is useful for improving the throughput of the fuzzer, but it can discard potential violations if the leakage is not caused by speculation.

    === "Syntax"
        ```yaml
        enable_speculation_filter: <True|False>
        ```

#### `enable_observation_filter`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> If enabled, Revizor will not consider test cases that do not leave speculative traces.
    This is achieved by pre-filtering: For each test case, Revizor adds an `LFENCE` after each instruction in the test case, and compares the resulting hardware traces with the original. If the traces are identical, the test case is discarded without further processing.

:   This option is useful for improving the throughput of the fuzzer, but it can discard potential violations if the leakage is not caused by speculation.

    === "Syntax"
        ```yaml
        enable_observation_filter: <True|False>
        ```

#### `enable_fast_path_model`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> If enabled, the fuzzer will assume that all boosted inputs produce the same contract trace, and thus it will re-use the contract trace of the original input for all its boosted variants. This is normally a valid assumption to make if the taint tracker in the model does not contain bugs.

:   This option is a pure performance optimization. It only impacts the speed of fuzzing, and not its correctness.

    === "Syntax"
        ```yaml
        enable_fast_path_model: <True|False>
        ```

#### `color`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> If enabled, the output will be colored.
This option is helps a lot with readability, but may produce corrupted output when redirected to a file.

    === "Syntax"
        ```yaml
        color: <True|False>
        ```

#### `logging_modes`

:   <span class="inline-box" title="Default Value">:material-water: `['info', 'stat']`</span> Control the information logged by Revizor.

    === "Syntax"
        ```yaml
        logging_modes:
          - <mode1>
          - <mode2>
          ...
        ```
    === "Available Options"
        `info` | `stat` | `dbg_timestamp` | `dbg_violation` | `dbg_dump_htraces` | `dbg_dump_ctraces` | `dbg_dump_traces_unlimited` | `dbg_executor_raw` | `dbg_model` | `dbg_coverage` | `dbg_generator` | `dbg_priming` | `dbg_isa_filter`
    === "Options Explained"
        * `info` - general information about the progress of fuzzing;
        * `stat` - statistics the end of the fuzzing campaign;
        * `dbg_timestamp` - every 1000 test cases print the timestamp during the fuzzing process;
        * `dbg_violation` - upon detecting a violation, print detailed information about it;
        * `dbg_dump_htraces` - print the first 100 hardware traces for every test case;
        * `dbg_dump_ctraces` - print the first 100 contract traces for every test case;
        * `dbg_dump_traces_unlimited` - print ALL traces (use carefully, produces LOTS of text);
        * `dbg_executor_raw` - prints hardware traces for every stage of the fuzzing process;
        this differs from `dbg_dump_htraces` in that it prints the traces collected by
        speculation/observation filters as well as at every iteration of multi-sample collection;
        * `dbg_model` - print a detailed info about EVERY instruction executed on the model (use carefully, produces LOTS of text);
        * `dbg_coverage` - stores instruction coverage information;
        * `dbg_generator` - prints a list of instructions used to generate test cases;
        * `dbg_priming` - prints information about the priming process; only useful for debugging the priming mechanism itself.
        * `dbg_isa_filter` - when rvzr loads information about the instruction set (normally, from `base.json`), it filters out some of the instructions, either because of the config options provided by the user, or because some instructions are known to cause issues in the model or executor. This debug option prints the list of instructions that were filtered out, along with the reason for filtering them out.

#### `multiline_output`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> If enabled, each output message will be printed on a separate line. Otherwise, the fuzzing progress will be continuously overwriting the same line (works only in the terminal).

    === "Syntax"
        ```yaml
        enable_priming: <True|False>
        ```

## <a name="code-generator"></a> Program Generator Configuration

#### `generator`

:   <span class="inline-box" title="Default Value">:material-water: `random`</span> Select the type of program generator to be used.

    === "Syntax"
        ```yaml
        generator: <type>
        ```
    === "Available Options"
        `random`
    === "Options Explained"
        * `random` - generate random assembly programs. This is the only supported option at the moment.

#### `instruction_set`

:   <span class="inline-box" title="Default Value is Chosen Automatically Based on the Target CPU">:octicons-cpu-24:</span> The instruction set under test.

    === "Syntax"
        ```yaml
        instruction_set: <isa>
        ```
    === "Available Options"
        `x86-64` | `arm64`

#### `instruction_categories`

:   <span class="inline-box" title="Default Value is Chosen Automatically Based on the Target CPU">:octicons-cpu-24:</span> Select a list of instruction categories to be used when generating programs. This list effectively filters out instructions from the ISA descriptor file (e.g., `base.json`) passed via the command line (`-s`).

    !!! info "Priority"
        This list has higher priority than `instruction_blocklist` but lower than `instruction_allowlist`.

        The resulting instruction pool is:
        `all from(instruction_categories) - instruction_blocklist + instruction_allowlist`

    === "Syntax"
        ```yaml
        instruction_categories:
          - <category1>
          - <category2>
          ...
        ```
    === "Available Options"
        Any category in the ISA descriptor file (`base.json`).

#### `instruction_blocklist`

:   <span class="inline-box" title="Default Value is Chosen Automatically Based on the Target CPU">:octicons-cpu-24:</span> A list of instructions that will **not** be used for generating programs. This list filters out instructions from `instruction_categories`, but not from `instruction_allowlist`.

    !!! info "Priority"
        This list has lower priority than `instruction_allowlist`.

        The resulting instruction pool is:
        `all from(instruction_categories) - instruction_blocklist + instruction_allowlist`

    !!! warning "Danger Zone"
        This option has a somewhat sensible default value for each supported architecture, selected to avoid known-bad instructions. Thus, setting this option explicitly is unadvisable. Prefer using `instruction_blocklist_append` to add more instructions to the default blocklist.

    === "Syntax"
        ```yaml
        instruction_blocklist:
          - <instruction1>
          - <instruction2>
          ...
        ```
    === "Available Options"
        Any instruction in the ISA descriptor file (`base.json`).

#### `instruction_blocklist_append`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> A list of instructions that will be appended to the default blocklist for the target ISA. This option is identical to `instruction_blocklist`, but the list is added to the default instead of replacing it.

    !!! info "Priority"
        This list has lower priority than `instruction_allowlist`.

        The resulting instruction pool is:
        `all from(instruction_categories) - instruction_blocklist + instruction_allowlist`

    === "Syntax"
        ```yaml
        instruction_blocklist_append:
          - <instruction1>
          - <instruction2>
          ...
        ```
    === "Available Options"
        Any instruction in the ISA descriptor file (`base.json`).

#### `instruction_allowlist`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> A list of instructions to use for generating programs.

    !!! info "Priority"
        This list has priority over `instruction_categories` and over `instruction_blocklist`, thus adding instructions on top of the categories.

        The resulting instruction pool is:
        `all from(instruction_categories) - instruction_blocklist + instruction_allowlist`

    === "Syntax"
        ```yaml
        instruction_allowlist:
          - <instruction1>
          - <instruction2>
          ...
        ```
    === "Available Options"
        Any instruction in the ISA descriptor file (`base.json`).

#### `program_generator_seed`

:   <span class="inline-box" title="Default Value">:material-water: `0`</span> Seed of the program generator (aka code generator). If set to zero, a random seed will be used for each run.

    === "Syntax"
        ```yaml
        program_generator_seed: <seed>
        ```

#### `program_size`

:   <span class="inline-box" title="Default Value">:material-water: `24`</span> Number of instructions in the test case programs to be produced by the code generator. Note that the actual size might be larger because of the instrumentation.

    === "Syntax"
        ```yaml
        program_size: <size>
        ```

#### `avg_mem_accesses`

:   <span class="inline-box" title="Default Value">:material-water: `12`</span> Average number of memory accesses in the test case programs to be produced by the code generator. The actual number will be random, but the average over all programs will be close to this value.

    === "Syntax"
        ```yaml
        avg_mem_accesses: <count>
        ```

#### `min_bb_per_function`

:   <span class="inline-box" title="Default Value">:material-water: `1`</span> Minimal number of basic blocks per function in generated programs.

    === "Syntax"
        ```yaml
        min_bb_per_function: <count>
        ```

#### `max_bb_per_function`

:   <span class="inline-box" title="Default Value">:material-water: `2`</span> Maximal number of basic blocks per function in generated programs.

    === "Syntax"
        ```yaml
        max_bb_per_function: <count>
        ```

#### `min_successors_per_bb`

:   <span class="inline-box" title="Default Value">:material-water: `2`</span> Minimal number of successors for each basic block in generated programs.

    !!! note "Hint, not a rule"
        This option is a *hint*; it could be overwritten

        * if the instruction set does not have the necessary instructions to satisfy it
        * if a certain number of successor is required for correctness.
        * if min_successors_per_bb > max_successors_per_bb, the value is overwritten with max_successors_per_bb

    === "Syntax"
        ```yaml
        min_successors_per_bb: <count>
        ```

#### `max_successors_per_bb`

:   <span class="inline-box" title="Default Value">:material-water: `2`</span> Maximal number of successors for each basic block in generated programs.

    !!! note "Hint, not a rule"
        This option is a *hint*; it could be overwritten

        *  if the instruction set does not have the necessary instructions to satisfy it
        *  if a certain number of successor is required for correctness

    === "Syntax"
        ```yaml
        max_successors_per_bb: <count>
        ```

#### `register_allowlist`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> A list of registers that **can** be used for generating programs.

    !!! info "Priority"
        This list has higher priority than `register_blocklist`. The resulting list is: `(all registers - register_blocklist) + register_allowlist`.

    === "Syntax"
        ```yaml
        register_allowlist:
          - <register1>
          - <register2>
          ...
        ```
    === "Available Options"
        Any register supported by the target CPU.

#### `register_blocklist`

:   <span class="inline-box" title="Default Value is Chosen Automatically Based on the Target CPU">:octicons-cpu-24:</span> A list of registers that will **not** be used for generating programs.

    !!! info "Priority"
        This list has lower priority than `register_allowlist`. The resulting list is: `(all registers - register_blocklist) + register_allowlist`.

    !!! warning "Danger Zone"
        The default value of this option includes registers that reserved for internal use by the executor, and thus should be avoided. Modifying this option may lead to a full system crash.

    === "Syntax"
        ```yaml
        register_blocklist:
          - <register1>
          - <register2>
          ...
        ```
    === "Available Options"
        Any register supported by the target CPU.

#### `faults_allowlist`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> By default, the generator will produce programs that never trigger exceptions. This option modifies this behavior by permitting the generator to produce 'unsafe' instruction sequences that could potentially trigger an exception. The model and executor will also be configured to handle these exceptions gracefully.

    === "Syntax"
        ```yaml
        faults_allowlist:
          - <fault1>
          - <fault2>
          ...
        ```
    === "Available Options"
        `div-by-zero` | `div-overflow` | `opcode-undefined` | `breakpoint` | `debug-register` | `non-canonical-access` | `user-to-kernel-access`
    === "Options Explained"
        * `div-by-zero` - generate divisions with unmasked divisor, which can cause a division by zero exception.
        * `div-overflow` - generate divisions with unmasked dividend, which can cause an overflow exception.
        * `opcode-undefined` - generate undefined opcodes, which can cause an undefined opcode exception.
        * `breakpoint` - generate breakpoints, which can cause INT3 exceptions.
        * `debug-register` - generate instructions that cause INT1 exceptions.
        * `non-canonical-access` - randomly select a memory access in a generated program and instrument it to access a non-canonical address.
        * `user-to-kernel-access` - randomly select memory access instructions in user-privilege actors and instrument them to access the kernel actor's (actor 0) memory. This creates cross-privilege-level memory access patterns useful for detecting CPU vulnerabilities like Meltdown. Requires at least one actor with `privilege_level: user`. The instrumentation modifies both the memory operands and the sandboxing masks to ensure accesses target the kernel's FAULTY data area.


## <a name="actor"></a> Actor Configuration

All actors are defined in the `actors` list, with the following syntax:

```yaml
actors:
  - <actor1_name>:
      <actor_option>: <value>
      <actor_option>:
        <sub_option1>: <value1>
        <sub_option2>: <value2>
      ...
  - <actor2_name>:
      ...
  ...
```

The following options are available for each actor:

#### `mode`

:   <span class="inline-box" title="Default Value">:material-water: `host`</span> The execution mode of the actor.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              mode: <mode>
        ```
    === "Available Options"
        `host` | `guest`
    === "Options Explained"
        * `host` - the actor runs in the normal, non-virtualized mode.
        * `guest` - the actor runs in a VM (one VM per actor).

#### `privilege_level`

:   <span class="inline-box" title="Default Value">:material-water: `kernel`</span> The privilege level of the actor.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              privilege_level: <level>
        ```
    === "Available Options"
        `user` | `kernel`
    === "Options Explained"
        * `user` - the actor runs in user mode (CPL=3).
        * `kernel` - the actor runs in kernel mode (CPL=0).

#### `data_properties`

:   <span class="inline-box" title="Default Value">:material-water: (see below)</span> The properties of the data memory used by the actor. These properties are applied only to the faulty page of the actor's data region (see [sandbox](../ref/sandbox.md) for details).

:   Note that the above properties are set in the host page tables for actors with `mode: host`, and in the guest page tables for actors with `mode: guest`.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              data_properties:
                present: <True|False>
                writable: <True|False>
                user: <True|False>
                accessed: <True|False>
                dirty: <True|False>
                executable: <True|False>
                reserved_bit: <True|False>
                randomized: <True|False>
        ```
    === "Available Options"
        `present` | `writable` | `user` | `accessed` | `dirty` | `executable` | `reserved_bit` | `randomized`
    === "Options Explained"
        * `present` [default: True] - the value of the Present bit in the page table entry.
        * `writable` [default: True] - the value of the Writable bit in the page table entry.
        * `user` [default: False] - the value of the User/Supervisor bit in the page table entry.
        * `accessed` [default: True] - the value of the Accessed bit in the page table entry.
        * `dirty` [default: True] - the value of the Dirty bit in the page table entry.
        * `executable` [default: False] - the value of the Executable bit in the page table entry.
        * `reserved_bit` [default: False] - the value of the Reserved bit in the page table entry.
        * `randomized` [default: False] - if true, the values of the above properties will be randomized for each test case.

#### `data_ept_properties`

:   <span class="inline-box" title="Default Value">:material-water: `(see below)`</span> The properties of the EPT entry used by the actor (on Intel) or the NPT entry (on AMD). These properties are applied only to the faulty page of the actor's data region (see [sandbox](../ref/sandbox.md) for details).

:   This property has no effect on actors with `mode: host`.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              data_ept_properties:
                present: <True|False>
                writable: <True|False>
                executable: <True|False>
                accessed: <True|False>
                dirty: <True|False>
                user: <True|False>
                reserved_bit: <True|False>
                randomized: <True|False>
        ```
    === "Available Options"
        `present` | `writable` | `executable` | `accessed` | `dirty` | `user` | `reserved_bit` | `randomized`
    === "Options Explained"
        * `present` [default: True] - the value of the Present bit in the EPT/NPT entry.
        * `writable` [default: True] - the value of the Writable bit in the EPT/NPT entry.
        * `executable` [default: False] - the value of the Executable bit in the EPT/NPT entry.
        * `accessed` [default: True] - the value of the Accessed bit in the EPT/NPT entry.
        * `dirty` [default: True] - the value of the Dirty bit in the EPT/NPT entry.
        * `user` [default: False] - the value of the User/Supervisor bit in the EPT/NPT entry.
        * `reserved_bit` [default: False] - the value of the Reserved bit in the EPT/NPT entry.
        * `randomized` [default: False] - if true, the values of the above properties will be randomized for each test case.

#### `observer`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> If enabled, the actor will be an observer actor, hence modelling an attacker. This option is only used if the contract is `noninterference`, and it is ignored otherwise.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              observer: <True|False>
        ```

#### `instruction_blocklist`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> Actor-specific instruction blocklist.

:   This option is useful when writing a test case template that uses multiple actors, and some actors should use a different set of instructions than the others. For example, if privileged instructions should be blocked for low-privilege actors.

    !!! info "Priority"
        This list has priority over the global `instruction_blocklist` and modifies the instruction pool for the specific actor.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              instruction_blocklist:
                - <instruction1>
                - <instruction2>
                ...
        ```

#### `fault_blocklist`

:   <span class="inline-box" title="Default Value">:material-water: `[]`</span> Actor-specific fault blocklist.

:   For example, when using `user-to-kernel-access`, you typically want to add it to the kernel actor's `fault_blocklist` to prevent the kernel from accessing its own memory (which would not be a cross-privilege access).

    !!! info "Priority"
        This list has priority over the global `faults_allowlist` and modifies the fault-inducing instrumentation for the specific actor.

    === "Syntax"
        ```yaml
        actors:
          - <actor_name>:
              fault_blocklist:
                - <fault1>
                - <fault2>
                ...
        ```
    === "Available Options"
        See [`faults_allowlist`](#faults_allowlist) for the list of available faults.


## <a name="data-generator"></a> Data Generator Configuration

#### `data_generator`

:   <span class="inline-box" title="Default Value">:material-water: `random`</span> Select the method of test case data generation.

    === "Syntax"
        ```yaml
        data_generator: <type>
        ```
    === "Available Options"
        `random`
    === "Options Explained"
        * `random` - generate random input data for the test cases. This is the only supported option at the moment.

#### `data_generator_seed`

:   <span class="inline-box" title="Default Value">:material-water: `10`</span> Seed of the test case data generator. If set to zero, a random seed will be used for each run.

    === "Syntax"
        ```yaml
        data_generator_seed: <seed>
        ```

#### `data_generator_entropy_bits`

:   <span class="inline-box" title="Default Value">:material-water: `31`</span> Entropy of the random values created by the data generator.

    === "Syntax"
        ```yaml
        data_generator_entropy_bits: <bits>
        ```
    === "Allowed Values"
        Integer in the range `[1, 31]`

#### `input_gen_probability_of_special_value`

:   <span class="inline-box" title="Default Value">:material-water: `0.05`</span> When set to a non-zero value, the data generator will occasionally produce special values (such as zero or MAX_INT) alongside random values, with the frequency controlled by this probability. These special values help exercise fast-path optimizations in the microarchitecture.

    === "Syntax"
        ```yaml
        input_gen_probability_of_special_value: <probability>
        ```
    === "Allowed Values"
        Float in the range `[0.0, 1.0]`

#### `inputs_per_class`

:   <span class="inline-box" title="Default Value">:material-water: `2`</span> Number of inputs generated for each input class via input boosting (aka Contract-Driven Input Generation). For the explanation of the input classes and the generation algorithm, see [this paper](https://arxiv.org/pdf/2301.07642), Section 4.D. Contract-driven Input Generator.

    === "Syntax"
        ```yaml
        inputs_per_class: <count>
        ```


## <a name="contract"></a> Contract Configuration

#### `contract_execution_clause`

:   <span class="inline-box" title="Default Value">:material-water: `['seq']`</span> The execution clause of the contract. Multiple clauses can be combined to form a more permissive contract.

    === "Syntax"
        ```yaml
        contract_execution_clause:
          - <clause>
        ```
    === "Available Options"
        `seq` | `no_speculation` | `seq-assist` | `cond` | `conditional_br_misprediction` | `bpas` | `nullinj-fault` | `nullinj-assist` | `delayed-exception-handling` | `div-zero` | `div-overflow` | `meltdown` | `fault-skip` | `noncanonical` | `vspec-ops-div` | `vspec-ops-memory-faults` | `vspec-ops-memory-assists` | `vspec-ops-gp` | `vspec-all-div` | `vspec-all-memory-faults` | `vspec-all-memory-assists`
    === "Options Explained"
        * `seq` - sequential execution.
        * `no_speculation` - sequential execution. Synonym for `seq`.
        * `seq-assist` - sequential execution with possible microcode assists.
        * `cond` - permitted misprediction of conditional branches.
        * `conditional_br_misprediction` - permitted misprediction of conditional branches. Synonym for `cond`.
        * `bpas` - permitted speculative store bypass
        * `nullinj-fault` - page faults are permitted to speculatively return zero.
        * `nullinj-assist` - microcode assists are permitted to speculatively return zero.
        * `delayed-exception-handling` - upon an exception or a fault, data-independent instructions that follow the exception are allowed to execute speculatively.
        * `meltdown` - permission-based page faults are permitted to speculatively return the value in the memory.
        * `fault-skip` - upon a fault, the faulting instruction is speculatively skipped.
        * `noncanonical` - permitted speculative non-canonical memory accesses.
        * `vspec*` - experimental contracts for value speculation. See [this paper](https://www.usenix.org/system/files/usenixsecurity23-hofmann.pdf) for details.
        * `div-zero` - experimental contract; do not use.
        * `div-overflow` - experimental contract; do not use.

#### `contract_observation_clause`

:   <span class="inline-box" title="Default Value">:material-water: `ct`</span> The observation clause of the contract. In most cases, the default value should be used.

    === "Syntax"
        ```yaml
        contract_observation_clause: <clause>
        ```
    === "Available Options"
        `none` | `l1d` | `memory` | `pc` | `ct` | `loads+stores+pc` | `ct-nonspecstore` | `ctr` | `arch` | `tct` | `tcto` | `ct-ni`
    === "Options Explained"
        * `none` - the model observes nothing. Useful for testing the fuzzer.
        * `l1d` - the model observes the addresses of data accesses, adjusted to imitate the L1D cache trace. Has very few real applications, and should be generally avoided.
        * `memory` - the model observes the addresses of data accesses.
        * `ct` (constant time tracer) - the model observes the addresses of data accesses and the control flow.
        * `loads+stores+pc` - the model observes the addresses of data accesses and the control flow. Synonym for `ct`.
        * `ct-nonspecstore` - the model observes the addresses of data accesses and the control flow, but does not observe the addresses of stores during speculation.
        * `ctr` - the model observes the addresses of data accesses and the control flow, as well as the values of the general-purpose registers.
        * `arch` - the model observes the addresses of data accesses and the control flow, as well as the values loaded from memory. This clause imitates the security guarantees provided by secure speculation mechanisms like STT.
        * `tct` (truncated constant time tracer) - the model observes address of the memory access and of the program counter at cache line granularity.
        * `tcto` (truncated constant time tracer with overflows) - the model address of the memory access and of the program counter at cache line granularity + observe cache line overflows.
        * `ct-ni` - (only available in multi-actor context) when executing actors with `observer: false`, the model observes the same data as as with `ct`. When executing actors with `observer: true`, the model observes complete memory of the actor as well as their register values.

#### `model_backend`

:   <span class="inline-box" title="Default Value">:material-water: `unicorn`</span> The backend used to implement the contract model.

    === "Syntax"
        ```yaml
        model_backend: <backend>
        ```
    === "Available Options"
        `dummy` | `unicorn` | `dynamorio`
    === "Options Explained"
        * `unicorn` - use Unicorn-based implementation of the model. This backend is more mature and feature-rich, but it supports a considerably smaller set of instruction than DynamoRIO (essentially, only the base x86 or ARM instruction sets, without any extensions).
        * `dynamorio` - use DynamoRIO-based implementation of the model. This backend is less mature and supports fewer contracts and features than Unicorn, but it can handle a much larger set of instructions, including complex extensions like AVX-512 on x86-64. It is also generally faster than Unicorn, especially when testing large test case or running with many inputs per test case.
        * `dummy` - use a dummy model. This model always returns the same (empty) contract trace, and as such will not produce meaningful results. This option is useful, however, when root-causing violations, because it allows to collect hardware traces without running the model, hence allowing to trace instructions that are not supported by any of the backends.

#### `model_min_nesting`

:   <span class="inline-box" title="Default Value">:material-water: `1`</span> Minimum number of nested mispredictions in the model. This value is used to generate the contract traces on the fast path of the fuzzer. Chose a small value when speculation is rare, and a larger value when speculation is common.

:   This option is a pure performance optimization. It only impacts the speed of fuzzing, and not its correctness.

    === "Syntax"
        ```yaml
        model_min_nesting: <depth>
        ```

#### `model_max_nesting`

:   <span class="inline-box" title="Default Value">:material-water: `30`</span> Maximum number of nested mispredictions in the model. This value is used to generate the contract traces on the slow path of the fuzzer, i.e., when a potential violation is detected and the fuzzer tries to check if it is a true positive.

:   In contrast to `model_min_nesting`, this option could cause false positives if set too low. Thus, it is advisable to set it to a sufficiently high value to cover all possible nested mispredictions in the test cases. Leave the default unless you are sure that a lower value is sufficient.

    === "Syntax"
        ```yaml
        model_max_nesting: <depth>
        ```

#### `model_max_spec_window`

:   <span class="inline-box" title="Default Value">:material-water: `250`</span> Size of the speculation window in the model.

:    This option sets a trade-off between accuracy and performance. A larger speculation window avoids potential false positives due to inaccurate modelling of the speculation, but it also slows down the model execution. Leave the default unless you are sure that a different value is needed.

    === "Syntax"
        ```yaml
        model_max_spec_window: <size>
        ```

## <a name="executor"></a> Executor Configuration

#### `executor`

:   <span class="inline-box" title="Default Value is Chosen Automatically Based on the Target CPU">:octicons-cpu-24:</span> ISA-specific version of the executor to use. The default value is auto-detected based on `cpuinfo`. Should be changed only if the auto-detection fails.

    === "Syntax"
        ```yaml
        executor: <type>
        ```
    === "Available Options"
        `x86-64-intel` | `x86-64-amd` | `arm64`

#### `executor_mode`

:   <span class="inline-box" title="Default Value">:material-water: `P+P`</span> Method of collecting hardware traces in the executor. The method determines the contents of hardware traces.

    === "Syntax"
        ```yaml
        executor_mode: <mode>
        ```
    === "Available Options"
        `P+P` | `F+R` | `E+R` | `PP+P` | `TSC`
    === "Options Explained"
        * `P+P` - prime and probe side-channel attack. The hardware traces contain the cache sets that were accessed during the execution of the test case.
        * `F+R` - flush and reload side-channel attack. The hardware traces contain the memory addresses that were accessed during the execution of the test case.
        * `E+R` - evict and reload side-channel attack. The hardware traces contain the cache sets that were accessed during the execution of the test case.
        * `PP+P` - partial prime and probe (i.e., leave a subset of cache lines unprimed). The hardware traces contain the cache sets that were accessed during the execution of the test case.
        * `TSC` - use `RDTSCP` instruction to measure the execution time of test cases. The hardware traces contain the execution time, in cycles.

#### `executor_warmups`

:   <span class="inline-box" title="Default Value">:material-water: `5`</span> Number of warmup rounds executed before starting to collect hardware traces.

    === "Syntax"
        ```yaml
        executor_warmups: <count>
        ```

#### `executor_sample_sizes`

:   <span class="inline-box" title="Default Value">:material-water: `[10, 50, 100, 500]`</span> A list of sample sizes to be used during the measurements.

    !!! info "Clarification"
        Executor normally performs measurements multiple times for each test case in order to collect a sample of hardware traces. This allows Revizor to tolerate noise and non-determinism in the measurements by applying statistical methods for comparing the traces.

        For performance reasons, Revizor does not immediately use a large sample size. Instead, it starts with a small sample, collects the traces, and checks if a violation is detected. If no violation is detected, the executor assumes that the test case is safe, and moves on to the next one. If a violation is detected, however, the executor tries to reproduce it with larger sample sizes.

        This option defines the list of sample sizes through which Revizor will iterate in this process. To make it sensible, the list should be sorted in ascending order with a reasonable gap between the sizes.

    === "Syntax"
        ```yaml
        executor_sample_sizes:
          - <sample_size1>
          - <sample_size2>
          ...
        ```

#### `executor_filtering_repetitions`

:   <span class="inline-box" title="Default Value">:material-water: `10`</span> The sample size to be used by the speculation and observation filters.

    === "Syntax"
        ```yaml
        executor_filtering_repetitions: <count>
        ```

#### `executor_taskset`

:   <span class="inline-box" title="Default Value">:material-water: `0`</span> The CPU core ID which the executor will use for running test cases. That is, the executor process will be pinned to this core.

    === "Syntax"
        ```yaml
        executor_taskset: <core_id>
        ```

#### `enable_pre_run_flush`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> If enabled, the executor will do its best to flush the microarchitectural state before running test cases.

    === "Syntax"
        ```yaml
        enable_pre_run_flush: <True|False>
        ```

## <a name="analyser"></a> Analyser Configuration

#### `analyser`

:   <span class="inline-box" title="Default Value">:material-water: `chi2`</span> The type of the analyser that is used to compare hardware traces against contract traces.

    === "Syntax"
        ```yaml
        analyser: <type>
        ```
    === "Available Options"
        `chi2` | `mwu` | `sets` | `bitmaps`
    === "Options Explained"
        * `sets` - combine the hardware traces for each input into a set. A violation is reported if two inputs in the same contract-equivalence class have different sets of hardware traces.
        * `bitmaps` - combine the hardware traces for each input into a bitmap. A violation is reported if two inputs in the same contract-equivalence class have different bitmaps of hardware traces.
        * `chi2` - use the chi-squared homogeneity test to compare the hardware traces of inputs in the same contract-equivalence class. This test effectively checks if the hardware traces from two different inputs come from the same distribution. A violation is reported if the test fails.
        * `mwu` - [experimental; both false positives and negatives are possible] use the Mann-Whitney U test to compare the hardware traces of inputs in the same contract-equivalence class. This test effectively checks if the hardware traces from two different inputs come from the same distribution. A violation is reported if the test fails.

#### `analyser_subsets_is_violation`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> This option is relevant only for the `sets` and `bitmaps` analysers. If enabled, the analyser will not label hardware traces as mismatching if they form a subset relation.

    === "Syntax"
        ```yaml
        analyser_subsets_is_violation: <True|False>
        ```

#### `analyser_outliers_threshold`

:   <span class="inline-box" title="Default Value">:material-water: `0.1`</span> This option is relevant only for the `sets` and `bitmaps` analysers. The analyser will ignore the hardware traces that appear in less than this percentage of the sampled traces.

    === "Syntax"
        ```yaml
        analyser_outliers_threshold: <threshold>
        ```

#### `analyser_stat_threshold`

:   <span class="inline-box" title="Default Value">:material-water: `0.5`</span> This option is relevant only for the `chi2` and `mwu` analysers. The threshold for the statistical tests. If a pair of hardware traces has the (normalized) statistics below the threshold, then the traces are considered equivalent.

:   For the chi2 test, the threshold is applied to the `statistics / (len(htrace1) + len(htrace2))`.

:   For the mwu test, the threshold is applied to the p-value.

    === "Syntax"
        ```yaml
        analyser_stat_threshold: <threshold>
        ```

## <a name="misc"></a> Miscellaneous Configuration

#### `coverage_type`

:   <span class="inline-box" title="Default Value">:material-water: `none`</span> The type of coverage tracking.

    === "Syntax"
        ```yaml
        coverage_type: <type>
        ```
    === "Available Options"
        `none` | `model_instructions`
    === "Options Explained"
        * `none` - disable coverage tracking.
        * `model_instructions` - track how many times the model executed each instruction in the target ISA.

#### `minimizer_retries`

:   <span class="inline-box" title="Default Value">:material-water: `1`</span> Number of minimization retries. When the minimizer performs a check to reduce a test case, each check is attempted this number of times and it succeeds if at least one check is successful.

    === "Syntax"
        ```yaml
        minimizer_retries: <count>
        ```

## Unique x86-64 Options


#### `x86_executor_enable_ssbp_patch`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> Enable a microcode patch against Speculative Store Bypass, if available.

    === "Syntax"
        ```yaml
        x86_executor_enable_ssbp_patch: <True|False>
        ```

#### `x86_executor_enable_prefetcher`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> Enable all prefetchers, if the software controls are available.

    === "Syntax"
        ```yaml
        x86_executor_enable_prefetcher: <True|False>
        ```

#### `x86_disable_div64`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> Do not generate 64-bit division instructions. Useful for avoiding certain types of speculation that are specific to 64-bit division.

    === "Syntax"
        ```yaml
        x86_disable_div64: <True|False>
        ```

#### `x86_enable_hpa_gpa_collisions`

:   <span class="inline-box" title="Default Value">:material-water: `False`</span> When a test case contains at least one guest actor, allocate its memory in the guest physical address space to match the corresponding host physical addresses of the main actor. Useful for testing Foreshadow-like leaks.

    === "Syntax"
        ```yaml
        x86_enable_hpa_gpa_collisions: <True|False>
        ```

#### `x86_generator_align_locks`

:   <span class="inline-box" title="Default Value">:material-water: `True`</span> When generating memory accesses with locks, apply instrumentation to align the locks to 8 bytes. Useful for avoiding faults on unaligned accesses.

    === "Syntax"
        ```yaml
        x86_generator_align_locks: <True|False>
        ```

---

## What's Next?

- [Command Line Interface](cli.md) - CLI options and modes
- [demo/big-fuzz.yaml](https://github.com/microsoft/side-channel-fuzzer/tree/main/demo/big-fuzz.yaml) - Comprehensive example configuration
- [demo/](https://github.com/microsoft/side-channel-fuzzer/tree/main/demo/) - Example configurations for various scenarios
