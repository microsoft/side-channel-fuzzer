# How to Interpret Violation Results

So you've run a fuzzing campaign and found a violation. Now what?

This guide will help you understand and validate violations detected by Revizor. This guide explains the structure of violation artifacts, how to reproduce violations, and how to interpret the output to determine whether a violation is genuine and worth investigating.

!!! info "Prerequisites"
    Before starting, ensure you have:

    - Revizor installed and functional on the target system
    - A violation directory (`violation-<timestamp>`) produced during fuzzing
    - The configuration file (`config.yaml`) used in the original fuzzing campaign
    - Access to the same hardware where the violation was detected

## Violation Message

When Revizor detects a violation during fuzzing, it prints a summary message to the console similar to this:

```plaintext
(venv-3.12) main ➜  revizor ./revizor.py fuzz -s base.json -c demo/detect-v1.yaml -n 1000 -i 100 -w ./

INFO: [prog_gen] Setting program_generator_seed to random value: 599740

INFO: [fuzzer] Starting at 15:39:42
17    ( 2%)| Stats: Cls:0/0,In:200,R:7,SF:10,OF:7,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0,V:0> Priming  27             . to 500

================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:92  | ID:192|
-----------------------------------------------------------------------------------
^...^...................^...........^.........^................. | 497    | 0     |
^...^........................................................... | 3      | 2     |
^^..^...........................................^.........^..... | 0      | 498   |


================================ Statistics ===================================

Test Cases: 18
Inputs per test case: 200.0
Violations: 1
Effectiveness:
  Total Cls: 98.0
  Effective Cls: 98.0
Discarded Test Cases:
  Speculation Filter: 10
  Observation Filter: 7
  Fast Path: 0
  Max Nesting Check: 0
  Tainting Check: 0
  Early Priming Check: 0
  Large Sample Check: 0
  Priming Check: 0

Duration: 40.5
Finished at 15:40:23
```

Most of the output is statistics, and they are mostly irrelevant for interpreting the violation itself. You can find a detailed explanation of the runtime statistics in the [Statistics Reference](../ref/runtime-statistic.md).

The relevant part for interpreting the violation is the `Violation Details` section:

```
-----------------------------------------------------------------------------------
                             HTrace                              | ID:92  | ID:192|
-----------------------------------------------------------------------------------
^...^...................^...........^.........^................. | 497    | 0     |
^...^........................................................... | 3      | 2     |
^^..^...........................................^.........^..... | 0      | 498   |
```

This section summarizes the hardware trace samples recorded for the inputs that triggered the violation.

Let's break it down.

### Violating Inputs

```
| ID:92  | ID:192|
```

This block tells us which inputs produced the violation. In this case, it's inputs 92 and 192. You can find them in the violation artifact directory as `input_92.bin` and `input_192.bin`.

### Hardware Traces

```
^...^...................^...........^.........^.................
^...^...........................................................
^^..^...........................................^.........^.....
```

This block shows a visual representation of all observed hardware traces for these inputs. In this example, we used Revizor's default P+P (Prime+Probe) cache side channel tracer, which records the state of L1D cache after a test case execution. The `^` character indicates that a cache line was accessed (evicted by the test case program), while the `.` character indicates that the cache line was not accessed. The complete line is a bitmap of all 64 L1D cache sets available on the target machine, numbered left to right from 0 to 63.

Accordingly, the first line is interpreted as follows:

```

    Set 4 accessed                  Set 36 accessed
    |                               |         Set 46 accessed
    |                               |         |
^...^...................^...........^.........^.................
|                       |
Set 0 accessed          Set 24 accessed
```

meaning that cache sets with IDs 0, 4, 24, 36, and 46 were accessed in this hardware trace.


!!! tip "Colors!"
    Enable `color: true` in the configuration file to improve readability of hardware trace visualizations.

### Trace Distribution

```
... | 497    | 0     |
... | 3      | 2     |
... | 0      | 498   |
```

Finally, this block shows the [statistical distribution](../topics/trace-analysis.md#statistical-trace-comparison) of hardware traces for each input. For example, input 92 produced the first hardware trace 497 times (out of the total of 500 measurements), while input 192 never produced that trace. Instead, input 192 produced the third hardware trace 498 times.

### Analysis

By looking at this table, we can deduce two important facts about the violation:

1. There is a clear difference in the sample distributions for the two inputs. This indicates a genuine violation rather than random noise.
2. The dominant (most frequently observed) hardware trace for each input have evicted distinct sets of cache lines. This is an indirect clue that the test case had a data-dependent memory accesses pattern that was not predicted by the contract (likely due to speculative execution).

## Violation Artifact

When Revizor detects a violation, it creates a directory named `violation-<timestamp>`, with the following structure:

```
violation-<timestamp>/
├── program.asm
├── input_0.bin
├── input_1.bin
├── ...
├── report.txt
├── org-config.yaml
├── reproduce.yaml
└── minimize.yaml
```

 The `program.asm` file holds the test case program that triggered the violation. The `input_*.bin` files contain the input sequence that exposed the leak. The `report.txt` file provides additional details including hardware and contract traces. The configuration files include `org-config.yaml` (the original configuration), `reproduce.yaml` (for reproducing the violation), and `minimize.yaml` (for test case minimization).

Before proceeding with analysis, locate this directory and verify that all required files are present.

## Reproducing the Violation

It is usually a good idea to first reproduce the violation outside of the fuzzing campaign. This confirms that the violation is stable and not a transient artifact of noise or a misconfiguration of the fuzzer.

```bash
rvzr reproduce -s base.json -c ./violation-<timestamp>/reproduce.yaml \
    -t ./violation-<timestamp>/program.asm -i ./violation-<timestamp>/input_*.bin
```

If Revizor prints "Violation detected" in the output, the violation reproduced successfully. The distribution of hardware traces should roughly match the original violation. Significant differences may indicate a bug or misconfiguration in the fuzzer (e.g., random seeds).

Non-reproducible violations should be rare, typically no more than one or two per machine per week of fuzzing. If your campaign produces more, adjust the configuration file to increase noise tolerance. See the [configuration options reference](../ref/config.md) for details on noise-related parameters.


## Evaluating Violation Quality

Several factors determine whether a violation is worth investigating further.

*Reproducibility* is the most important criterion. Violations that consistently reproduce across multiple runs indicate stable, genuine leaks. Sporadic violations that appear and disappear may be false positives caused by noise. In such cases, consider adjusting noise tolerance settings ([`analyser_stat_threshold`](../ref/config.md#analyser_stat_threshold) and/or [`executor_sample_sizes`](../ref/config.md#executor_sample_sizes)) in the configuration file and rerunning the fuzzing campaign.

*Trace distribution* provides additional insight. Clean violations show clear separation between inputs with consistent occurrence counts. Messy violations with overlapping traces or highly variable counts suggest non-determinism and may be harder to analyze. In such cases, consider collecting more samples per input by increasing the [`executor_sample_sizes`](../ref/config.md#executor_sample_sizes) configuration option (note: this will slow down fuzzing).

Finally, *the hardware trace pattern* can be informative as well. There is no hard rule here, but if you see lots of accessed cache sets while the configuration is supposed to limit the number of memory accesses to only a few, that may indicate that some CPU feature creates additional noise, beyond the ability of the statistical analyzer to filter it out. In practice, this is often due to prefetchers. It is typically a good idea to disable them, unless you are specifically testing for prefetcher-related leaks.

## Next Steps

Once you have confirmed that a violation is reproducible and worth investigating, proceed to minimize the violation artifacts and root-cause the leak. See the [How to Minimize Test Cases](minimize.md) and [How to Root-Cause a Violation](root-cause-a-violation.md) guides for detailed instructions.

## See Also

- [How to Root-Cause a Violation](root-cause-a-violation.md) - Systematic analysis of confirmed violations
- [How to Design a Fuzzing Campaign](design-campaign.md) - Tuning fuzzer parameters for better results
- [How to Minimize Test Cases](minimize.md) - Simplifying violation artifacts for analysis
- [Configuration Options](../ref/config.md) - Detailed configuration parameter reference
- [Execution Modes](../ref/modes.md) - Understanding reproduce mode and other execution modes
- [Trace Analysis and Violation Detection](../topics/trace-analysis.md) - How Revizor detects and analyzes violations
- [Contracts and Leakage Models](../topics/contracts.md) - Understanding contract semantics
