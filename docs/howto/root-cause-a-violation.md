# How to Root-Cause a Violation

This guide discussed in detail how to identify the root cause of confirmed contract violations. This guide shows a typical workflow and some useful techniques for analyzing violation artifacts and isolating the specific CPU behavior that leads to information leakage.

!!! warning "Art, Not Science"
    Root-causing violations is more art than science. The techniques described here are not guaranteed to work in every situation because violations can arise from a wide variety of complex CPU behaviors. Use your intuition and knowledge of microarchitecture to guide your analysis. Experiment with different approaches and document what works best for you.

!!! info "Prerequisites"
    The guide assume you have already finished a [fuzzing campaign](design-campaign.md) and [minimized the violation artifacts](minimize.md).

## Locate the Violation Files

We will explore the root-cause analysis through a concrete example. The example will demonstrate a CT-SEQ contract violation on an x86-64 CPU.

We will be working with:

- The violation artifact in `violation-0000-0000/` produced during fuzzing
- A minimized version of the violation program in `min.asm` produced by the minimizer
- A set of minimized input files in `./inputs/min_input_*.bin` produced by the minimizer
- The configuration file `config.yaml` used during fuzzing

## Gather Insights from Minimizer

A good starting point is to examine the output of the minimizer, especially from input minimization passes. These passes attempt to reduce the differences between inputs that trigger the violation, and thus they often highlight the specific data values that leak and that impact the violation.

Below is an example of the printed summary from the differential input minimizer:

```
[PASS 2] Differential Input Minimizer
  > Minimizing the difference between inputs 1 and 11

Address    +0x0     +0x40    +0x80    +0xc0    +0x100   +0x140   +0x180   +0x1c0
0x00000000 ........ ........ ........ ........ ........ ........ ........ ........
0x00000200 ........ =....... ........ ........ ........ ........ ........ ........
0x00000400 ........ ........ ........ ........ ........ ........ ........ ........
0x00000600 ........ ........ ........ ........ ........ ........ ........ ........
0x00000800 ........ ........ ........ ........ ........ ........ ........ ........
0x00000a00 ........ ........ ........ ........ ........ ........ ........ ........
0x00000c00 ........ ........ ........ ........ ........ ........ ........ ........
0x00000e00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001000 ........ ........ ........ ........ ........ ........ ........ ........
0x00001200 ........ ........ ........ ........ ........ ........ ........ ........
0x00001400 ........ ........ ........ ........ ........ ........ ........ ........
0x00001600 ........ ........ ........ ........ ........ ........ ........ ........
0x00001800 ........ ........ ........ ........ ........ ........ ........ ........
0x00001a00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001c00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001e00 ........ ........ ........ ........ ........ ........ ........ ........
0x00002000 .....^..
0x00002040 ........ ........ ........ ........
  > Result: Leaked 1 bytes
  > Addresses: ['0x2028']
```

The minimizer goes through the pair of inputs that trigger the violation - inputs #1 and #11 in this case - and tries to minimize the differences between them:

* If both inputs already have identical values at a given address, the minimizer prints `=` for that address. In this example, this is the case for address `0x240`.
* Next, the pass attempts to zero out one byte at a time in both inputs. If the violation persists, then the minimizer prints `.` for that address. In this example, most of the addresses are zeroed out.
* Next, the pass attempts to copy one byte from input #1 into the same address in input #11. If the violation persists, then the minimizer prints `+` for that address. This example does not have such cases.
* If both attempts fail, the pass restores the original values at the given address, prints `^`, and moves to the next address. In this example, the minimizer restored the original value at address `0x2028`.

The interpretation of these results is case-specific, but generally, the values with `+` or `=` are those that create conditions for leakage, and the values with `^` are the addresses whose value leaks.

In this example, the minimizer found that this test case leaks one byte at address `0x2028` (used to initialize RDI). The minimizer also found that the address `0x240` must contain specific non-zero values that must be the same in both inputs. This address in the input is used to initialize the corresponding offset in the sandbox of actor 0. See [Sandbox Memory Layout](https://microsoft.github.io/side-channel-fuzzer/user/sandbox/) for more details about register and memory initialization.

!!! tip "Minimizer Behavior"
    Ideally, the minimizer should be able to reduce the leakage to a single byte. If more then a couple bytes leak, it typically indicates that the violation is non-deterministic, and it might be a good idea to re-run the program minimizer or to change the configuration to increase the number of attempts/increase the noise threshold. If *no* bytes leak, this is a certain sign that something went wrong; re-run the minimizer.

## Step 3: Add Comments to Minimized Program

Run the minimizer again with the `comment` pass enabled to annotate the minimized program with memory access information. This will help you map hardware traces to specific instructions in the program.

```bash
rvzr minimize -s base.json -c ./violation-0000-0000/minimize.yaml \
    -t min.asm -o commented.asm -i <num_inputs> \
    --enable-comment-pass 1
```

## Insert Speculation Fences

To isolate speculative behavior, add fences:

```bash
rvzr minimize -s base.json -c ./violation-0000-0000/minimize.yaml \
    -t commented.asm -o fenced.asm -i <num_inputs> \
    --enable-fence-pass 1
```

This pass with attempt to insert an `LFENCE` after every instruction in the program and check if the violation still occurs.

In the resulting file (`fenced.asm`) the region *without* fences is the one that causes the violation. The remaining instructions are just setting up the data for the violation, and are likely irrelevant.

!!! warning "Unexpected Fence Insertion Results"
    If an `LFENCE` is inserted after *every* instruction in the test case and the violation still occurs, this is most likely due to a bug in the model or the executor. If you are using a custom model, consider checking the model for correctness. If you haven't made changes to the Revizor source code, please, open an issue in the [bug tracker](https://github.com/microsoft/side-channel-fuzzer/issues).

## Map Hardware Traces to Minimized Program and Data

When both program and its inputs are minimized, you should be able to identify which instructions caused the cache accesses in the hardware traces and which data was leaked.

When we run the `reproduce` command with the minimized program and inputs, we will see the following hardware traces:

```bash
rvzr reproduce -s base.json -c ./violation-0000-0000/reproduce.yaml \
    -t commented.asm -i ./inputs/min_input*.bin

...

================================ Violations detected ==========================
-----------------------------------------------------------------------------------
                             HTrace                              | ID:1   | ID:11 |
-----------------------------------------------------------------------------------
^...............................................^............... | 420    | 0     |
^............................................................... | 80     | 0     |
^..............^................................................ | 0      | 500   |
```

!!! tip "Input IDs"
    If in your case the input IDs have changed after minimization, you can either exclude some of the inputs from the arguments of the `reproduce` command, or re-run the minimizer with fewer passes.

We see that the hardware traces have been significantly simplified compared to the original violation, and now there are at most two accessed cache sets in each trace: 0 and 48 for input #1, and 0 and 15 for input #11. This is a good sign: the minimization was successful.

We can also tell that the only difference between the two traces is the accessed cache set 48 vs 15 . This is the cache set that is causing the violation, and we should be aiming to find the instruction that does the access.

To do so, let's look at the contents of the `commented.asm` file. This file contains the minimized program with comments that show which memory addresses or cache lines are accessed by each instruction.

```assembly
; ... skipped header ...
1.  and rax, 0b1111111111111 # instrumentation
2.  lfence
3.  mov edx, dword ptr [r14 + rax]
4.  # mem access: [1] 0x0 cl 0:0 | [11] 0x0 cl 0:0
5.  or cx, 0b1000 # instrumentation
6.  and cl, 0b11111000 # instrumentation
7.  and dx, 0b11 #
8.  and rsi, 0b1111111111111 #
9.  add cl, 39 #
10. mov rbx, 0b1111111111111 #
11. bt si, dx
12. jbe .bb_0.1
13. jmp .exit_0
14. .bb_0.1:
15. mov ecx, edi
16. and rcx, 0b1111111111000 # instrumentation
17. mov byte ptr [r14 + rcx], 88
; ... skipped footer ...
```

This program contains only two memory accesses, at lines 3 and 17.

The [annotation](minimize.md#comment-pass-output) at line 4 tells us that the `mov` instruction accesses memory offset `0x0` when executed with input 1 (`[1]`) and the same cache set when executed with input 11 (`[11]`). The notation `0:0` stands for cache set `0` and cache line offset `0`.

This information lets us map this instruction to the first access in the hardware trace:

```plaintext
    ^...............................................^...............
    |
  This eviction maps to `mov edx, dword ptr [r14 + rax]` at line 3
```

The second memory access (line 17) does not have an annotation, which implies that the contract model has not executed this instruction with the inputs provided. It does not, however, mean that the CPU has not executed this instruction, as there is a chance that this instruction was executed speculatively. This is a typical scenario in violations detected by Revizor.

If we look at the instructions prior to the memory access, we can see `jbe` instruction at line 12, which is a conditional jump - a common source of speculation, namely branch prediction. This type of speculation is not permitted by the target contract (CT-SEQ), so it could cause a violation. From this, we can make a hypothesis that the memory access at line 17 is speculative and is the one causing the second cache access:

```plaintext
 Inputs [1]:
              Hypothesis: This eviction maps to `mov` at line 17
                                                  |
  ^...............................................^...............

 Inputs [11]:
  ^..............^................................................
                 |
           Hypothesis: This eviction maps to `mov` at line 17
```

To check if our hypothesis is correct, let's cross-reference this information with the leaked bytes from the differential input minimizer:

```plaintext
; .. skip zero bytes
0x00002000 .....^..
0x00002040 ........ ........ ........ ........
  > Result: Leaked 1 bytes
  > Addresses: ['0x2028']
```

This summary tells us that `rdi` has a differing value between inputs #1 and 11. At the same time, the first time `rdi` is used in the program is at line 15, where it is moved to `rcx`, and then later used as a part of the address in the memory access at line 17. This would make the speculative memory access at line 17 access different addresses with the two inputs, and would explain the difference between the hardware traces.

At this point, the hypothesis is more-or-less confirmed, and we can declare that the root cause of the leak was the misprediction of the `jbe` branch at line 12, which caused the speculative execution of the memory access at line 17, and which in turn leaked the value of `rdi`.

If we want to further increase our confidence, we can manually inspect the contents of the inputs at the address `0x2028` to see if the values correspond to the cache set ID that we observe in the hardware traces. This can be done by running the `hexdump` command on the input files:

```bash
$ hexdump -C ./inputs/min_input_0001.bin | grep 2020
00002020  00 00 00 00 00 00 00 00  1e 1c 4a 00 1e 1c 4a 00  |..........J...J.|
$ hexdump -C ./inputs/min_input_0011.bin | grep 2020
00002020  00 00 00 00 00 00 00 00  c8 13 58 00 c8 13 58 00  |..........X...X.|
```

The values are `0x4a1c1e004a1c1e` for input #1 and `0x5813c8005813c8` for input #11. These are masked with `0b1111111111000` by `and` at line 16 and become `7192` and `5064` respectively. If we translate these values to cache set IDs (`id = (addr % 0x1000) // 64`), we get `48` and `15`. These values match the cache set IDs that we observed in the hardware traces, which confirms our hypothesis.

If we want even more confidence, we can manually modify the input files (e.g, with `hexedit` tool) to see if the hardware traces change when we modify the value of `rdi` in the input files.


---

## Modify the Program

In many cases, the minimization process will not provide a clear result as in the example above and you will not be able to make a specific hypothesis about the root cause of the violation. In such cases, you can try to modify the program in various ways to see if the violation still occurs. There are no strict rules on which modifications to make and you will have to rely on your intuition and knowledge of the target microarchitecture, but here are some general guidelines:

1. **Simplify Instructions**: Start by trying to manually replace instructions in `minimized.asm` with simpler ones. For example, replace complex instructions with memory operands with simple loads or stores.
2. **Increase/Decrease Aliasing**: Try to change the addresses of memory accesses to match (or not match if they already do) the addresses of other instruction. Such aliasing often triggers speculation (e.g., in Speculative Store Bypass or MDS attacks).
3. **Add/Remove Dependent Instructions**: If you have a hypothesis about which instruction triggers speculation, try adding or removing data-dependent instructions before it. This will change the size of the speculative window and might change hardware traces, which will give you more insight into the violation.
4. **Change Memory Permissions**: If the violation is related to memory accesses, try changing the permissions of the memory regions that are accessed by the program. For example, if the memory is read-only, try changing it to read-write. If the violation disappears, it might indicate that the violation is related to the permission checks in the CPU.
5. **Change Instruction Operands**: Try changing operands to add or remove data dependencies between instructions. For example, if you have a sequence of two moves `mov rax, [rax]; mov rbx, [rax]`, try changing the second move to `mov rbx, [rbx]` to see if the violation still occurs if there are no data dependencies between the instructions.

After each modification, run the `reproduce` command to see if the violation still occurs:

```bash
rvzr reproduce -s base.json -c ./violation-<timestamp>/reproduce.yaml \
    -t modified.asm -i ./inputs/min_input*.bin
```


!!! tip "Share Your Findings"
    If you find any other strategies that work well, please consider sharing them by opening a pull request to this documentation. We would love to hear about your experiences and learn from them.


## See Also

- [How to Interpret Violation Results](interpret-results.md) - Understanding and validating violations before root-cause analysis
- [How to Minimize Test Cases](minimize.md) - Complete minimization workflow and pass descriptions
- [Minimization Passes](../ref/minimization-passes.md) - Reference documentation for all minimization passes
- [Configuration Options](../ref/config.md) - Configuration parameters for reproduction and minimization
- [Command-Line Interface](../ref/cli.md) - Complete CLI reference for all execution modes
- [Sandbox Memory Layout](../ref/sandbox.md) - Understanding input file structure and register initialization
- [Trace Analysis and Violation Detection](../topics/trace-analysis.md) - How Revizor detects violations
- [Contracts and Leakage Models](../topics/contracts.md) - Understanding contract semantics
