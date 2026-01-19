# Primer: Speculation Contracts and Model-Based Relational Testing

Below is a brief primer on the theoretical foundations of speculation contracts and model-based relational testing—concepts that underlie the Revizor tool. This primer provides a high-level overview of the topic, introducing the concepts of noninterference, speculation contracts, and model compliance.

This document is intended for those new to the topic, particularly people without a background in information-flow analysis. For a more detailed and technical explanation, refer to the [original contracts paper](https://arxiv.org/pdf/2006.03841).

## Information-Flow Properties

We will start with the basics: the concepts of confidentiality and
[noninterference](../glossary.md#noninterference), which are fundamental to understanding how
[speculation contracts](../glossary.md#speculation-contract-aka-leakage-contract) work.

Traditionally, security mechanisms like access control and encryption have focused on protecting
data at rest or in transit. However, these mechanisms do not address the problem of
[**information flow**](../glossary.md#information-flow) within a system.
For example, consider a program that reads a secret input and then writes it to a public output, such as a web server that logs failed login attempts along with the username and masked password entered. Even if the program is secure in the sense that it does not allow unauthorized access to the secret data, it may still leak the secret through its public output, such as logging "User admin failed login with password starting with 'P@ss'" — revealing partial information about the secret password. This is where **information-flow security** comes into play.

Information-flow security is concerned with how data moves through a computation and how it can be observed by an attacker. The goal is to ensure that secret information does not leak to observers who are unauthorized to access it. An **end-to-end confidentiality policy** might be stated as: *“No secret input data can be inferred by an attacker through observations of system output.”* In other words, even if an adversary can see all public outputs of a computation, they should learn nothing about the secret inputs.

**Information-flow properties** generally classify program variables or inputs/outputs into security levels (e.g., `Secret` and `Public`). The key property for confidentiality is that *no information flows from Secret to Public.* But how can information flow? There are two primary routes:

- **Explicit flows:** These occur when confidential data is directly assigned or passed into a public variable or output. For example, in code, writing `public = secret` is an explicit flow from a secret variable to a public variable (an obvious violation of confidentiality). Any mechanism that directly transfers the bits of a secret into a publicly observable sink is an explicit flow. Such flows are usually straightforward to detect.

- **Implicit flows:** These occur indirectly, through the control structure of the program. An implicit flow arises when the *control path* taken by a program (e.g., which branch of an `if` or how many loop iterations) depends on a secret, thereby implicitly leaking information.

=== "Example 1: Implicit Flow"

:   Consider this pseudocode example:

    ```c
    if (Sec == 0) {
        Pub = 0;
    } else {
        Pub = 1;
    }
    ```

    Here `Sec` is a secret input and `Pub` is a public output. There is no direct assignment of `Sec` to `Pub`. However, an observer of `Pub` can deduce information about `Sec`. In fact, this program sets `Pub` to 0 if `Sec` was 0; otherwise, it sets `Pub` to 1—effectively copying the one-bit information “is Sec zero?” into `Pub`. This is an implicit flow of information from `Sec` to `Pub` through the control structure (the `if` condition on `Sec`).


## Noninterference: Definition and Examples

**Noninterference** is a formal property that captures the idea of perfect confidentiality: changes in secret data have *no observable effect* on public outputs. This property can be formalized as: *"a system is noninterferent if variations in Secret inputs cause no differences in Public outputs"*. Equivalently, confidential inputs do not interfere with the publicly visible state of the system.

To make this more concrete, imagine we run a program twice with two different secret inputs but the same public inputs. If **no attacker can distinguish** the two runs by observing anything public, then the program satisfies the noninterference property. The “attacker” here is assumed to have complete access to all public outputs, which are formalized as a function `PublicOut`:

```
output = PublicOut(Sec, Pub)
```

Noninterference essentially demands that for any two secrets `Sec1` and `Sec2` and any public input `Pub`, the program’s behavior from an attacker’s perspective is identical when run on `(Sec1, Pub)` versus `(Sec2, Pub)`:

=== "Definition 1: Noninterference"
:   A program `P` is noninterferent if, for all<br>public inputs `Pub` and all pairs of secret inputs `Sec1`, `Sec2` it holds that <br>`PublicOut(P, Sec1, Pub) = PublicOut(P, Sec2, Pub)`.

Here are some examples to illustrate this principle:

=== "Example 2: Interfering program"

:   Suppose our program simply copies a secret to output:

    ```c
    void copy(int* sec, int* output) {
        *output = *sec;
    }
    ```

:    Running it with two different secrets clearly yields different public outputs (e.g., `output` becomes 5 in one run and 7 in another). An attacker would distinguish these runs, so the program is **not** noninterferent—it blatantly leaks information.

---

=== "Example 3: Noninterfering program"

:   A trivial example of a noninterferent program is one that produces no output dependent on the secret. For instance:

    ```c
    void assign_zero(int* sec, int* output) {
        *output = 0;
    }
    ```

:    This program ignores secret `sec` entirely and always sets the public output `output` to 0. No matter what the secret input is, the public output is constant (0), so an attacker gains no information about `sec`. Indeed, any two runs are indistinguishable (both runs output 0). This satisfies noninterference (albeit by doing nothing useful with the secret).

---

=== "Example 4: Allowed benign dependency"

:   It is possible for a program to use secret data internally yet still be noninterferent as long as the final public outputs don’t reveal those secrets. For instance:

    ```c
    void mask_secret(int* sec, int* output) {
        int temp = *sec;
        temp = temp * 0;   // multiply secret by 0
        *output  = temp;
    }
    ```

:    Here the program *did* read the secret (`sec`) and even manipulated it, but it “washed out” the secret by multiplying by 0. The value assigned to `output` is always 0. From an external view, this is just like the previous example—no dependence of `output` on `sec`. Noninterference is concerned only with *what can be observed by the attacker*, not with whether the program internally used the secret. As long as any use of the secret eventually has no effect on outputs, the policy holds.

:   Naturally, this example is not useful either, as it does nothing with the secret. In practice, however, there are techniques to ensure noninterference while still making use of secret data for useful computations. We won't go into these techniques here as they are beyond the scope of this primer.

---

One important insight is that noninterference is relative to a given specification of what is “observable.” If you consider only the functional outputs as observable, a program might be noninterferent in that model. But if in reality the attacker can observe more (e.g., the execution time of a program), then the program that was secure in theory might be insecure in practice. This leads us to examine how *side channels* break the assumptions of basic noninterference.

## Beyond Direct Outputs: Side Channels

The original works on information-flow properties focused on direct outputs of a program (e.g., writing to a file or a network socket). However, in practice, attackers can extract information from more than just the “official” outputs of a program. For example, the attacker might observe how long a computation takes or measure the power consumption of a device. These additional sources of information are called **side channels**. Side channels are unintended channels through which secret data can be inferred by observing the system’s behavior, even if the direct outputs are secure.

These side channels can reveal information about the secret inputs, and so we must include them in the definition of noninterference. Similarly to how we defined `PublicOut(Sec, Pub)` as the observable output, we can define `Trace` as the observable side-channel information for a given program `P`.

```
trace = Trace(P, Sec, Pub)
```

For example, a trace might be the execution time of the program or its cache access pattern.

Noninterference then requires that the traces of two runs with different secrets - `(Sec1, Pub)` versus `(Sec2, Pub)` - are indistinguishable to an attacker. This is a stronger requirement than just looking at the functional outputs.

=== "Definition 2: Side-Channel Noninterference"
:   Given a side channel that produces a trace `Trace`, a program `P` is noninterferent with respect to this side channel if, for all public inputs&nbsp;`Pub` and all pairs of secret inputs `Sec1`, `Sec2` it holds that <br>`Trace(P, Sec1, Pub) = Trace(P, Sec2, Pub)`.

Here are some examples of side channels and how they can violate noninterference:

=== "Example 5A: Timing side channel"

:   Consider a program that reads a compares a password with a user’s input:

    ```c
    bool check_password(const char *attempt, const char *pswd) {
        for (int i = 0; i < length(pswd); i++) {
            if (attempt[i] != pswd[i]) {
                return false;  // mismatch found, return early
            }
        }
        return true; // all characters matched
    }
    ```

:   If the attacker can measure how long the function takes to reject a guess, they can infer the password one character at a time. This leakage surfaces as a violation of the noninterference property with respect to timing observations.

:   A counterexample to Definition 2 could be as follows: Let's say we use the same input on two different secrets:

:   - `input1={attempt="aaa", pswd="abc"}`
:   - `input2={attempt="aaa", pswd="aab"}`

:   The traces of these inputs will be:

:   - `trace1 = Trace(check_password, input1) = 1`
:   - `trace2 = Trace(check_password, input2) = 2`

:   These inputs constitute a violation of Definition 2, as `trace1 != trace2` even though the two inputs have the same public values.

---

=== "Example 5B: Timing side channel - Password length"

:   Noninterference is able to model different kinds of secret-dependent leaks. Let's take for example a patched version of the previous program:

    ```c
    bool check_password(const char *attempt, const char *pswd) {
        int len = min(length(attempt), length(pswd));
        bool same = true;
        for (int i = 0; i < len; i++) {
            same = same && (attempt[i] == pswd[i]); // all the loop is executed
        }
        return same;
    }
    ```

:   In this version there is no early-exit condition, yet the attacker is still able to infer the _length_ of the password through a side-channel. This is captured by the following counterexample:

:   - `input1={attempt="aaaaaa", pswd="b"}`, `trace1 = 1`
:   - `input2={attempt="aaaaaa", pswd="bbb"}`, `trace2 = 3`

:   Which shows that the program still violates Definition 2.

---

=== "Example 6: Cache side channel"

:   Consider a program that uses a secret value to index into an array, as in the following code:

    ```c
    int multiply(const char *array, int pub, int sec) {
        char x = array[sec];
        return x * pub;
    }
    ```

:   A co-located attacker could observe the cache access pattern of the program by using Prime+Probe or Flush+Reload attack. Such traces can reveal the addresses accessed by the program and thus leak the secret value. This leakage would violate the noninterference property with respect to cache observations.

:   A violation could be surfaced by two inputs:

:   - `input1={array=0x10000, pub=1, sec=0x40}`
:   - `input2={array=0x10000, pub=1, sec=0x80}`

:   Let's assume that the cache line size is 64 bytes, and the cache is direct-mapped, meaning that the cache line ID is based on the memory access address `addr` as `line_id = (addr % 0x1000) // 0x40`. Since the array access in the first line of `multiply` will access two different addresses for the two inputs, they will also produce two different traces:

:   - `trace1 = Trace(multiply, input1) = ((0x10000 + 0x40) % 0x1000) // 0x40 = 1`
:   - `trace2 = Trace(multiply, input2) = ((0x10000 + 0x80) % 0x1000) // 0x40 = 2`

:   Since we have two inputs that match on the secret value `sec` but differ on the cache trace, this constitutes a violation of Definition 2.

## Challenges of Side-Channel Noninterference

Despite its completeness, the above formalization of side-channel noninterference is too simplistic to faithfully capture the side effects of program execution on modern, highly optimized hardware, especially CPUs. There are two key challenges:

- *Challenge 1 - Noisy and Non-Deterministic Traces*: The traces observed by the attacker over a side channel are typically noisy, non-deterministic, and depend on the microarchitectural state of the CPU. For example, cache access patterns can be influenced by other programs running on the machine, the operating system and its interrupts, and can depend on microarchitectural buffers like store buffers or branch history tables. This means that the `Trace` function is not a simple deterministic function of the program inputs, but a complex function of many factors, some of which affect the result concurrently and in a non-deterministic fashion.

- *Challenge 2 - Unknown Side Channels*: Modern CPUs have a plethora of side channels, including cache timing, branch prediction, and many others. To ensure complete confidentiality, we need to check that the program does not leak information over *any* of them. This is a challenging task, as we do not know the full set of possible side channels when it comes to commercial hardware with proprietary microarchitectures. For example, a CPU might have an obscure microarchitectural optimization that vastly expands possibilities for information leaks, as was the case with Spectre and Meltdown vulnerabilities. Not including this optimization will undermine the noninterference analysis. Therefore, to test for noninterference comprehensively, we need a way to discover and reason about all possible side channels that could leak information.

The next two sections discuss how speculation contracts address these challenges.

## Speculation Contracts: Dealing with the Complexity of Modern Hardware

As a solution to the first challenge, Guarnieri et al. (2021) introduced the concept of **speculation contracts**. A speculation contract is a simplified and deterministic model of the hardware, designed to capture the information that a given program *could* leak over side channels when executed with the given inputs. The key term here is "could"—the contract is not meant to exactly predict the side-channel traces, but instead, it errs on the side of caution, overestimating the possible leaks to achieve deterministic and noise-free traces.

A speculation contract works by defining two key aspects for every instruction in the CPU's ISA:

1. [**Observation Clause**](../glossary.md#observation-clause): For each instruction that may have
an observable side effect, the contract declares an observation clause. It describes the data
exposed by the instruction.

2. [**Execution Clause**](../glossary.md#execution-clause): For each instruction whose semantics
may be affected by hardware optimizations (e.g., speculative execution), the contract declares an
execution clause. It describes the effect of such optimizations, but without specifying the exact
mechanism of the optimization.

At a high level, a contract implements a function `ContractTrace` that maps a program `P` and its
inputs `Sec, Pub` to a [contract trace](../glossary.md#contract-trace-ctrace) `ctrace`. It is
essentially a conservative approximation of the `Trace` function.

```
ctrace = ContractTrace(P, Sec, Pub)
```

The contract trace is a sequence of all data that is exposed when a program is executed according
to a contract. It captures the side-channel observations that *could be visible* if the CPU
followed the speculation contract's rules for a given program execution.

Accordingly, the noninterference property is redefined in terms of the contract trace:

=== "Definition 3: Contract Noninterference"

:   Given a contract that produces a contract trace&nbsp;`ContractTrace`, a program `P` is noninterferent with respect to this contract if,<br>for all public inputs&nbsp;`Pub` and all secret inputs `Sec1`, `Sec2`, it holds that <br>`ContractTrace(P, Sec1, Pub) = ContractTrace(P, Sec2, Pub)`.

The following examples illustrate how a contract can be used to model side-channel leaks on a CPU.

=== "Example 7: Memory Observation Contract, MEM-SEQ"

:   Let's imagine a CPU with a shared data cache and no other optimizations (i.e., no speculation). A co-located attacker can recover the addresses of loads/stores by observing which of the cache sets changed their state via a cache timing side-channel attack (e.g., Prime+Probe). We can encode these expectations in an observation clause for loads and stores by specifying that they expose their address. Since the CPU does not speculate, the execution clause for all instructions is empty. We call this contract MEM-SEQ (memory leakage with sequential execution), and it can be summarized as a table:

    |       | Observation Clause | Execution Clause |
    | ----- | ------------------ | ---------------- |
    | Load  | Expose Address     | -                |
    | Store | Expose Address     | -                |
    | Other | -                  | -                |

:   Note that MEM-SEQ intentionally overestimates the leaks by assuming that the attacker observes complete addresses loads/stores (in contrast to a subset of bits that are actually leaked in practice) and that *all* loads/stores are observable (in reality, they might be masked by noise or other factors). This overestimation is intentional to ensure that the contract is conservative and captures all possible corner cases.

:   Let's now consider how we can produce a contract trace using MEM-SEQ. We will use a slightly modified version of the `multiply` function from Example 6:

    ```c
    int multiply(const char *array, int pub, int sec) {
        char x = array[sec];   // MEM-SEQ exposes: &array[sec]
        char y = array[pub];   // MEM-SEQ exposes: &array[pub]
        return x * y;
    }
    ```

:   The inputs are:

:   - `input1 = {array=0x10000, pub=1, sec=2}`
:   - `input2 = {array=0x10000, pub=1, sec=3}`

:   The model collects a trace by executing the program line-by-line according to the rules in the table above (in practice, this is usually done using a modified CPU emulator). The first line has a load from memory, so the model records the address `&array[sec]` as exposed. The second line has another load, so the model records the address `&array[pub]` as exposed. The contract traces for this program would be:

:   - `ctrace1 = ContractTrace(multiply, input1) = [0x10002, 0x10001]`
:   - `ctrace2 = ContractTrace(multiply, input2) = [0x10003, 0x10001]`

:   Finally, this model can be used to check for noninterference by comparing contract traces according to Definition 3. In this case, we have two inputs with matching public values and different secrets, and they produced different contract traces, `ctrace1 != ctrace2`. This constitutes a violation and means that the `multiply` function is not noninterferent with respect to MEM-SEQ.

---

=== "Example 8: Branch Prediction Contract, MEM-COND"

:   Now let's consider a more complex scenario, with a CPU that implements branch prediction—a common form of speculative execution. In this case, the CPU may incorrectly predict branch targets and execute instructions that are not part of the correct control flow. We can model this behavior in a contract by introducing an execution clause for conditional jumps that specifies the mispredicted target. To make the example useful, we will assume that the CPU also has a data cache, so the observation clause for loads and stores remains the same as in MEM-SEQ. We call this contract MEM-COND (memory leakage with conditional branch misprediction).

    |            | Observation Clause | Execution Clause  |
    |------------|--------------------|-------------------|
    | Load       | Expose Address     | -                 |
    | Store      | Expose Address     | -                 |
    | Cond. Jump | -                  | Mispredict Target |
    | Other      | -                  | -                 |

:   As a target program we will use the following function:

    ```c
    int conditional_multiply(char *array, int pub, int sec) {
        int z = array[pub];   // MEM-COND exposes: &array[pub]
        if (z < 10) {         // MEM-COND mispredicts (assume z = 10)
            z *= array[sec];  // MEM-COND exposes: &array[sec]
        }
        return z;
    }
    ```

:   and a pair of inputs with the same public value but different secrets:

:   - `input1 = {array=0x10000, pub=1, secret=2}`
:   - `input2 = {array=0x10000, pub=1, secret=3}`

:   The first line of `conditional_multiply` has a load, so it exposes its address, `&array[pub]`. For the sake of this example, let's assume this load returns `10`, so the next branch is not supposed to be taken. However, according to MEM-COND, branches take the wrong target, so the model executes the third line anyway. This line is a load, so it exposes the address `&array[sec]`. After this, the program terminates, and the resulting traces are:

:   - `ctrace1 = ContractTrace(conditional_multiply, input1) = [0x10002, 0x10001]`
:   - `ctrace2 = ContractTrace(conditional_multiply, input2) = [0x10003, 0x10001]`

:   Again, the traces are different, so the program violates noninterference with respect to MEM-COND.
:   Notably, however, these two inputs would *not* violate noninterference with respect to MEM-SEQ, as the branch at line 2 would not be mispredicted, and the traces would be identical:

:    `ctrace_mem_seq1 = ctrace_mem_seq2 = [0x10001]`

## Building and Testing Speculation Contracts

Speculation contracts are typically built by hand, with the initial versions based on public knowledge of the CPU's microarchitecture and its side-channel vulnerabilities. However, in the case of commercial CPUs, the exact details of the microarchitecture are often proprietary and not publicly disclosed. In these cases, the contract could—and often will—be incomplete. This is where the testing of speculation contracts becomes crucial: the initial "draft" of a contract is tested against the real hardware to ensure that it captures all side-channel leaks that the CPU exhibits. If the contract misses something, it is refined based on the results of the testing, and the process is repeated until the contract is deemed safe to use.

But how do we test a speculation contract? A naive approach might be to directly compare the traces produced by the model with the traces collected from the real CPU for the same program and inputs. However, this approach is generally not feasible because the contract traces intentionally overestimate the hardware traces, so mismatches are expected. Moreover, the model might expose information differently than the real hardware (e.g., the model might expose load/store addresses, while the hardware exposes cache set indexes), meaning direct comparison is often impossible.

Instead, a more precise approach is to compare *the information contained in the traces*. The idea is to check that the information exposed by the model is a strict superset of the information exposed by the real hardware. This is done by verifying that all inputs producing identical contract traces for a given program also produce identical hardware traces. If this property holds for all possible programs and inputs (ignore the complexity question for now), then any program that would be noninterferent with respect to the real hardware is guaranteed to be noninterferent with respect to the speculation contract. At this point, the model is safe to use as a proxy for real hardware when analyzing side-channel leaks.

To formalize this idea, let's introduce a new function `HardwareTrace` to denote the
[hardware trace](../glossary.md#hardware-trace-htrace) collected from the real hardware, and it
will take an extra argument `Ctx` to capture the fact that real-world hardware traces depend on
the microarchitectural state (e.g., on the state of branch predictors or caches).

=== "Definition 4: [Contract Compliance](../glossary.md#contract-compliance)"

:   A CPU complies with a speculation contract if, for all programs `P`, all input pairs
`(Sec1, Pub), (Sec2, Pub)`, and all initial microarchitectural states&nbsp;`Ctx`, if
`ContractTrace(P, Sec1, Pub) = ContractTrace(P, Sec2, Pub)`, then
`HardwareTrace(P, Sec1, Pub, Ctx) = HardwareTrace(P, Sec2, Pub, Ctx)`.


and conversely

=== "Definition 5: [Contract Violation](../glossary.md#violation)"

:   A CPU violates a speculation contract if there exists a program&nbsp;`P`, a microarchitectural
state&nbsp;`Ctx`, and two inputs `(Sec1, Pub), (Sec2, Pub)` such that
`ContractTrace(P, Sec1, Pub) = ContractTrace(P, Sec2, Pub)` and <br>
`HardwareTrace(P, Sec1, Pub, Ctx) != HardwareTrace(P, Sec2, Pub, Ctx)`.

We call the tuple `(P, Ctx, Sec1, Sec2)` a
[**contract counterexample**](../glossary.md#violation-artifact-aka-contract-counterexample). The
counterexample demonstrates that an adversary can learn more information from hardware traces than
what the contract specifies. A counterexample indicates a potential microarchitectural leakage
that was not accounted for by the contract. The goal of Revizor is to find such counterexamples.

## [Model-Based Relational Testing](../glossary.md#model-based-relational-testing-mrt) and Revizor

Revizor applies the principles above, and provides a framework for building executable speculation
contracts together with a mechanism to test real hardware (currently only CPUs) against these
contracts by searching for contract counterexamples, as in Definition 5. However, there are
certain issues that appear when the theory from the previous section is applied in practice, which
we had to address in Revizor.

The first issue is the search space: testing all possible programs and inputs is literally
impossible. We mitigate this issue by relying on a sampling-based approach, similar to fuzzing,
where we approximate the complete search space via random sampling. Specifically, Revizor generates
small (50-100 instructions long) programs, creates random inputs for them, collects both the
contract and hardware traces for these inputs, and checks whether any of the traces constitute a
contract counterexample. This process is called
[*Model-based Relational Testing*](../glossary.md#model-based-relational-testing-mrt), and it is
detailed further in the [Architecture Overview](../internals/architecture/overview.md).

This approach works well in practice because any given hardware optimization can typically be triggered by many different programs, and we need to find only one instance to detect a violation. Evidence of this is the [list of trophies](https://microsoft.github.io/side-channel-fuzzer/) that Revizor has already amassed.

The second issue we encountered is nondeterminism. As mentioned earlier, hardware traces can be non-deterministic due to various factors like interrupts or other programs running on the machine. To handle this, we use statistical methods: Revizor collects hardware traces for each program-input pair multiple times and then compares their distributions. If the distributions of the traces are statistically similar, Revizor considers the traces to be equivalent. This approach helps us account for noise in the hardware traces while still making reliable decisions about contract compliance.

For more details, see [Architecture Overview](../internals/architecture/overview.md).

## Conclusion

In this primer, we have introduced the concepts of noninterference, side channels, and speculation contracts, which all underlie the design of Revizor:

- The hardware fuzzer in Revizor uses speculation contracts and the concepts of noninterference (1) to detect unexpected side channels and dangerous microarchitectural optimizations in commercial CPUs, and (2) to aid in building sound leakage models for those CPUs.
- The software fuzzer in Revizor (*NOTE: currently under construction*) uses the leakage models produced by the hardware fuzzer, and applies the principles of noninterference testing to detect side-channel vulnerabilities in real-world software.

With these two components, we aim to provide a comprehensive tool for discovering and mitigating side-channel vulnerabilities software that can handle even the most obscure and complex microarchitectural optimizations in modern hardware.

---

## Sources and Further Reading

- A. Sabelfeld and A. C. Myers. *Language-Based Information-Flow Security*. IEEE Journal on Selected Areas in Communications, 21(1), 2003. (Survey of information-flow security, implicit/explicit flows, covert channels, etc.)
- J. A. Goguen and J. Meseguer. *Security Policies and Security Models*. IEEE Symposium on Security and Privacy, 1982. (Origin of noninterference as a security policy formalism.)
- J. B. Almeida et al. *Verifying Constant-Time Implementations*. USENIX Security Symposium, 2016. (Constant-time programming principles and the ct-verif tool for automated verification.)
- M. Guarnieri, B. Köpf, J. Reineke, P. Vila. *Hardware-Software Contracts for Secure Speculation*. IEEE Symposium on Security and Privacy, 2021. (Original paper on speculation contracts.)
- O. Oleksenko, C. Fetzer, B. Köpf, M. Silberstein. *Revizor: Testing Black-box CPUs against Speculation Contracts*. ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS), 2022. (Paper describing Model-based Relational Testing and Revizor.)

