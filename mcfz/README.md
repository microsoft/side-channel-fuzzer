# Software Leakage Fuzzer

Note: This module is at the experimental stage of development and its interfaces
        may (and likely will) change in the future.

This module leverages a leakage model to detect side-channel information leaks
in software binaries. The leakage model is the same one as used by the hardware fuzzer,
and it is assumed to be already tested against the target CPU. The software fuzzer uses
this model to collect contract traces for the target binary.

The software fuzzer takes as input a target binary and a grammar describing the format of
the binary's inputs. The grammar must specify which parts of the input are public and which
are private.
FIXME: the current prototype doesn't actually use a grammar, but instead assumes
that the target binary takes two files as input: one for public data and one for private data.

The goal of the software fuzzer is to identify cases where contract traces depend on
the private data, which is a sign of information leakage. To this end, the fuzzer checks
traces for the non-interference property: if two executions of the binary with different
private values but identical public data produce different traces, then the binary is
leaking information.

The fuzzer operates in four stages:

## Stage 1: Fuzzing-based Input Generation

The fuzzer uses AFL++ to generate a diverse set of inputs (containing both public and secret data)
that cover a wide range of execution paths in the target binary.

Example:
```
./mcfz.py fuzz_gen -c config.yaml -t 60 -- /usr/bin/openssl enc -e -aes256 -out enc.bin -in @@ -pbkdf2 -pass @#
```

## Stage 2: Boosting

The second stage takes each input generated during the fuzzing stage and creates public-equivalent
variants. Each variant contains the same public data as the original input, but with randomly
generated secret values. This creates equivalence classes for non-interference testing.

Example:
```
./mcfz.py boost -c config.yaml
```

## Stage 3: Tracing

The third stage collects contract traces for each input using the DynamoRIO-based leakage model
backend of Revizor (see `rvzr/model_dynamorio/backend`).

Example:
```
./mcfz.py trace -c config.yaml -- /usr/bin/openssl enc -e -aes256 -out enc.bin -in @@ -pbkdf2 -pass @#
```

## Stage 4: Leakage Analysis & Reporting

The final stage analyzes the traces collected in the previous stage to detect violations of
non-interference and reports any information leaks.

Example:
```
./mcfz.py report -c config.yaml -b /usr/bin/openssl
```


## Complete Example

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

./mcfz.py fuzz_gen -c dbg/mcfz.yaml -t 30 -- ~/openssl/openssl-driver -d @@ -p policy.txt
./mcfz.py boost -c dbg/mcfz.yaml
./mcfz.py trace -c dbg/mcfz.yaml -- ~/openssl/openssl-driver -d @@ -p policy.txt
./mcfz.py report -c dbg/mcfz.yaml -b ~/openssl/openssl-driver
```
