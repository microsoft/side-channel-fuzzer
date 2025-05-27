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

The fuzzer operates in three stages:

## THE BELOW IS NOT YET IMPLEMENTED (SEE "ACTUAL EXAMPLE" BELOW)

## Stage 1: Public Input Generation

The fuzzer uses AFL++ to generate a set of public inputs that cover a wide range of execution paths
in the target binary.

Example:
```
./consfuzz.py pub_gen -c config.yaml -w ~/consfuzz-results/ -t 60 --target-cov 5 -- /usr/bin/openssl enc -e -aes256 -out enc.bin -in @@ -pbkdf2 -pass @#
```

## Stage 2: [NAME TBD]

The second stage combines generation of secret inputs (fully random) and tracing of the binary.
The tracing is done for each pair of public and secret inputs, and the traces are
collected in a directory. The underlying tracing engine is the DynamoRIO-based backend of Revizor
(see `rvzr/model_dynamorio/backend`).

Example:
```
./consfuzz.py stage2 -c config.yaml -w ~/consfuzz-results/ -n 10 -- /usr/bin/openssl enc -e -aes256 -out enc.bin -in @@ -pbkdf2 -pass @#
```

## Stage 3: Leakage Analysis & Reporting

The third stage analyzes the traces collected in the previous stage and reports
the results.

Example:
```
./consfuzz.py report -c  config.yaml -w ~/consfuzz-results/ -b /usr/bin/openssl
```


## ACTUAL EXAMPLE

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

./consfuzz.py pub_gen -c dbg/consfuzz.yaml -w ~/results/ -t 10 --target-cov 50 -- ~/eval-rvzr-sw/drivers/bearssl/bearssl -k @# -i ~/eval-rvzr-sw/drivers/bearssl/test/iv.bin -o enc.bin @@
./consfuzz.py stage2 -c dbg/consfuzz.yaml -w ~/results/ -n 2 -- ~/eval-rvzr-sw/drivers/bearssl/bearssl -k @# -i ~/eval-rvzr-sw/drivers/bearssl/test/iv.bin -o enc.bin @@
./consfuzz.py report -c dbg/consfuzz.yaml -w ~/results -b ~/eval-rvzr-sw/drivers/bearssl/bearssl
```
