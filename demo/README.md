This directory contains a set of demo configurations for fuzzing various known CPU vulnerabilities using Revizor.
Each config here is intentionally made to detect only one type of vulnerabilities.

For example, if you fuzz an Intel CPU with `detect-v1.yaml`, you will likely detect an instance of Spectre V1.
(of course, there is always a chance that you will find a new previously-unknown vulnerability with this config, but the likelihood is rather low).

The commands below assume that the ISA spec (downloaded via `rvzr download_spec`) is stored in `base.json`.

## [Spectre V1](https://meltdownattack.com/)

```
rvzr fuzz -s base.json -c demo/detect-v1.yaml -i 50 -n 10000
```
Expected duration - several seconds.

## Spectre V1 (store variant)

```
rvzr fuzz -s base.json -c demo/detect-v1-store.yaml -i 50 -n 10000
```
Expected duration - several seconds.

## Spectre V1-Var ([description](https://dl.acm.org/doi/10.1145/3503222.3507729) and [here](https://eprint.iacr.org/2022/715.pdf))

```
rvzr fuzz -s base.json -c demo/detect-v1-var.yaml -i 50 -n 10000
```
Expected duration - several hours.

## [MDS](https://mdsattacks.com/) or [LVI-Null](https://lviattack.eu/), depending on the CPU model

Note: only Intel CPUs.

```
rvzr fuzz -s base.json -c demo/detect-mds.yaml -i 50 -n 10000
```
Expected duration - several minutes.

## Spectre V4 ([description](https://www.cyberus-technology.de/posts/2018-05-22-intel-store-load-spectre-vulnerability.html))
```
rvzr fuzz -s base.json -c demo/detect-v4.yaml -i 50 -n 10000
```
Expected duration - 5-20 minutes.

## Zero Divisor Injection (ZDI)

Note: only Intel CPUs.

```
rvzr fuzz -s base.json -c demo/detect-zdi.yaml -i 50 -n 10000
```
Expected duration - several minutes.

## String Comparison Overrun (SCO)

```
rvzr fuzz -s base.json -c demo/detect-sco.yaml -i 50 -n 10000
```
Expected duration - several minutes.

## Foreshadow (simplified version)

Note: only Intel CPUs.

```
rvzr fuzz -s base.json -c demo/detect-foreshadow.yaml -i 50 -n 10000
```
Expected duration - several minutes.

## Transient Scheduler Attack, Store Queue variant (TSA-SQ)

Note: only AMD CPUs vulnerable to TSA.

```
rvzr tfuzz -s base.json -c demo/tsa-sq/config.yaml -t demo/tsa-sq/template.asm -i 50 -n 10000
```
Expected duration - several minutes.

## Transient Scheduler Attack, L1D Cache variant (TSA-L1D)

Note: only AMD CPUs vulnerable to TSA.

```
rvzr tfuzz -s base.json -c demo/tsa-l1d/config.yaml -t demo/tsa-l1d/template.asm -i 50 -n 10000
``
Expected duration - several minutes.
