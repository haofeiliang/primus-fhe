# Performance decisions and measurements

English | [简体中文](README.zh_CN.md)

Current APIs and contracts are in the [development guide](../development/README.md). This directory preserves performance decisions, costs and historical evidence. Each report records its revision, parameters and measured scope; historical results are not current validation or security guarantees. The TFHE benchmark suite and report tools have been removed. Run historical commands only at the corresponding source revision; the last complete suite is available at `8d7c4b1a`. Future benchmarks belong to the backend or LUT crate.

## Retained choices and limits

| Topic | Decision and evidence |
| --- | --- |
| Coefficient arithmetic | Retain NTRU pairs, bounded NTT pairs, GLWE u64 grouped accumulation and compact bucket reduction, and NTRU Fourier u64 four-way accumulation within their documented bounds. See [arithmetic](sparse-arithmetic.md), especially the recorded [grouped/reduction](sparse-arithmetic.md#grouped-ntt-reassessment) and [Fourier](sparse-arithmetic.md#fourier-four-way-reassessment) reassessments. Do not add gains measured against different baselines. |
| Fourier first-product write | Keep clear-then-accumulate. F1 improves binary PBS and classic CBS in measured profiles, but sparse CBS and process variability prevent global acceptance. The [final comparison](fourier-first-write.md) summarizes the corrected 108-process comparison and retains all 54 paired results. |
| Layout and batching | Retain the internal paired NTRU LUT blind rotation. Aggregation tiles, first-bucket specialization, streaming products and GLWE tile-major keys did not justify adoption in the tested workloads. See [layout and batching](sparse-layout-and-batching.md). |
| Parameters | GLWE NTT replica/bucket and decomposition candidates are scoped to validated consumers; defaults remain unchanged. PBS success alone does not validate CBS output scales. See the three [parameter reports](#evidence-index). |
| Shared projection | The first-level prototype was withdrawn: the small complete-request gain did not justify storage, API and error-contract costs. The [study](shared-projection-analysis.md) retains the derivation and negative result. |
| Workspace storage | Reuse across requests and sharing addresses across stages are separate choices. Keep role-specific buffers where warranted; neither less memory nor equal buffer shapes proves faster execution. See [workspace measurements](workspace-measurements.md) and the [sparse scratch comparison](sparse-baseline.md#aggregate-scratch-address-comparison). |
| Paper comparison | Algorithm 2, OpenFHE and HEXL measurements have explicit adaptation boundaries. Absolute timings do not establish equivalence to the authors' unavailable sparse implementation. See [paper comparison](sparse-paper-comparison.md). |

## Evidence index

| Report | What it answers |
| --- | --- |
| [Benchmark schema 2](tfhe-benchmark-schema2.md) | Centralized runner/report validation: six workloads, three serial processes each, CPU 4 only |
| [TFHE baseline](tfhe-baseline.md) | Benchmark coverage, setup, alignment and container measurements from the earlier cleanup |
| [Fourier first-product write](fourier-first-write.md) | Final F0/F1 full-request comparison, resource costs, build validation and the decision to retain F0 |
| [Preparation and workspace measurements](workspace-measurements.md) | NTT construction, NTRU/RNS key-set preparation, borrowed resources, parameter sharing, return buffers and storage costs |
| [Sparse baseline](sparse-baseline.md) | Complete requests, stage diagnosis, retained/peak heap and aggregate scratch |
| [Sparse arithmetic](sparse-arithmetic.md) | Pair/four-way accumulation, lazy ranges and compact reduction |
| [Sparse layout and batching](sparse-layout-and-batching.md) | Tiles, first buckets, streaming, source layout and paired LUT rotations |
| [Paper comparison](sparse-paper-comparison.md) | Parameter/operation alignment, OpenFHE, expanded storage and HEXL |
| [Replica and bucket parameters](sparse-parameter-measurements.md) | Matching, retry distributions, memory and fixed-basis candidates |
| [Decomposition parameters](sparse-decomposition-measurements.md) | Role-specific error budgets and finite candidate screening |
| [Consumer validation](sparse-consumer-measurements.md) | PBS/ManyLUT/MVB, feedback and CBS→CMux, including rejected scales |
| [Shared projection](shared-projection-analysis.md) | Reverse-trace cost, arbitrary-tail errors and the withdrawn prototype |

## Measurement method

1. Fix the comparison boundary: source revision, machine/CPU, toolchain, features,
   parameters and complete operation. Arithmetic/layout experiments preserve the
   logical keys, public bucket graph, input and LUT. Parameter studies separately
   explain matching, error and material differences.
2. Build and save both versions before sampling. Time one named workload per
   iteration into prepared buffers; keep unrelated setup, allocation, validation
   and diagnostic probes outside timing. Report construction cost separately
   when the candidate changes it.
3. Alternate versions in independent processes on fixed CPUs. Record sample,
   warmup and measurement settings plus benchmark IDs. Retain controls, adverse
   observations and confirmation runs; a Criterion interval from one process
   does not cover process-to-process variation.
4. Verify mathematical equivalence with independent oracles or exact captures
   where applicable. Decryption alone is insufficient when gadget consumers
   require every output scale. Record tested and untested paths explicitly.
5. Decide using reproducible **complete-request** gains together with numerical
   bounds, retained/peak storage, code size, API and maintenance costs. A stage
   speedup or smaller allocation count alone is insufficient. There is no blanket
   percentage threshold; state why the concrete tradeoff is worthwhile.

The historical CPU 4/8 runs use two cache groups on the **same** Ryzen 9 9955HX3D
machine (96 MiB and 32 MiB L3 respectively), not two independent platforms.
Small gains on one group and losses on the other are mixed evidence, not proof
of a universal regression or a cache-writeback cause. Preserve unchanged-path
controls and confirmation runs; do not attribute their movement to a kernel
they do not execute. A decision not to adopt a prototype can reflect insufficient
repeatable benefit relative to storage and maintenance costs, even when some
means improve. The retained arithmetic decisions keep the narrower workload
and numerical bounds in their linked reassessments.

Counters measure their stated scope: allocation traffic is not retained heap or
peak, requested heap is not RSS, and wall time alone does not identify cache
writeback or bandwidth. Keep stage probes separate from acceptance timings.
Report-specific commands, seeds, parameters and limits remain beside the results.
Validation commands and ordinary CI belong in the [testing guide](../development/testing.md).

## Data and tools

Raw measurement tables live in [data/](data/); the linked report defines each
CSV's columns and comparison. The independent [projection oracle](tools/shared_projection_oracle.py)
is explained in the [projection study](shared-projection-analysis.md#oracle-与进入原型的条件).
Keep these evidence assets with their report, without retaining temporary
candidate implementations or adding experiments to ordinary CI.

Extend the relevant topic report when revisiting a decision; keep stage progress
and local implementation plans out of this directory. Public contracts remain in
rustdoc/README, and local algorithm reasons remain beside the implementation.
