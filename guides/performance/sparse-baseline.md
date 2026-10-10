# Sparse PBS, CBS and lookup baseline

> Archive note (2026-10-10): the TFHE benchmark suite and report tools were removed. Commands and source paths below refer to historical revisions; the last complete suite is available at `8d7c4b1a`. Measurements remain evidence for their recorded versions, not current validation.

[Performance decisions and measurement method](README.md) · [Arithmetic](sparse-arithmetic.md) · [Layout and batching](sparse-layout-and-batching.md)

This baseline records the 2026-10-04 matched workloads, stage/resource diagnostics
and CPU-dependent observations. Later arithmetic and batching experiments have
their own source baselines; their percentages must not be added to these results.

## Conditions and workload pairing

AMD Ryzen 9 9955HX3D, x86_64 Linux, rustc 1.98.1 (48a229cea), LLVM 22.1.8,
release bench profile, repository `target-cpu=native`. No workspace SIMD feature;
Fourier explicitly enables `rustfft,tfhe-fft`. Transform libraries can still use
their own SIMD. Builds and timings ran separately; requests ran sequentially on
logical CPU 4. Historical rechecks also used CPU 8. CPU 4 belongs to the 96 MiB
L3 group (0–7,16–23), CPU 8 to the 32 MiB group (8–15,24–31). Neither frequency
nor other system activity was controlled; these short measurements do not isolate
cache capacity, bandwidth, instruction scheduling or scratch-address effects.

The existing `sparse_pbs` fixtures pair classic/sparse at n728/h32/N1024/t8,
three copies and 64 buckets. Both GLWE CBS benchmarks now use the same
fixed-weight `glwe::diagnostic` profile at t4, with client seed 42 and input seed
43 independent of scheme-specific server-key generation. They use identical
client coefficients, input ciphertext, codec, LUT and bases within each pair.
Their former n800 binary classic fixture was not comparable with sparse n728;
the new `n728_h32_N1024` ID prevents mixing Criterion histories. NTRU classic CBS
used n800/N1024/t4 and seed 42 in the measurements below. Current NTRU CBS/one-hot
benchmarks instead pair classic/sparse at n728/h32/N1024, with separate input RNG;
those new IDs have passed numerical smoke checks but have no timing results in this report.

Parameters come from the shared profiles (`../../benchmarks/tfhe/src/parameters/mod.rs`, historical source):
NTT Q=132120577 for u32 PBS, Q=998244353 for u32 CBS, Q=1125899906826241 for u64;
Fourier uses Native32/64. NTRU external/return q is `PowOf2(2^24)`.
Full BR bases use logB=2 (u32) or 8 (u64). GLWE KS uses the same full basis;
NTRU return KS uses logB=3/L8. GLWE accumulator sigma=6.4, NTRU sigma=0.7;
fixed-weight external sigma=3.2*q/16384, NTRU return sigma=3.2. CBS output and
trace/scheme-switch bases/noise retain `glwe::cbs` and `ntru::cbs` unchanged.

## Complete requests without instrumentation

Criterion: 15 samples, 0.3 s warmup, 1 s measurement target; one preallocated
request per iteration. Setup, keygen, input encryption, public LUT compilation,
output/workspace allocation and correctness checks are excluded. Values below
are mean point estimates in milliseconds, **classic / sparse**. Small differences
are not established speedups. Both words and FFT engines are covered; u64 covers
both GLWE orders, u32 timing retains BR→KS only. There are 54 timed request IDs.

| GLWE backend / word | Order | PBS, classic / sparse | CBS, classic / sparse |
| --- | --- | ---: | ---: |
| ntt / u32 | BR→KS | 17.506 / 21.935 | 20.695 / 26.513 |
| ntt / u64 | BR→KS | 12.700 / 16.564 | 12.993 / 16.623 |
| ntt / u64 | KS→BR | 12.468 / 16.317 | 12.995 / 16.470 |
| rustfft / u32 | BR→KS | 27.449 / 22.025 | 29.131 / 20.904 |
| rustfft / u64 | BR→KS | 16.257 / 15.916 | 14.875 / 16.175 |
| rustfft / u64 | KS→BR | 16.244 / 16.035 | 15.433 / 16.271 |
| tfhe_fft / u32 | BR→KS | 24.504 / 21.445 | 26.879 / 19.750 |
| tfhe_fft / u64 | BR→KS | 12.878 / 15.702 | 13.881 / 15.880 |
| tfhe_fft / u64 | KS→BR | 13.326 / 15.497 | 13.268 / 15.976 |

| NTRU backend / word | PBS, classic / sparse | Classic CBS, n800 |
| --- | ---: | ---: |
| ntt / u32 | 5.617 / 5.518 | 6.880 |
| ntt / u64 | 5.179 / 5.530 | 4.617 |
| rustfft / u32 | 10.933 / 8.257 | 11.398 |
| rustfft / u64 | 6.351 / 6.885 | 5.667 |
| tfhe_fft / u32 | 9.232 / 7.146 | 9.306 |
| tfhe_fft / u64 | 5.295 / 6.892 | 4.447 |

## Historical CPU-dependent regression recheck

Built `d566a73a` and current production code with the **unchanged original CBS
benchmark**, including its RNG sequence and `n728_N1024` sparse ID. Each CPU ran
current/before/before/current, 20 samples, 0.5 s warmup and 2 s measurement target.
This compares the historical baseline with current code; it is not a bisect of
the resource-migration commit. Mean milliseconds, two runs per revision:

| CPU / order | Before | Current |
| --- | ---: | ---: |
| 4 / BR→KS | 16.499 / 16.591 | 16.514 / 16.562 |
| 4 / KS→BR | 16.498 / 16.627 | 16.515 / 16.454 |
| 8 / BR→KS | 17.156 / 17.076 | 17.205 / 17.164 |
| 8 / KS→BR | 17.181 / 17.300 | 17.160 / 17.093 |

The old 3–4% CPU 4 regression did not reproduce in this comparison. This does
not explain or invalidate the [historical observation](workspace-measurements.md#glwe-ntt-borrowed-resource-measurement).
CPU groups have different absolute latency for both revisions; no scratch,
alignment or inline change follows from this result alone.

## Diagnostic stage costs

A temporary instrumented build used allocation-free thread-local `Instant`
accumulators. After the first complete request, it averaged ten individual
requests per case, with the same fixtures. All 66 PBS/CBS combinations were
checked, including u32 in both GLWE orders. Instrumentation changes code
layout and adds timestamp/TLS overhead; these numbers locate costs and must
not replace the uninstrumented complete-request times above. No overhead was
subtracted and no cross-build wall-time equality is assumed.

The following u64 rows use BR→KS for GLWE. All entries are milliseconds;
“—” denotes an absent or unseparated stage. Classic CMux/external-product
work stays inside BR; it is not zero-cost.

| Request / backend | BR incl. substages | Aggregate | Control transform | External product | Projection | Scheme switch | Return |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| glwe sparse PBS / ntt | 16.658 | 14.525 | 1.128 | 0.997 | — | — | 0.015 |
| glwe sparse PBS / rustfft | 15.800 | 13.709 | 1.027 | 1.056 | — | — | 0.014 |
| glwe sparse PBS / tfhe_fft | 17.842 | 15.933 | 0.900 | 1.001 | — | — | 0.015 |
| glwe sparse CBS / ntt | 16.338 | 14.253 | 1.100 | 0.976 | 0.226 | 0.036 | — |
| glwe sparse CBS / rustfft | 16.509 | 14.315 | 1.088 | 1.098 | 0.231 | 0.040 | — |
| glwe sparse CBS / tfhe_fft | 15.515 | 13.619 | 0.923 | 0.965 | 0.207 | 0.037 | — |
| ntru sparse PBS / ntt | 4.434 | 3.752 | 0.269 | 0.406 | — | — | 1.161 |
| ntru sparse PBS / rustfft | 5.798 | 5.084 | 0.269 | 0.438 | — | — | 1.250 |
| ntru sparse PBS / tfhe_fft | 5.705 | 5.088 | 0.213 | 0.396 | — | — | 1.234 |
| ntru classic CBS / ntt | 4.499 | — | — | — | 0.173 | 0.014 | — |
| ntru classic CBS / rustfft | 5.500 | — | — | — | 0.205 | 0.017 | — |
| ntru classic CBS / tfhe_fft | 4.455 | — | — | — | 0.161 | 0.013 | — |

Sparse u64 mask quantization took 0.30–0.96 µs. GLWE KS→BR input
preparation (inverse extraction + ring KS + compact extraction) took
12.7–15.1 µs. GLWE ordinary return groups
ring KS/extraction for BR→KS and extraction only for KS→BR; NTRU return groups
Q→q conversion, signed extraction and LWE KS. CBS does not execute ordinary return.
Classic quantization is interleaved with CMux and remains in its combined BR
measurement; sparse control transforms are not an extra stage of classic BR.

Reconstruct the temporary stage probe at these boundaries (no public scratch API):

| Phase | Measured scope |
| --- | --- |
| BR | `BootstrapResources::blind_rotate`; includes GLWE input preparation when present |
| Quantization | sparse `exponent_slice_to`; GLWE also includes body quantization, NTRU body stays in BR remainder |
| Aggregate | each bucket's metadata/split, dummy copy and all rotated selector additions |
| Control transform | completed aggregate → NTT/Fourier; sum over all 64 buckets |
| External product | each sparse aggregate product; sum over buckets, excluding subsequent buffer swaps |
| Projection | CBS `project_prefix_coefficients[_with_scratch]_to` |
| Scheme switch | CBS scheme-switch call and its resource rebind wrapper |
| Input preparation | GLWE inverse extraction through compact extraction |
| Return | GLWE `return_accumulator_to` or NTRU `return_accumulator_at_to` |

Outer BR and its nested stages overlap; **do not sum those columns**. The stage
probe and allocator wrapper were removed after recording the results.

## Source keys, retained workspace and peak accounting

The diagnostic allocator delegates unchanged to `System`. In each constructor
scope it tracks successful alloc/alloc_zeroed/realloc requests and frees on the
calling thread; retained = allocated − released. A separate live-byte counter
tracks the maximum live requested bytes within that scope. Realloc replaces the
old logical request with the new one. This is **requested live-heap peak**, not
allocator-internal transient copying, allocator overhead, RSS or total process peak.

Source bytes below are measured BR coefficient/transform-array lengths times
element size, excluding metadata, return/CBS keys and context tables. These
array sizes are storage footprints, not measured cache/DRAM traffic; classic BR
can skip public zero-exponent controls. Sparse has (3n+64) controls, GLWE classic n,
NTRU classic n+1 including the public lift initializer. GLWE uses full GGSWs;
NTRU uses one polynomial per gadget level. Fourier classic uses N/2 Complex64
values per polynomial; sparse retains N coefficient words.

| Family / backend / word | BR source MiB, classic / sparse | PBS workspace retained = peak KiB, classic / sparse |
| --- | ---: | ---: |
| glwe / ntt / u32 | 147.88 / 456.62 | 58.00 / 271.69 |
| glwe / ntt / u64 | 136.50 / 421.50 | 114.00 / 311.69 |
| glwe / rustfft / u32 | 364.00 / 562.00 | 98.00 / 871.69 |
| glwe / rustfft / u64 | 182.00 / 562.00 | 130.00 / 647.69 |
| glwe / tfhe_fft / u32 | 364.00 / 562.00 | 98.00 / 871.69 |
| glwe / tfhe_fft / u64 | 182.00 / 562.00 | 130.00 / 647.69 |
| ntru / ntt / u32 | 37.02 / 114.16 | 135.82 / 141.50 |
| ntru / ntt / u64 | 34.17 / 105.38 | 214.63 / 220.32 |
| ntru / rustfft / u32 | 91.12 / 140.50 | 235.82 / 305.50 |
| ntru / rustfft / u64 | 45.56 / 140.50 | 246.63 / 316.32 |
| ntru / tfhe_fft / u32 | 91.12 / 140.50 | 235.82 / 305.50 |
| ntru / tfhe_fft / u64 | 45.56 / 140.50 | 246.63 / 316.32 |

NTRU PBS workspace includes common BR buffers plus scalar/batch return buffers;
GLWE includes the input or output KS buffers required by its order.
Standalone CBS includes **both** borrowed `BootstrapResources` and the CBS owner
(LUT and projection buffers), with no ordinary return buffer. Constructor peaks
below retain earlier constructor outputs; nothing moved between owners is omitted.
Caller ciphertext outputs, immutable context/keys, allocator overhead and stack
are excluded from workspace heap. Inline owners are listed separately; they are
not a full stack-usage measurement.

| u64 CBS request | Workspace retained = peak KiB | Inline owner bytes | Caller output KiB |
| --- | ---: | ---: | ---: |
| glwe / ntt / classic | 178.00 | 712 | 64.00 |
| glwe / ntt / sparse | 375.69 | 712 | 64.00 |
| glwe / rustfft / classic | 194.00 | 712 | 64.00 |
| glwe / rustfft / sparse | 711.69 | 712 | 64.00 |
| glwe / tfhe_fft / classic | 194.00 | 720 | 64.00 |
| glwe / tfhe_fft / sparse | 711.69 | 720 | 64.00 |
| ntru / ntt / classic | 137.00 | 440 | 24.00 |
| ntru / rustfft / classic | 169.00 | 480 | 24.00 |
| ntru / tfhe_fft / classic | 169.00 | 488 | 24.00 |

The GLWE CBS rows use BR→KS. For u64 KS→BR, NTT CBS retains 238280 / 440712
bytes (classic / sparse); Fourier retains 254664 / 784776 bytes for either
engine. The additional input KS belongs to common resources. All observed
workspace constructor peaks equal retained bytes. PBS inline owners are 544
bytes for GLWE NTT/RustFFT and 552 for GLWE TFHE-FFT; NTRU owners are
328 / 368 / 376 bytes for NTT / RustFFT / TFHE-FFT, respectively.

All 66 first online requests and 660 subsequent measured requests made **zero
allocations**, with zero additional requested live-heap peak. PBS decode and CBS
CMux/decrypt oracles passed. This is fixed-seed functional coverage, not a
statistical noise/security claim.

## Setup and key generation

Separate single constructor observations in milliseconds; no drop of the
returned object is timed. They are diagnostic setup costs, **not stable keygen
benchmarks**. Context means table construction plus parameter clone, excluding
original profile/sampler preparation. PBS retains one shared client across the
pair. Generator setup is included when created inside the measured closure;
pre-existing context, client and generator buffers are outside the scope.

| u64 PBS family / backend | Context | Client | Server keygen, classic / sparse | Server retained MiB, classic / sparse | Server scope peak MiB, classic / sparse |
| --- | ---: | ---: | ---: | ---: | ---: |
| glwe / ntt | 0.021 | 0.003 | 125.12 / 422.05 | 136.59 / 421.61 | 136.67 / 421.69 |
| glwe / rustfft | 0.028 | 0.003 | 174.07 / 593.23 | 182.13 / 562.14 | 182.24 / 562.39 |
| glwe / tfhe_fft | 101.317 | 0.003 | 174.88 / 579.66 | 182.13 / 562.14 | 182.24 / 562.39 |
| ntru / ntt | 0.021 | 0.017 | 58.81 / 152.00 | 79.73 / 150.95 | 79.76 / 150.96 |
| ntru / rustfft | 0.028 | 0.012 | 66.11 / 176.21 | 91.13 / 186.08 | 91.18 / 186.12 |
| ntru / tfhe_fft | 106.629 | 0.013 | 67.75 / 174.87 | 91.13 / 186.08 | 91.18 / 186.12 |

The server includes ordinary return material; CBS fixtures additionally include
trace/scheme-switch keys. These server totals should not be confused with the
BR-only source arrays. Allocator reuse and first-plan construction affect setup
latency; use the retained u64 `server_keygen` Criterion IDs in each backend's `setup` target for sustained timing. Historical word/engine combinations
remain available at the recorded revisions.

## Implications and limits

- Aggregation dominates the measured u64 sparse paths: about 85–89% of GLWE
  PBS/CBS and 67–73% of NTRU PBS. Prioritize complete-request experiments on
  rotated source reads, aggregate write traffic, tiling and paired additions.
  The u32 probes also remain aggregation-heavy: 79–88% for GLWE sparse
  PBS/CBS and 73–76% for NTRU sparse PBS.
  These percentages do not establish a DRAM bandwidth bottleneck without counters.
- NTRU return is material: roughly 1.16–1.25 ms on the sparse probes, versus
  0.86–0.89 ms on classic probes. The same return algorithm follows different BR
  working sets; cache state is a hypothesis, not a demonstrated cause.
- Control transforms and external products cost less than aggregation but remain
  measurable. Quantization, GLWE KS and ordinary CBS projection/scheme switch are
  small here; none is the first target for this sparse baseline. One-hot and
  high-precision workloads can have different proportions.
- Sparse is not uniformly faster. Several u32 Fourier profiles benefit, while
  u64 NTT and TFHE-FFT pairs often do not. Preserve paired profiles and complete
  latency when testing changes; reducing external-product count alone is insufficient.
- BR key arrays are hundreds of MiB for GLWE; workspace ownership is hundreds of
  KiB. No evidence here justifies merging same-sized scratch or changing public
  ownership APIs. The [address comparison below](#aggregate-scratch-address-comparison)
  separately tests reuse across consecutive buckets.
- NTRU sparse CBS/one-hot were not supported at this measurement baseline and were not
  measured. No SIMD timing, multi-request throughput, performance counters or
  statistical failure-rate study was performed.

## Aggregate scratch address comparison

Measured on 2026-10-04 with the same production baseline and toolchain. The
aggregation-heavy GLWE NTT sparse CBS path was selected: u64, n728/h32/N1024,
GLWE dimension 1, Q=1125899906826241, full BR logB=8/L6, three copies, 64 buckets,
t4 and BR→KS. Client/server seed 42 and independent input seed 43 match the paired
fixture; the timed input encrypts 1. This compares consecutive buckets' aggregate
storage, not sharing BR, trace and scheme-switch buffers or changing their owners.

A temporary workspace retained **two** ordinary `Vec<u64>` aggregates in both
policies. `reuse_a` uses A for every bucket; `alternate_ab` uses A/B for even/odd
buckets. At each bucket, the existing dummy copy overwrites the selected buffer,
then the unchanged tiled rotated additions, in-place NTT and external product
consume it. There is no extra copy, clearing pass, transform or changed arithmetic
order. Each buffer has 24576 coefficients (192 KiB). Both policies retain
581312 bytes of workspace heap (567.69 KiB), versus production's 384704 bytes
(375.69 KiB): **one additional allocation and 192 KiB**, excluded from timing.
These totals include borrowed resources and the CBS owner, excluding keys,
context, caller output, inline owners and allocator overhead; they are not RSS.

Both policies use one saved executable and the same context, keys, ciphertext,
output, evaluator and buffers throughout each process. A relaxed atomic policy
load once per BR selects `aggregates[bucket_index & mask]`, with mask 0 or 1;
the store is outside `b.iter`. This temporary dispatch exists in both policies
and is absent from production. Disassembly confirms one shared sparse BR kernel
(19432 bytes) and one CBS entry (2314 bytes); the no-inline request wrapper is a
5-byte tail jump. There are no separately specialized policy kernels. This does
not establish equal retired instruction counts or diagnose hardware stalls.

Each process runs `reuse_a, alternate_ab, alternate_ab, reuse_a`, then swaps the
two policies' positions, with 30 Criterion samples, 0.5 s warmup and 2 s target per
round. Each iteration performs one complete CBS; setup and correctness probes
are outside timing. Runs are sequential: CPU 4, CPU 8, then a fresh process on
CPU 4. Table entries are averages of the four round mean estimates, with the
range of those estimates in parentheses, in milliseconds. They are descriptive
summaries, not pooled confidence intervals. Positive change means slower A/B.

| Process / CPU | Reuse A | Alternate A/B | Relative change |
| --- | ---: | ---: | ---: |
| First / 4 | 16.370 (16.311–16.420) | 16.366 (16.333–16.397) | −0.025% |
| Second / 8 | 17.016 (16.960–17.074) | 17.029 (17.004–17.054) | +0.076% |
| Fresh / 4 | 16.182 (16.178–16.194) | 16.194 (16.176–16.230) | +0.073% |

The round mean 95% confidence intervals overlap in every process. There is no
stable complete-request benefit from alternating buffers in this experiment.
All three processes placed both arrays at offset 16 modulo 64 and modulo 4096,
with a 200704-byte address separation. Absolute virtual addresses changed between
processes; this is not an alignment/offset sweep or a control of physical pages.
No wrapper/inline or alignment variant was added after the initial comparison
failed to show a benefit.

Before timing, each process checks bits 0 and 1 with A-only, B-only, A/B and B/A
policies, including repeated reuse. Across three processes, all **54 checked CBS
calls allocated zero times**, all 48 comparisons with the corresponding A-only
baseline were coefficient-exact, and all six CMux/decrypt bit oracles passed.
These checks do not constitute a statistical noise study.

Hardware counters were unavailable: `perf stat -e cycles,instructions -- true`
failed with `perf_event_paranoid=4`. No cycles, retired instructions, cache misses
or store-stall measurements are reported; wall time cannot identify cache
writeback, false dependencies or store forwarding as a cause. No system
permissions or counter policy were changed.

**Decision: retain the existing single aggregate.** Evidence does not justify
another 192 KiB here. This is not a general claim that address reuse is faster,
or a result for Fourier, other shapes, cross-role sharing or parallel requests.
The temporary policy, second buffer and harness were removed; production layout,
public API and normal benchmark workloads remain unchanged by this experiment.

To repeat, temporarily add the second same-sized aggregate to the sparse NTT
workspace and the runtime mask selection above. Use the paired u64 sparse CBS
fixture, keeping its objects alive for all eight rounds; measure constructor
allocations separately and check exact outputs before timing. Build once and
copy the executable, then run it on CPUs 4, 8 and 4 in that order:

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap --no-run
taskset -c 4 /path/to/saved-probe --bench --sample-size 30 \
  --warm-up-time 0.5 --measurement-time 2 --noplot
```

Use separate Criterion output directories for each process. Normal production
benchmarks have no scratch-policy option; do not interpret their timings as this
controlled two-buffer experiment. Remove the probe after comparison.

After restoring the original sources and paired benchmark byte-for-byte,
format/diff checks, benchmark compilation and its u64 sparse BR→KS smoke case
passed. This experiment adds no permanent numerical tests or CI workload.

## Reproduction

Build first, then run saved executables with `taskset`; do not compile concurrently
with timing. For example, from the workspace root:

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs --bench circuit_bootstrap --no-run
taskset -c 4 cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap -- \
  'u64/cbs/' --warm-up-time 0.3 --measurement-time 1 --sample-size 15 --noplot
cargo bench -p primus_tfhe_glwe_fourier --features rustfft,tfhe-fft --bench sparse_pbs --bench circuit_bootstrap --no-run
```

Use the same two targets in each of the four backends. Fourier packages need
`rustfft,tfhe-fft`; NTT needs no feature. Select `u64/.*/complete$` for both orders,
`u32/.*BootstrapKeyswitch.*/complete$` for GLWE u32 and `u32/.*/complete$` for NTRU.
On NTRU `circuit_bootstrap`, select `/cbs/` to exclude one-hot. The existing
Criterion fixtures seed clients/input/keygen as documented above; keep these
seeds and constructor profiles fixed when reconstructing the temporary probe.

For the historical comparison, build `d566a73a` and `def858ef` without the new
CBS benchmark pairing, copy each executable before rebuilding, and use
`taskset -c 4` then `taskset -c 8`, `--bench 'u64/cbs/sparse/'`,
`--warm-up-time 0.5 --measurement-time 2 --sample-size 20 --noplot` in
current/before/before/current order. Use the current Cargo.lock for both builds.

After removing instrumentation, formatting, both changed GLWE targets'
all-targets check and strict clippy passed, as did all 24 normal CBS benchmark
smoke cases (8 NTT, 16 Fourier). No ordinary numerical tests were rerun and no
CI matrix was expanded for this benchmark-only change.

## NTRU high-precision lookup

Measured on 2026-10-04 with the 4-D implementation accompanying this section
(parent `254e2190`). Both NTRU backends now compose sparse one-hot CBS with the
existing table selection, low-chunk rotations and Q→q/extraction/KS return.
An independent NLEV[1] is generated only for explicit public lifts; its basis
and row noise are caller-selected. No online numerical kernel changed.

The [pipeline fixture](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#historical-measurements)
pairs classic/sparse at **n800/h32/N1024**, q24/t8, c8/d5/o8, the public function
`(x*x+3*x+7) mod 65536`, and input 43981. Client seed 42 and input seed 43 produce
the same client coefficients and encrypted input in each pair; server material
consumes different randomness. Sparse uses r3/B64. This deliberately retains the
circuit profile's external sigma (`2^24 * 2.046151696979124e-6`, about 34.3287),
not the n728 diagnostic profile's larger external sigma. BR/trace/scheme-switch
and independently sampled lift use sigma 0.7; return KS uses 3.2. The explicit
lift reuses BR's basis (Q50 logB8/L6 or Native64 logB8/L8). These are arithmetic
fixtures, not security presets or equal-security comparisons.

Conditions: the same Ryzen 9 9955HX3D, stable rustc 1.98.1 / LLVM 22.1.8,
repository `target-cpu=native`, release profile, `ntt,rustfft,tfhe-fft` without
the workspace `simd` feature. The benchmark was built first; six requests then
ran sequentially on CPU 4 without concurrent compilation/tests. Each ID uses
15 samples, 0.3 s warmup, 1 s measurement target and flat sampling (30 measured
requests). Setup/keygen/LUT creation/encryption/workspace allocation and probes
are untimed. Frequency and other system activity were not controlled. This is
one representative baseline, not a repeated before/after optimization experiment.

| Backend / u64 | Classic mean ms (95% CI) | Sparse mean ms (95% CI) |
| --- | ---: | ---: |
| NTT | 48.997 (48.852–49.167) | 49.989 (49.405–50.702) |
| RustFFT | 56.082 (55.860–56.358) | 66.694 (66.061–67.443) |
| TFHE-FFT | 45.401 (45.247–45.565) | 60.551 (59.951–61.319) |

Sparse was not faster in this sample. In particular, enabling the full lookup
composition does not imply a performance improvement. The Fourier gap and near
NTT result remain observations of these parameters and this machine; no cache
or scratch-address cause was established.

Retained requested heap **bytes**, excluding context/tables, allocator metadata,
stack and transient peak allocation:

| Backend / u64 | Client + server, classic / sparse | Separate sparse lift | Evaluator, classic / sparse |
| --- | ---: | ---: | ---: |
| NTT | 92505304 / 174264800 | 49152 | 787464 / 793864 |
| RustFFT | 105850408 / 214856496 | 65536 | 1059968 / 1131904 |
| TFHE-FFT | 105850408 / 214856496 | 65536 | 1059968 / 1131904 |

The public polynomial LUT retains 731880 bytes and eight output buffers 51456
bytes for each u64 case. The classic initializer is included in its BR material;
only sparse adds the separately reported lift. The dense and shared-subtable
workloads have no explicit Lift and retain zero separate lift bytes. Their
public LUT and workspace sizes differ, so they are not substituted into the
latency table above.

Each of 36 evaluation smoke IDs (three workloads × classic/sparse × u32/u64 ×
three transforms) checked all decoded digits and zero online allocations.
Twelve public-creation IDs also passed. The untimed phase probe measures circular
error at external q=2^24 against the exact digit scale q/t=2^21. The decoding
half-gap is 1048576. Sparse maxima across the eight output chunks:

| Backend / word | Polynomial | Dense | Shared |
| --- | ---: | ---: | ---: |
| NTT / u32 | 219059 | 304261 | 64899 |
| NTT / u64 | 1032 | 1023 | 342 |
| RustFFT / u32 | 44710 | 70708 | 22435 |
| RustFFT / u64 | 1296 | 805 | 207 |
| TFHE-FFT / u32 | 45561 | 71307 | 22341 |
| TFHE-FFT / u64 | 1301 | 822 | 207 |

The u64 polynomial classic maxima were 1160/1190/1190 for NTT/RustFFT/TFHE-FFT.
These are complete returned-LWE residuals, including CBS, products, rotations,
modulus switch and KS; they do not isolate FFT error or certify a failure rate.
NTT exact arithmetic and Fourier rounding retain their separate contracts.
Small-parameter tests additionally cover all pruning/lift layouts, independent
lift bases, binding errors and alternating inputs without allocation. No large
parameter or statistical tests were added to ordinary CI.

Reproduce the selected baseline after building, with no concurrent test/build:

```sh
cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft --no-run
taskset -c 4 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- \
  '/u64/(classic|sparse)/n800_h32_N1024/c8_d5_o8/evaluate$' \
  --sample-size 15 --warm-up-time 0.3 --measurement-time 1 --noplot
```

The former n800 uniform-binary IDs use different secrets and encrypted input.
Their historical timings cannot be treated as an implementation before/after
comparison with this fixed-weight fixture.
