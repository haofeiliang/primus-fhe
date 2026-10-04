# Sparse PBS and CBS measurements

The original baseline below was measured on 2026-10-04. Production source: `def858ef`; the only persistent code
change is the paired GLWE CBS benchmark described below. These are functional
arithmetic profiles, not assessed security parameters or equal-security comparisons.
No production algorithm, workspace layout or public API changed in that baseline.
The later [NTRU pair experiment](#ntru-paired-coefficient-aggregation) records an accepted kernel optimization.
The [tile experiment](#coefficient-aggregation-tiles) and
[first-bucket experiment](#glwe-first-bucket-trivial-input) record candidates that were not retained.

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

Parameters come from the [shared profiles](../../test-support/tfhe/src/parameters/mod.rs):
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
not explain or invalidate the [historical observation](workspaces-and-storage.md#glwe-ntt-borrowed-resource-measurement).
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
The existing `primus_test_allocations::measure` was not changed or relabeled.

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
latency; use the existing `server_keygen` Criterion IDs for sustained timing.

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

The [pipeline fixture](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#benchmark-fixture)
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

## NTRU paired coefficient aggregation

Measured on 2026-10-04 against `573dd919`. **Decision: retain pairs for u32 and
u64 in both NTRU backends.** Two adjacent selectors now share the initialized
aggregate traversal through the existing `Nlev` pair method. An odd final
selector uses the single method. The private helper preserves dummy copying,
key order, zero exponents, first-bucket NLEV lifting and later NGSW products.
There is no new backend word-width branch, key layout, scratch allocation,
transform, floating-point operation or public API. This does not change GLWE.

Conditions match the machine/toolchain above: Ryzen 9 9955HX3D, rustc 1.98.1,
release profile, repository native CPU flags, no portable-SIMD feature. Fourier
builds enable both `rustfft,tfhe-fft`. Saved before/after executables run sequentially,
with builds and tests outside measurement. CPU 4 uses before/after/after/before;
CPU 8 repeats PBS with after/before/before/after. Each backend/workload-group
round uses a fresh process, 30 samples, 0.5 s warmup and a 2 s measurement target (Criterion may extend it).
One iteration is one complete request into existing buffers. Setup, keygen,
input encryption, LUT preparation, allocation and validation remain outside timing.

The existing paired n728/h32/N1024, r3/B64 fixtures are unchanged. PBS uses t8
and includes Q-to-q conversion, extraction and LWE key switching. Ordinary CBS
uses t4; the nonzero one-hot batch uses t8/M4 and produces all three required
controls. These two consumers exercise the coarser CBS rotation geometry.
NTT u32 CBS/one-hot use Q=998244353 rather than PBS's Q=132120577; the other
moduli, bases, role-specific noise and fixed seeds are those documented above.
These remain arithmetic diagnostics, not assessed security parameters.

### Complete-request latency

All values are milliseconds. Each before/pair cell lists the **two round mean
estimates**, not two individual requests. Delta compares their averages.
The CI column gives the envelope of the two per-round mean 95% confidence
intervals for each version; it is **not** a pooled confidence interval.

#### PBS, including the return to LWE

| CPU / backend / word / request | Before means | Pair means | Delta | Before CI envelope → pair CI envelope |
| --- | ---: | ---: | ---: | --- |
| 4 / ntt / u32 / PBS | 5.855 / 5.517 | 5.018 / 5.002 | -11.9% | [5.461, 5.923] → [4.950, 5.079] |
| 4 / ntt / u64 / PBS | 5.514 / 5.549 | 4.677 / 4.958 | -12.9% | [5.464, 5.618] → [4.639, 5.168] |
| 4 / rustfft / u32 / PBS | 7.306 / 8.023 | 6.167 / 6.086 | -20.1% | [7.246, 8.394] → [6.035, 6.295] |
| 4 / rustfft / u64 / PBS | 7.026 / 7.027 | 5.341 / 5.384 | -23.7% | [6.943, 7.129] → [5.286, 5.461] |
| 4 / tfhe_fft / u32 / PBS | 7.099 / 7.141 | 5.864 / 5.820 | -17.9% | [7.041, 7.242] → [5.778, 5.923] |
| 4 / tfhe_fft / u64 / PBS | 6.958 / 6.894 | 5.265 / 5.700 | -20.8% | [6.835, 7.054] → [5.215, 5.776] |
| 8 / ntt / u32 / PBS | 6.098 / 6.096 | 5.706 / 5.626 | -7.1% | [6.024, 6.190] → [5.555, 5.820] |
| 8 / ntt / u64 / PBS | 6.083 / 6.090 | 5.247 / 5.278 | -13.5% | [6.022, 6.179] → [5.188, 5.406] |
| 8 / rustfft / u32 / PBS | 8.005 / 7.922 | 6.741 / 6.839 | -14.7% | [7.827, 8.080] → [6.676, 7.090] |
| 8 / rustfft / u64 / PBS | 7.999 / 7.444 | 5.888 / 5.871 | -23.9% | [7.369, 8.104] → [5.825, 5.949] |
| 8 / tfhe_fft / u32 / PBS | 8.351 / 7.662 | 6.382 / 6.417 | -20.1% | [7.587, 8.457] → [6.322, 6.510] |
| 8 / tfhe_fft / u64 / PBS | 7.376 / 7.398 | 5.784 / 5.814 | -21.5% | [7.284, 7.487] → [5.731, 5.914] |

#### CBS and nonzero one-hot consumers (CPU 4)

| CPU / backend / word / request | Before means | Pair means | Delta | Before CI envelope → pair CI envelope |
| --- | ---: | ---: | ---: | --- |
| 4 / ntt / u32 / CBS | 5.714 / 5.707 | 5.524 / 5.429 | -4.1% | [5.634, 5.812] → [5.375, 5.658] |
| 4 / ntt / u32 / one-hot | 6.535 / 6.555 | 6.206 / 6.259 | -4.8% | [6.465, 6.637] → [6.148, 6.327] |
| 4 / ntt / u64 / CBS | 4.098 / 4.179 | 3.499 / 3.350 | -17.2% | [4.062, 4.245] → [3.315, 3.532] |
| 4 / ntt / u64 / one-hot | 4.500 / 4.496 | 3.879 / 3.712 | -15.6% | [4.462, 4.543] → [3.686, 3.912] |
| 4 / rustfft / u32 / CBS | 6.829 / 6.891 | 5.693 / 5.655 | -17.3% | [6.777, 7.000] → [5.618, 5.740] |
| 4 / rustfft / u32 / one-hot | 7.703 / 7.891 | 6.685 / 6.675 | -14.3% | [7.649, 7.959] → [6.586, 6.838] |
| 4 / rustfft / u64 / CBS | 5.785 / 5.897 | 4.058 / 4.344 | -28.1% | [5.726, 6.035] → [4.029, 4.456] |
| 4 / rustfft / u64 / one-hot | 6.524 / 6.305 | 4.625 / 4.815 | -26.4% | [6.242, 6.601] → [4.588, 4.870] |
| 4 / tfhe_fft / u32 / CBS | 6.471 / 6.373 | 5.214 / 5.388 | -17.5% | [6.293, 6.587] → [5.172, 5.480] |
| 4 / tfhe_fft / u32 / one-hot | 7.550 / 7.090 | 5.904 / 5.916 | -19.3% | [7.011, 7.623] → [5.865, 5.977] |
| 4 / tfhe_fft / u64 / CBS | 5.829 / 5.692 | 3.942 / 4.027 | -30.8% | [5.625, 5.915] → [3.909, 4.063] |
| 4 / tfhe_fft / u64 / one-hot | 6.027 / 6.176 | 4.338 / 4.340 | -28.9% | [5.962, 6.385] → [4.300, 4.388] |

All PBS cases improve on both CPUs; each case's pair CI envelope lies below
its before envelope. CBS/one-hot improvements also recur across both runs.
NTT u32 ordinary CBS has the smallest effect: one pair interval slightly overlaps
a baseline interval, so its approximate 4% change should not be read as a precise
portable speedup. Other consumer CI envelopes are separated. There is visible
run-to-run variation, notably in some Fourier cases; clocks and other system
activity were not controlled. These results do not extrapolate to other CPUs,
ring lengths, bases, bucket counts or portable-SIMD performance.

### Correctness and memory

A temporary probe outside the timed loop fingerprinted the coefficient control
key, public bucket indices and input ciphertext, and saved the entire PBS output.
All 48 PBS captures match by backend/word across versions and CPUs, including
coefficient-exact Fourier outputs. The existing benchmark's decrypt oracle,
CBS CMux oracle and one-hot control oracle passed before every selected timing.
These fixed fixtures are not a statistical noise study.

Each backend adds one small private-kernel regression for direct coefficient
scatter/addition, independent of the pair kernel's contiguous intervals. It covers
zero through five selectors, dummy reset on reused output, nonconsecutive mask
indices, three levels, odd tails, equal exponents, both signs and 0/N-1/N/2N-1.
Barrett and native wrapping cases use u32/u64. Existing first-NLEV/later-NGSW
phase tests, complete PBS/MVB/CBS/one-hot/LUT and zero-allocation tests remain the
consumer checks; no benchmark or large parameter sweep was added to ordinary CI.

A separate temporary allocator probe measured evaluator construction and two
complete PBS calls, independently of the latency executables. The columns below
are **identical before and after**. BR bytes count only the coefficient control
array, excluding map metadata and return/CBS keys. Retained and peak columns are
requested workspace heap bytes from allocation/free events, excluding immutable
context/keys, caller output, inline owners and allocator overhead; neither is RSS.

| Backend / word | BR coefficient bytes | Construction allocations | Retained workspace bytes | Construction peak bytes |
| --- | ---: | ---: | ---: | ---: |
| ntt / u32 | 119,701,504 | 12 | 144,900 | 144,900 |
| ntt / u64 | 110,493,696 | 12 | 225,608 | 225,608 |
| rustfft / u32 | 147,324,928 | 15 | 312,836 | 312,836 |
| rustfft / u64 | 147,324,928 | 15 | 323,912 | 323,912 |
| tfhe_fft / u32 | 147,324,928 | 15 | 312,836 | 312,836 |
| tfhe_fft / u64 | 147,324,928 | 15 | 323,912 | 323,912 |

All 24 first/reused online calls in that probe made zero allocations and had
zero additional heap peak. No key-generation time or key-construction peak was
remeasured: key generation and ownership are untouched. Source key bytes and
workspace geometry are unchanged. Pairing reduces the logical aggregate load/store
traversals; it does not eliminate selector contributions or source-key reads.
No hardware-counter measurements were available (`perf_event_paranoid=4`), so this
report does not attribute the gain to cache writeback or quantify DRAM traffic.

To repeat the latency experiment, build each revision and save the executables
before rebuilding the other version. Use the existing `sparse_pbs` and
`circuit_bootstrap` targets, with no extra benchmark target or runtime strategy:

```sh
cargo bench -p primus_tfhe_ntru_ntt --bench sparse_pbs --bench circuit_bootstrap --no-run
cargo bench -p primus_tfhe_ntru_fourier --features rustfft,tfhe-fft \
  --bench sparse_pbs --bench circuit_bootstrap --no-run

# Give each process its own Criterion output directory; repeat in the orders above.
CRITERION_HOME=/tmp/primus-pair-round taskset -c 4 <saved-sparse_pbs-executable> \
  '/sparse/complete' --bench --sample-size 30 --warm-up-time 0.5 --measurement-time 2 --noplot
CRITERION_HOME=/tmp/primus-pair-cbs-round taskset -c 4 <saved-circuit_bootstrap-executable> \
  '/(cbs/sparse/.*/complete|one_hot/sparse/.*/nonzero)$' \
  --bench --sample-size 30 --warm-up-time 0.5 --measurement-time 2 --noplot
```

For the independent memory check, enable thread-local allocation/free counters
only around `context.evaluator(server)` and then two `apply_lookup_table_to` calls
with an already allocated output. Reset live/peak counters between those scopes;
keep the returned evaluator alive when reading retained bytes. Do not include
this instrumentation in the latency binary. Temporary capture code, allocator
probe, strategy copies and logs were removed after recording these results.

## Coefficient aggregation tiles

**2026-10-04; baseline `501c90ac`. Decision: retain the existing untiled
NTRU and GLWE Fourier aggregation.** The NTRU pair optimization above remains
unchanged. These experiments do not justify a general tile policy or an accepted
word-specific replacement. GLWE NTT's existing tile policy was not changed.

### Method and remaining cost

Use the same n728/h32/N1024, r3/B64, t8 sparse PBS fixtures and seeds as above.
The request includes the ordinary output return, including NTRU Q→q/extraction/KS.
No modulus, basis, key layout, sampling or arithmetic kernel changed. Compare
complete-polynomial tiles of 8, 16 and 32 KiB with a whole control: copy the dummy
once, traverse tiles outside the existing selector-pair loop, then transform the
**completed** aggregate. Each pair reads the corresponding source polynomial
range; an odd last selector still uses the single-input kernel. No encrypted
zero or zero exponent is skipped, and no tile owns a new buffer.

The AMD Ryzen 9 9955HX3D, rustc 1.98.1, repository `target-cpu=native` and default
features plus `rustfft,tfhe-fft` were held fixed. CPU 4 and CPU 8 are on different
CCD/cache groups. Builds/tests ran separately from latency measurements. Power,
frequency and unrelated system activity were not controlled. `perf_event_paranoid=4`
prevented hardware-counter evidence; these timings do not identify cache misses,
writeback latency or DRAM traffic.

A temporary `Instant` probe around each bucket's aggregation, control transform
and external product reconfirmed the remaining u64 cost. These are median stage
sums from up to the last 100 warmed requests, in ms, **not acceptance timings**:

| Backend, u64 | Requests retained | Aggregate | Transform | External product | Aggregate bytes | BR coefficient-array bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ntru / ntt | 100 | 2.885 | 0.276 | 0.425 | 49,152 | 110,493,696 |
| ntru / rustfft | 87 | 3.304 | 0.270 | 0.440 | 65,536 | 147,324,928 |
| glwe / rustfft | 28 | 13.725 | 1.032 | 1.059 | 262,144 | 589,299,712 |

All tables below use freshly rebuilt **uninstrumented** binaries. Early comparisons
were discarded after detecting a reused instrumented library artifact when saved
source was restored with an older mtime. Rebuilding with fresh source timestamps,
checking the build log, and checking both binaries and run logs for probe markers
preceded the replacement measurements. The discarded timings are not mixed into
these tables. Key/input capture and correctness assertions execute outside `b.iter`.

### Whole-control versus constant tiles

CPU 4 screening used 15 samples, 0.3 s warmup and a 1 s measurement target.
Run the whole-control baseline before and after each candidate series. Cells
contain the point mean and Criterion's 95% confidence interval in ms; the two
baseline cells are distinct fresh processes. GLWE uses BR→KS in this screen.

| Backend / word | Whole, first | 8 KiB | 16 KiB | 32 KiB | Whole, last |
| --- | --- | --- | --- | --- | --- |
| glwe / rustfft / u64 | 16.088 [15.803, 16.436] | 19.577 [19.347, 19.825] | 18.484 [18.260, 18.729] | 18.080 [17.882, 18.317] | 15.932 [15.803, 16.089] |
| ntru / ntt / u64 | 4.723 [4.676, 4.784] | 5.280 [5.219, 5.355] | 5.065 [4.999, 5.139] | 4.938 [4.891, 4.997] | 4.704 [4.658, 4.764] |
| ntru / rustfft / u64 | 5.417 [5.264, 5.638] | 5.644 [5.581, 5.721] | 5.362 [5.314, 5.421] | 5.388 [5.324, 5.470] | 5.333 [5.267, 5.414] |

The u64 NTRU NTT and GLWE Fourier candidates regressed; NTRU RustFFT had no
convincing gain. The u32 screen retained the two larger candidates:

| Backend / word | Whole, first | 16 KiB | 32 KiB | Whole, last |
| --- | --- | --- | --- | --- |
| glwe / rustfft / u32 | 20.992 [20.701, 21.354] | 21.798 [21.572, 22.160] | 21.277 [21.065, 21.521] | 20.819 [20.593, 21.177] |
| glwe / tfhe_fft / u32 | 19.930 [19.701, 20.219] | 21.140 [20.841, 21.514] | 20.531 [20.277, 20.883] | 19.890 [19.667, 20.158] |
| ntru / ntt / u32 | 5.044 [4.998, 5.097] | 5.517 [5.465, 5.578] | 5.441 [5.401, 5.488] | 5.109 [5.044, 5.181] |
| ntru / rustfft / u32 | 6.130 [6.071, 6.203] | 5.788 [5.743, 5.841] | 5.730 [5.679, 5.793] | 6.132 [6.027, 6.289] |
| ntru / tfhe_fft / u32 | 5.786 [5.751, 5.828] | 5.513 [5.429, 5.648] | 5.438 [5.384, 5.519] | 5.779 [5.727, 5.843] |

Only the NTRU Fourier u32 constant-tile prototype showed a useful signal. That
alone cannot justify tiling u64, or prove that a word-specific implementation
will preserve the gain.

### Candidate that preserves the u64 whole-control path

The reviewable candidate selected `max(32 KiB / size_of::<T>(), N)` only for u32
and the full control length otherwise, in the same tile loop. NTRU retained its
`NlevIter` and borrowed level ranges. GLWE moved its existing pair traversal into
an inline private bucket helper; tiles used the flat polynomial-batch kernel,
since a tile need not be a whole GGSW. The numerical order within each polynomial
remained unchanged.

CPU 4 used before/after/after/before; CPU 8 reversed that order. Each request used
30 samples, 0.5 s warmup and a 2 s measurement target. Means below are individual
runs; delta compares their arithmetic averages. CI envelopes are the min/max of
individual 95% CIs, **not a pooled confidence interval**.

| CPU / backend / word | Whole means | u32-only tile means | Delta | Whole CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| 4 / glwe / rustfft / u32 | 20.883 / 20.970 | 21.582 / 22.290 | +4.8% | [20.749, 21.184] → [21.399, 22.514] |
| 4 / glwe / tfhe_fft / u32 | 19.836 / 19.910 | 20.173 / 21.146 | +4.0% | [19.668, 20.089] → [20.026, 21.382] |
| 4 / ntru / rustfft / u32 | 6.126 / 6.098 | 6.284 / 6.267 | +2.7% | [6.060, 6.202] → [6.216, 6.333] |
| 4 / ntru / tfhe_fft / u32 | 5.842 / 5.820 | 5.994 / 5.991 | +2.8% | [5.781, 5.903] → [5.932, 6.071] |
| 8 / glwe / rustfft / u32 | 21.466 / 22.561 | 21.256 / 21.280 | -3.4% | [21.286, 22.787] → [21.057, 21.516] |
| 8 / glwe / tfhe_fft / u32 | 19.589 / 19.602 | 20.048 / 20.251 | +2.8% | [19.430, 19.822] → [19.862, 20.538] |
| 8 / ntru / rustfft / u32 | 6.701 / 6.714 | 6.950 / 7.026 | +4.2% | [6.657, 6.771] → [6.864, 7.077] |
| 8 / ntru / tfhe_fft / u32 | 6.432 / 6.403 | 6.590 / 6.902 | +5.1% | [6.352, 6.540] → [6.526, 7.092] |

NTRU's u32 gain did not survive this version; GLWE's result was not consistent
across CPUs/engines. A final NTRU-only check forced the private bucket helper to
inline, leaving the same u32/whole-u64 policy. Symbol inspection confirmed the
out-of-line helper disappeared, but the complete request still did not recover
the constant-tile gain. CPU 4 used the same 30-sample ABBA settings:

| Backend / word | Whole means | Forced-inline candidate means | Delta | Whole CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| ntru / rustfft / u32 | 6.170 / 6.077 | 6.249 / 6.147 | +1.2% | [6.033, 6.223] → [6.108, 6.294] |
| ntru / rustfft / u64 | 5.289 / 5.367 | 5.313 / 5.318 | -0.2% | [5.244, 5.446] → [5.268, 5.377] |
| ntru / tfhe_fft / u32 | 5.822 / 5.851 | 5.977 / 5.884 | +1.6% | [5.752, 5.922] → [5.833, 6.106] |
| ntru / tfhe_fft / u64 | 5.165 / 5.247 | 5.174 / 5.245 | +0.1% | [5.124, 5.312] → [5.126, 5.301] |

These observations do not prove tiling can never help NTRU u32, nor identify the
code-generation difference responsible for the prototype/candidate gap. They do
reject these candidates as a default change. No additional code-generation or
parameter search was retained just to recover one screening result.

### Correctness, resources and stopping point

- All 83 captures from the uninstrumented comparisons matched the corresponding
  key/public-map/input fingerprint and the **complete ciphertext output**, across
  nine request IDs. Every timed fixture also passed its independent decrypt check.
- Three temporary direct-scatter unit oracles passed for NTT and both Fourier
  aggregators, in u32/u64. They covered N=32 and N=1024, nonconsecutive indices,
  empty/odd/even selector lists, mixed signs, exponent 0/N−1/N/2N−1, dummy reset,
  dirty-buffer reuse and short final tiles. The GLWE case used 27 polynomials
  (k=2/L=3), crossing row/level boundaries. All 432 measured oracle calls allocated
  zero times. Those tests were removed with the rejected implementation.
- BR coefficient-array footprints remained 119,701,504 / 110,493,696 bytes for
  NTRU NTT u32/u64, 147,324,928 for either NTRU Fourier word, and 589,299,712 for
  either GLWE Fourier word. Logical coefficient contributions are unchanged;
  tiling revisits index/exponent arrays more often.
- Aggregate storage stayed 52/48 KiB for NTRU NTT u32/u64, 64 KiB for NTRU
  Fourier, and 256 KiB for GLWE Fourier. Existing transformed buffers stayed
  128/64 KiB for NTRU Fourier and 512/256 KiB for GLWE Fourier. These are relevant
  buffers, not total workspace/RSS. No owner, constructor, key or allocation layout
  changed. Constructor/keygen peaks were not remeasured; earlier resource tables
  must not be presented as new peak measurements.

The ordinary PBS screening exit condition was met, so this experiment did **not**
expand into new CBS, one-hot, high-precision LUT, GLWE KS→BR or SIMD performance
matrices. There is no retained execution-path change needing that acceptance
matrix. After source restoration, all-targets check passed for the three
experimental backends and 57 existing tests passed for them plus NTRU LUT (features
`ntt,rustfft,tfhe-fft`, `--lib --tests`). These correctness tests do not substitute
for performance measurements of those consumers.

For reproduction, build separate baseline/candidate `sparse_pbs` executables with
`cargo bench -p <backend> --bench sparse_pbs --features rustfft,tfhe-fft --no-run`,
rebuilding the library after every source restore. Pin each saved binary with
`taskset -c 4` (or `8`), use separate Criterion output directories and the settings
above, and select `/sparse/complete$`; GLWE screening additionally selects
`BootstrapKeyswitch`. Keep setup/capture outside timing and use one complete PBS
per iteration. Reconstruct the tile traversal described above without changing
key layout or pair arithmetic, and revalidate the executable rather than relying
on a previously built artifact. All experimental source, capture hooks and
executables were removed; no new benchmark or permanent test is retained.

## GLWE first-bucket trivial input

**2026-10-04; baseline `575de611`. Decision: retain the general first-bucket
external product.** The algebraic specialization is valid, but this experiment
found no repeatable complete-request gain. No production API, key layout,
workspace, benchmark or test change is retained.

### Preconditions and exact scope

Both GLWE PBS orders enter sparse BR with a freshly initialized accumulator
`(0, …, 0, P)`, where `P = X^(-R(b)) * LUT`. KS→BR first prepares the small LWE,
then the same raw BR kernel overwrites every mask polynomial with zero. Previous
workspace contents and the input order do not change this invariant.

For the current `ApproxSignedBasis`, `init_value_carry(0) = (0, false)`:
non-power-of-two adjustment starts at a strictly positive threshold, while a
native power-of-two basis either extracts a zero carry bit or initializes it to
false. Each decomposer subsequently receives `(0, false)` and emits the same
pair. This holds with both full and truncated levels. See the
[basis initialization](../../crates/primus_decompose/src/primitive/basis.rs) and
[digit/carry kernel](../../crates/primus_decompose/src/primitive/common.rs).
Consequently, in the sum over the `k+1` GLev rows, only the body row contributes.
The actual Fourier transforms/products are finite, so the skipped zero terms
also contribute no approximation error; this was independently checked below.

The temporary candidate kept **all** first-bucket coefficient aggregation,
control transforms, encrypted selections and dummy material. A temporary product
entry reused the existing workspace and processed only the final input/key row
for bucket zero; every subsequent bucket used the original full product. Thus
only zero-mask decomposition, digit transforms and multiply-adds were removed;
output clearing, body work and inverse transforms remained. No scan for zero
coefficients, public empty-bucket skip, altered initial rotation or new scratch
was introduced. This is the prerequisite external-product experiment, **not**
an evaluation of first-bucket GLev storage or body-row-only aggregation.

### First bucket and complete requests

The fixtures use u64, n728/h32/N1024/k1, r3/B64 and unchanged diagnostic parameters:
PBS t8, CBS t4; both orders, NTT and the two Fourier engines. The CPU/toolchain/features
are those above, with timings pinned to CPU 4. No builds/tests overlapped timing.
Each fixture retained the same deterministic client/key/input seeds and verified
its decrypt or CBS CMux result outside timing.

Separate instrumented binaries measured the three first-bucket stages with
`Instant`. Each case supplied 28 observations; rows below give the range of
per-case medians over PBS/CBS and both orders, in **microseconds**, not confidence
intervals. Total includes aggregation, control transform and external product;
probe/code-generation overhead was not subtracted.

| Backend | First bucket total, general → candidate | First external product, general → candidate |
| --- | --- | --- |
| ntt | 195.43–272.11 → 201.03–245.97 | 14.78–16.63 → 9.33–10.32 |
| rustfft | 193.96–255.06 → 187.99–279.94 | 16.27–17.36 → 10.09–10.37 |
| tfhe_fft | 192.43–244.61 → 216.49–236.83 | 14.81–16.79 → 9.22–10.15 |

The local external-product reduction is roughly 5–7 µs against a roughly 16 ms
request: only about 0.03–0.04% of the request's arithmetic budget. Even eliminating
the entire measured first external product would save only about 0.1% at these
parameters; the real candidate still needs its body and inverse transform.
These estimates do not bound unrelated compiler/layout or system effects, and
must not be reported as measured end-to-end speedups.

Fresh **uninstrumented** binaries then ran general/candidate/candidate/general
in separate processes: 30 samples, 0.5 s warmup, 2 s measurement target, one
complete request per iteration. Binary markers and build logs distinguished
these executables from the stage probes. Means and CI envelopes below are in ms;
the delta uses the average of the two means. An envelope spans the individual
95% confidence intervals; it is not a pooled CI. BK means BR→KS, KB means KS→BR.

| Backend / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| ntt / CBS / BK | 16.354 / 17.172 | 16.792 / 18.085 | +4.0% | [16.254, 18.002] → [16.569, 18.900] |
| ntt / CBS / KB | 17.683 / 16.640 | 16.862 / 17.227 | -0.7% | [16.443, 18.382] → [16.575, 17.696] |
| ntt / PBS / BK | 17.019 / 16.606 | 16.625 / 16.595 | -1.2% | [16.308, 17.474] → [16.308, 16.938] |
| ntt / PBS / KB | 16.420 / 16.519 | 16.644 / 16.735 | +1.3% | [16.248, 16.858] → [16.388, 17.028] |
| rustfft / CBS / BK | 16.270 / 16.209 | 16.234 / 16.263 | +0.1% | [16.037, 16.496] → [16.072, 16.497] |
| rustfft / CBS / KB | 16.187 / 16.227 | 16.211 / 16.294 | +0.3% | [15.985, 16.459] → [16.028, 16.476] |
| rustfft / PBS / BK | 16.089 / 16.151 | 16.480 / 16.337 | +1.8% | [15.928, 16.334] → [16.118, 16.743] |
| rustfft / PBS / KB | 17.682 / 16.105 | 16.131 / 15.966 | -5.0% | [15.950, 17.921] → [15.792, 16.303] |
| tfhe_fft / CBS / BK | 15.971 / 15.921 | 15.728 / 15.834 | -1.0% | [15.751, 16.209] → [15.518, 16.060] |
| tfhe_fft / CBS / KB | 18.805 / 16.022 | 15.899 / 15.940 | -8.6% | [15.858, 21.050] → [15.720, 16.179] |
| tfhe_fft / PBS / BK | 16.277 / 15.614 | 15.991 / 15.982 | +0.3% | [15.442, 16.638] → [15.798, 16.214] |
| tfhe_fft / PBS / KB | 17.475 / 15.619 | 15.868 / 15.771 | -4.4% | [15.427, 17.649] → [15.600, 16.103] |

The apparent larger reductions in some KB averages came with substantial baseline
run-to-run variation; the last general run overlapped or beat the candidate.
Other requests were neutral or regressed. The candidate therefore does not meet
the repeatable complete-request criterion. Frequency/background activity was
uncontrolled and hardware counters remained unavailable; no cache or scheduling
cause is inferred. A smaller bucket count was not used to amplify the effect.

### Correctness, resources and exit

- 48 uninstrumented captures over all 12 request IDs matched the corresponding
  key/public-map/input fingerprint and complete PBS/CBS output, including Fourier
  gadget output. Every fixture also passed its decrypt/CMux oracle.
- Two temporary focused tests covered u32/u64, N=32, k=1/2, full/truncated bases,
  nonzero and zero bodies, and synthesized dummy-only/one/three-selector buckets
  with exponents 0/N−1/N/2N−1. All 864 first-product comparisons were coefficient
  exact against the general product; the measured pairs allocated zero times.
  Each case subsequently reused both workspaces for a full product on the new
  accumulator. The existing raw sparse tests independently checked phase and
  direct negacyclic rotation; CBS tests checked gadget scales and CMux consumption.
- Zero initialization and all later digits/carries were checked by scalar and
  batch decomposition for every valid base-log/retained-level combination under
  the tested u32/u64 NTT primes and native domains, starting with dirty buffers.
- Key arrays stayed 441,974,784 bytes for NTT and 589,299,712 for each Fourier
  engine. Aggregate scratch remained 192 KiB for NTT and 256 KiB for Fourier,
  with the latter's existing 256 KiB transformed control buffer. These are array
  footprints, not memory traffic or the complete workspace. All owners and
  constructors stayed unchanged; no new keygen, construction-peak or RSS
  measurement is claimed.

The candidate passed 36 tests including the two temporary oracles. After restoring
the original source and removing the oracles/capture hooks, all-targets check and
34 existing GLWE backend tests passed (`rustfft,tfhe-fft`, `--lib --tests`). No new
CI case or unused public product method is retained. No u32/SIMD performance or
second-CPU acceptance matrix was added once the u64 complete-request test failed.
First-bucket GLev storage, omitted-row aggregation/transforms and their sampling/
noise effects remain untested follow-ups; they must not inherit a speedup claim
from this valid but too small external-product simplification. NTRU was unchanged.

To reproduce, add a temporary body-row product beside the existing NTT/Fourier
GGSW product, retaining its clearing, carry initialization and inverse transform;
in sparse BR call it only for bucket zero. Build separate uninstrumented
`sparse_pbs` and `circuit_bootstrap` binaries for both GLWE backends with
`--features rustfft,tfhe-fft`, rebuilding restored sources with fresh timestamps.
Select `u64/.*sparse.*complete$`, pin to CPU 4 and use the Criterion settings above.
Keep stage probes/capture setup outside measured complete requests and retain
first-bucket material so the key and noise distribution are unchanged.
