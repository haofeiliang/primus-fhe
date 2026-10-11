# Sparse coefficient arithmetic

[Performance guide](README.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks) · [Layout and batching](sparse-layout-and-batching.md)

The retained kernels reduce coefficient-aggregation work without changing the
canonical aggregate, transforms, external products or ciphertext noise. The
arithmetic contracts below describe the current selection rules. The performance
evidence is historical: the two direct reassessments were measured on 2026-10-06
at source `09e5f1b8`, not at current HEAD. Their percentages must not be added to
results against earlier baselines or treated as parameter recommendations.

## Retained arithmetic and fallback

| Path | Selection and fallback |
| --- | --- |
| NTRU NTT | u64 uses bounded lazy pairs; u32 uses canonical pairs. An odd selector uses the corresponding single update. |
| GLWE NTT | u64 uses a whole-bucket group only when at least four selectors fit the modulus headroom; otherwise it uses bounded lazy pairs. u32 keeps canonical single updates. |
| GLWE NTT group reduction | AVX-512F/DQ selects the vector-friendly reciprocal kernel; other CPUs use scalar Barrett reduction. |
| NTRU Fourier | u64 uses groups of four, then pairs/single for the tail; u32 uses pairs/single throughout. |

All paths copy the bucket dummy before accumulating. Empty buckets, zero
exponents and encrypted zero selectors keep their existing meaning; no selector
is skipped. Complete polynomial lengths, valid exponents in `[0,2N)` and matching
control layouts are established by the keys and workspace. Source-key reads are
unchanged. The kernels reuse the existing aggregate, with no extra retained heap,
key field or public configuration.

### NTRU paired coefficient aggregation

Two adjacent selectors share one aggregate traversal, preserving source order;
an odd tail uses a single update. This applies to both NTRU backends, including
the pair fallback of the Fourier four-way path. It preserves first-bucket NLEV
lifting and later NGSW consumption through the same external-product operation.
The [NTT](../../crates/primus_tfhe_ntru_ntt/src/sparse/blind_rotation.rs) and
[Fourier](../../crates/primus_tfhe_ntru_fourier/src/sparse/blind_rotation.rs)
traversals use `NlevIter` and borrowed views. Fusing selector updates does not
change the number of transforms or external products.

### Bounded lazy NTT pair

The [shared polynomial kernels](../../crates/primus_poly/src/monomial/lazy.rs)
accept canonical sources `a,b` in `[0,q)` and an initialized accumulator in
`[0,2q)`. For each interval of constant rotation signs, a pair computes one of:

```text
acc + a + b
acc + a + q - b
acc + q - a + b
acc + 2q - a - b
```

The bias prevents underflow. Intermediates stay below `4q`, representable under
Barrett's `q < 2^(BITS-2)` bound. One conditional subtraction of `2q` restores
`[0,2q)`; a single tail stays below `3q` and uses the same correction. At bucket
completion, one `reduce_once_slice_assign` restores `[0,q)` before the ordinary
NTT. This does not widen the NTT input contract or introduce full Barrett
reduction inside the pair loop. TFHE selects this path for u64 only.

### Whole-bucket GLWE NTT accumulation

For `m` canonical sources, add `m*q` to the canonical dummy accumulator, then
apply rotated contributions in `[-(q-1),q-1]`. Every prefix remains nonnegative
and below `(2m+1)*q`. The conservative capacity is:

```text
max_group_len = floor((floor(T::MAX / q) - 1) / 2)
```

The [aggregation helper](../../crates/primus_tfhe_glwe_ntt/src/sparse/aggregation.rs)
computes this by dividing first and caps it at `usize::MAX`; other word widths
return zero capacity. The dispatcher requires `4 <= m <= max_group_len`, so the
whole bucket must fit. At Q=1125899906826241, capacity is 8191.

Existing native pair/single kernels perform the unreduced signed additions.
The bound prevents actual word wrapping; each tile is then fully reduced before
NTT. Tiles contain complete polynomials, targeting 16 KiB and retaining at least
one polynomial. Short or over-capacity buckets use bounded pairs instead of
multiple groups and repeated full reductions. Selection depends only on public
bucket size and modulus. NTRU does not use whole-bucket grouping.

### Compact sparse bucket reduction

Within the GLWE group path, let `B=2^64`, `x` be any u64 value and
`mu=floor(B/q)`, taken from the high limb of the Barrett reciprocal. The estimate
`floor(x*mu/B)` underestimates `floor(x/q)` by at most one. Computing the high
product from three 32-bit partial products, omitting the low-low product, loses
at most one more. Thus `x-estimate*q` lies in `[0,3q)`; conditional subtraction
of `2q` and then `q` produces the canonical residue.

The partial products and their middle carry sum fit u64. Since `q < 2^62`,
`3q < B`; the estimated product is at most `x`, so multiplication and subtraction
do not overflow. This reduction accepts the whole word, not only the observed
bucket range, and restores the ordinary NTT's `[0,q)` input.

The private helper checks AVX-512F/DQ outside the coefficient loop and lets LLVM
vectorize safe slice arithmetic inside the target-feature function. Unsupported
CPUs retain scalar Barrett reduction. u32, other backends and generic modulus
APIs are unaffected. These dispatch conditions matter: the recorded combined
gains below do not establish non-AVX-512 performance.

### Fourier four-way accumulation

The [NTRU Fourier helper](../../crates/primus_tfhe_ntru_fourier/src/sparse/aggregation.rs)
adds four native coefficient rotations before FFT. Four wrap points split each
polynomial into at most five intervals; a dispatch outside the coefficient loop
specializes the 16 possible sign combinations. Each coefficient loads/stores
its aggregate once and consumes all four sources in their original order.
Wrapping arithmetic is exact in `Z/(2^64)`, giving the same result as two pair
updates. No floating-point sum is reordered. A tail of 1–3 selectors uses pairs
and a possible single update; u32 retains that fallback for the whole bucket.

The cost is code size. In the saved reassessment PBS binary, the u64 aggregate
symbol grew from 7,156 to 32,601 bytes, about 25 KiB. Total `.text` grew by
23,008 bytes for PBS and 42,864 bytes for LUT; those binary-wide differences
include inlining/layout effects and are not a universal cost per instantiation.
Only fixed-size stack arrays are added. A smaller sign-mask candidate did not
match the measured benefit of specialization; it was not retained.

## Reassessment conditions

Both reassessments isolate an arithmetic substitution within `09e5f1b8`; they do
not compare whole revisions. AMD Ryzen 9 9955HX3D, rustc 1.98.1 / LLVM 22.1.8,
release and repository `target-cpu=native` were used without portable SIMD.
Fourier enabled both FFT engines; its historical LUT target also required NTT.
Logical CPU 4 belongs to the 96 MiB L3 group and CPU 8 to the 32 MiB group;
both support AVX-512F/DQ. Compare variants **within each CPU**. Frequency and
unrelated activity were not locked, and no cache or writeback cause was measured.

Each CPU/workload used four fresh processes in ABBA order, reversing A/B for
successive workloads and CPU 8. Each process used a separate Criterion directory,
30 samples, 0.5 s warmup and a 3 s measurement target. Paper and LUT workloads
used Flat sampling; diagnostic PBS/CBS/one-hot kept their ordinary mode. The
Fourier confirmation used 50 samples, 1 s warmup and an 8 s target.

One iteration was one complete request using fixed inputs and reusable buffers.
Key generation, LUT compilation, encryption, allocation and validation were
outside timing. PBS included its return to LWE; paper NAND also included affine
preprocessing and q↔Q conversion. CBS/one-hot timed gadget generation with CMux
validation **outside** timing, unlike the current CBS/one-hot benchmarks. Stage
probes were not included or subtracted from complete-request times.

### Historical workload parameters

These are arithmetic diagnostics, not security/DFR recommendations. In this
table `q` is the external modulus and `Q` the ring modulus; `r/B` gives replica
and bucket counts. `b/L` means decomposition base log and level count.

| Workload | n / h / N | q / Q | r / B | BR b/L |
| --- | --- | --- | --- | --- |
| GLWE STD128 NAND r3 | 1024 / 43 / 1024 | 512 / 268369921 | 3 / 46 | 7/4 |
| GLWE STD128 NAND r2 | same | same | 2 / 86 | 7/3 |
| GLWE padded function r3 | 2048 / 70 / 2048 | 4096 / 18014398509404161 | 3 / 73 | 27/2 |
| GLWE padded function r2 | same | same | 2 / 140 | 27/1 |
| GLWE u64 diagnostic | 728 / 32 / 1024 | Q / 1125899906826241 | 3 / 64 | 8/6 |
| NTRU Fourier u64 PBS/CBS/one-hot | 728 / 32 / 1024 | 2^24 / 2^64 | 3 / 64 | 8/8 |
| NTRU Fourier u64 LUT | 800 / 32 / 1024 | 2^24 / 2^64 | 3 / 64 | 8/8 |

GLWE has k=1. Paper ring KS uses b7/L4 for NAND and b5/L10 for the function;
r2 and r3 are distinct parameter sets, each held fixed across its arithmetic
comparison. The diagnostic PBS/CBS message moduli are 8/4; one-hot uses t8/M4
and emits three nonzero controls. Historical diagnostic bases/noise are recorded
in the [baseline](sparse-baseline.md#conditions-and-workload-pairing); all other
return, trace and scheme-switch settings remain fixed within each comparison.

The LUT workloads have eight two-bit input and output chunks, d=5, and return
all eight output chunks. One evaluates `x*x+3*x+7 mod 2^16`; the other uses a
seed-42 dense mapping. Both variants retain the same two-input blind-rotation
traversal and historical selection/return implementation. These are not the
current M16/d3/c4–6/N4096 complete-tree benchmarks; the old LUT percentages do
not validate performance of the new workload.

## Grouped NTT reassessment

**Decision: retain GLWE u64 grouping with compact reduction within its bounds.**
The comparison disables only group dispatch and its private module in the pair
variant, keeping bounded lazy pairs followed by one canonicalization before NTT.
Both variants retain the same tiles, dummies, source order, odd tails, keys,
transforms, external products, return path and noise. Grouping plus reduction
is measured together, not attributed separately to the two changes.

The [80 process records](data/sparse-group-pair-reassessment.csv) cover ten
workloads on both CPUs. The eight u64 target workloads improve by 5.12%–10.39%;
the unchanged u32/classic controls vary by −0.54% to +0.36%. Each cell below is
the average of two process means per variant, in milliseconds. Negative change
favors the group; per-process 95% intervals remain in the CSV and are not pooled.

| Workload | CPU 4: pair → group ms; change | CPU 8: pair → group ms; change |
| --- | ---: | ---: |
| STD128 NAND r3, u64/Q28 | 13.278 → 12.395; -6.65% | 14.051 → 12.805; -8.87% |
| STD128 NAND r2, u64/Q28 | 7.325 → 6.738; -8.01% | 7.930 → 7.331; -7.55% |
| Padded function r3, u64/Q54 | 28.395 → 25.570; -9.95% | 28.245 → 25.311; -10.39% |
| Padded function r2, u64/Q54 | 11.159 → 10.588; -5.12% | 11.222 → 10.558; -5.92% |
| Diagnostic PBS BR→KS, u64/Q50 | 15.537 → 14.161; -8.86% | 16.274 → 15.091; -7.27% |
| Diagnostic CBS BR→KS, u64/Q50 | 15.791 → 14.587; -7.62% | 16.335 → 15.264; -6.56% |
| Diagnostic PBS KS→BR, u64/Q50 | 15.600 → 14.483; -7.16% | 16.278 → 14.899; -8.48% |
| Diagnostic CBS KS→BR, u64/Q50 | 16.095 → 14.743; -8.40% | 16.347 → 15.008; -8.19% |
| Control: STD128 NAND r3, u32/Q28 | 8.299 → 8.295; -0.05% | 8.812 → 8.844; +0.36% |
| Control: classic PBS BR→KS, u64/Q50 | 12.392 → 12.373; -0.16% | 12.372 → 12.305; -0.54% |

Every neighboring comparison favors the group in the eight targets. Untimed
captures recorded matching public maps, key-coefficient fingerprints, full
inputs and returned LWE/transformed CBS outputs; paper q→Q exponent and q-output
phase checks also passed. The selected buckets all fit the headroom. No new
retained workspace is needed; keygen time and allocator peak were not remeasured.
The evidence supports this local choice on the recorded machine, not a universal
speedup or a new parameter recommendation.

## Fourier four-way reassessment

**Decision: retain the private NTRU Fourier u64 specialization.** The pair variant
removes only the four-control branch and helper, using the existing pair/single
loop for all selectors. Both single-input and two-input instantiations keep the
same dummies, selectors, transforms, products and returns.

The [124 process records](data/sparse-fourier-four-way-reassessment.csv) contain
112 main measurements and 12 longer confirmations. Main PBS/CBS/one-hot means
improve by 1.86%–9.38%, and historical LUT means by 3.44%–5.60%. The table uses
the same two-process mean convention as the NTT table.

| Workload | CPU 4: pair → four-way ms; change | CPU 8: pair → four-way ms; change |
| --- | ---: | ---: |
| rustfft / PBS, u64 | 5.281 → 4.899; -7.23% | 5.854 → 5.657; -3.36% |
| rustfft / CBS, u64 | 4.027 → 3.696; -8.22% | 4.760 → 4.431; -6.89% |
| rustfft / Compact one-hot, u64 | 4.601 → 4.262; -7.36% | 4.980 → 4.888; -1.86% |
| rustfft / Polynomial LUT, u64 | 39.089 → 36.898; -5.60% | 39.216 → 37.858; -3.46% |
| rustfft / Dense LUT, u64 | 40.683 → 38.830; -4.55% | 41.035 → 39.624; -3.44% |
| tfhe_fft / PBS, u64 | 5.203 → 4.843; -6.93% | 5.753 → 5.578; -3.05% |
| tfhe_fft / CBS, u64 | 3.976 → 3.603; -9.38% | 4.633 → 4.285; -7.52% |
| tfhe_fft / Compact one-hot, u64 | 4.277 → 3.882; -9.25% | 4.865 → 4.545; -6.58% |
| tfhe_fft / Polynomial LUT, u64 | 35.935 → 33.954; -5.51% | 36.746 → 35.228; -4.13% |
| tfhe_fft / Dense LUT, u64 | 37.739 → 35.738; -5.30% | 38.369 → 36.825; -4.02% |
| Control: rustfft / sparse PBS, u32 | 6.057 → 6.045; -0.20% | 6.660 → 6.676; +0.25% |
| Control: rustfft / classic PBS, u64 | 6.405 → 6.373; -0.50% | 7.583 → 7.538; -0.60% |
| Control: tfhe_fft / sparse PBS, u32 | 5.753 → 5.711; -0.73% | 6.573 → 6.313; -3.95% |
| Control: tfhe_fft / classic PBS, u64 | 5.377 → 5.281; -1.79% | 6.802 → 6.807; +0.08% |

Every neighboring comparison favors four-way in the ten u64 targets. However,
the unchanged CPU 8 TFHE-FFT/u32 control initially appears 3.95% faster: pair
means were 6.825/6.321 ms against 6.315/6.312 ms. CPU 4 TFHE-FFT/classic also
varies by 1.79%. These changes are not arithmetic gains and are not subtracted
from other timings. Individual Criterion intervals do not capture all
process-level variation.

The same saved binaries were rerun on CPU 8 with reversed ABBA order and longer
sampling. These observations supplement rather than replace the main matrix:

| CPU 8 longer confirmation | Pair ms | Four-way ms | Change |
| --- | ---: | ---: | ---: |
| Control: tfhe_fft / sparse PBS, u32 | 6.326 | 6.312 | -0.21% |
| rustfft / Compact one-hot, u64 | 5.279 | 4.887 | -7.44% |
| tfhe_fft / PBS, u64 | 5.784 | 5.591 | -3.35% |

The u32 control narrows to 0.21%; PBS again improves by about 3.35%. One-hot's
pair means are 5.531/5.028 ms against 4.887/4.886 ms, so its fixed percentage is
unreliable. The larger confirmation does not replace the modest 1.86% main result.
Untimed captures matched full inputs/outputs, public maps and key fingerprints
within each FFT engine. The exact coefficient sums preserve the FFT inputs;
these checks are finite evidence, not noise or security analysis. The retained
code-size cost is justified by the measured complete requests, without extra
heap ownership. GLWE/u32 four-way and portable-SIMD performance were not measured.

## Earlier decisions and counterexamples

The earlier reports supply evidence for choices not isolated by the two direct
reassessments. These summaries refer to 2026-10-04/05 measurements on the same
machine; their detailed historical tables remain in Git, not in the two CSVs.
Each percentage compares its own baseline and cannot be combined with another.

| Comparison baseline | Observation and retained scope |
| --- | --- |
| NTRU pairs, `573dd919` | Complete PBS improved 7.1%–23.9% across NTT, both FFT engines, u32/u64 and both CPUs. CPU 4 CBS/one-hot improved 4.1%–30.8%; the smallest NTT/u32 CBS effect had overlapping intervals. Retain pairs and odd tails. |
| Bounded lazy NTT pairs, `344be16b` | Complete GLWE PBS/CBS improved 4.6%–6.3%; NTRU PBS/CBS improved 2.3%–3.2%. NTRU one-hot first regressed 1.1%, then improved 2.8% with longer sampling of the same binaries. Retain the u64 path, without promising uniform gains. |
| Whole-bucket grouping, `1c4ffd97` | GLWE results were modest and variable, including slower individual runs. NTRU's trial improved PBS 2.07% but changed CBS/one-hot by +0.47%/+0.10%; the NTRU group path was rejected. |
| Fourier four-way, `b6e2fa0f` | CPU 4 improved 6.34%–10.24%; CPU 8 usually gained less. TFHE-FFT PBS regressed 1.14% in short runs, then improved 3.39% with longer sampling. The later direct reassessment above includes both controls and LUT consumers. |
| Compact reduction, `52589af6` | Holding each paper profile fixed, full PBS improved 1.51%–6.00%. The much larger isolated reduction gain was not a PBS gain. The joint reassessment above tests grouping and reduction against lazy pairs directly. |

No hardware counters established a cache/writeback explanation. Finite exact
output comparisons support unchanged arithmetic for the measured requests;
prior test counts or allocation probes are not current test-coverage claims.

## Reading and reusing the retained data

Both CSVs retain every process mean and individual 95% interval. Their fields are:

| Field | Meaning |
| --- | --- |
| `cpu` | Pinned logical CPU on the recorded host, not a portable core class |
| `workload` | Zero-based workload index within this CSV; use `bench_id` to identify it |
| `bench_id` | Exact historical Criterion workload ID, not a current Cargo target |
| `algorithm` | NTT: `pair_7f` is bounded lazy pairs; `group_7g_7l` is whole-bucket grouping with compact reduction. Fourier: `pair` / `four` identifies pair-only / four-way aggregation. |
| `run_order` | Process position 0–3 for that CPU/workload/round, not a sample index |
| `mean_ms`, `ci95_low_ms`, `ci95_high_ms` | One process's Criterion mean and its 95% confidence interval, in milliseconds |
| `round` (Fourier only) | `main` or `confirmation`; keep them separate |
| `sample_size`, `warmup_s`, `measurement_target_s` (Fourier only) | Criterion settings for the process; the target duration is not a runtime cap |

The NTT file has 10 workloads × 2 CPUs × 4 processes = 80 rows, all using
30/0.5/3 settings. The Fourier file has 14 × 2 × 4 = 112 main rows plus three
CPU 8 confirmations × 4 = 12 rows. To reproduce a table cell, average the two
`mean_ms` values for each algorithm in the same CPU/workload/round, then compute
`100 * (candidate_mean / pair_mean - 1)`. Do not average CI endpoints into a
pooled interval or discard the unchanged controls.

Historical ID components distinguish `BootstrapKeyswitch` (BR→KS),
`KeyswitchBootstrap` (KS→BR), `complete_ring_return` (the paper ring return),
`nonzero` (the three M4 one-hot controls) and `c8_d5_o8` (the old LUT geometry).
`dense_seed42` names the dense random function. In the paper IDs,
`sparse_candidate_r2` selects the two-replica parameter set rather than a
second arithmetic algorithm. `tfhe_fft` is the historical ID spelling of the
TFHE-FFT engine. These IDs are preserved to interpret the data, not offered as
filters for current targets.

The CSVs preserve process summaries, not raw Criterion samples, capture arrays,
executable hashes or counterfactual binaries. Rebuilding the original comparison
requires the recorded revision, fixtures, isolated substitutions and sampling
protocol; this documentation cleanup did not reconstruct or rerun them. Current
crate-local workloads and commands are in the [benchmark guide](../development/testing.md#tfhe-benchmarks)
and [high-precision guide](../development/testing.md#high-precision-lut-benchmarks).
Changing a workload or backend requires a new complete-request comparison;
renaming an old target does not reproduce these measurements.
