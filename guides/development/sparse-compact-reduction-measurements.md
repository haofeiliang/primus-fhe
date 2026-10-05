# Compact sparse bucket reduction

Measured on 2026-10-05, with `52589af6` as the original implementation.
This follows the [consumer parameter study](sparse-consumer-measurements.md),
but holds parameters and cryptographic material fixed within each comparison.
The retained change is local to GLWE NTT's u64 whole-bucket accumulation:
canonicalize each tile with a vector-friendly single-word reciprocal instead
of the scalar two-limb reciprocal calculation. Complete PBS latency falls by
**1.5%–6.0%** across the four profiles and two CPU groups below, using the mean
of two runs per implementation. This is a small arithmetic improvement, not
another parameter reduction or reproduction of the paper's absolute latency.

## Kernel and numerical contract

The current compact layout and 16 KiB destination tiles remain unchanged.
For a bucket of m selectors, the initialized accumulator plus m*q bias keeps
rotated addition/subtraction in `[0,(2m+1)q)`. The existing dispatcher uses this
whole-bucket path only for u64, m>=4 and `(2m+1)q <= u64::MAX`. Other buckets
retain pair accumulation and final single correction. Every dummy/selector
is processed, including encrypted zero entries.

The new reduction accepts any u64 value x. Put `B=2^64`, and take
`mu=floor(B/q)` from the existing Barrett reciprocal's high limb. Then
`floor(x*mu/B)` underestimates `floor(x/q)` by at most one. The same
32-bit partial-product identity used in the existing
[Barrett multiply-add kernel](../../crates/primus_modulus/src/barrett/native.rs)
omits the low-low product and underestimates that high product by at most one
more. Its estimate therefore gives a remainder in `[0,3q)`. Subtracting `2q`
and then `q` conditionally produces exactly `x mod q`.

Every 32-bit partial product fits u64, including the middle carry sum.
The modulus contract `q < 2^62` ensures `3q < B`; the estimated product is at
most x, so its multiplication and subtraction cannot overflow. The canonical
result still satisfies the ordinary NTT entry's `[0,q)` contract. There is no
change to NTT representation, decomposition, summation order or ciphertext noise.

The private implementation checks AVX-512F/DQ outside the coefficient loop.
Its target-feature function uses safe slice iteration and integer arithmetic;
LLVM vectorizes the three 32-bit products. No casts of slice pointers, inline
assembly or C++ dependency are introduced. Unsupported CPUs retain the original
scalar Barrett loop. The u32 path and the insufficient-headroom pair path are
unchanged. Generic Barrett APIs and other backends do not change.

## Selection and isolated cost

A temporary public-API replay first measured the current BR stages, then compared
three final reductions with identical maps, keys, inputs and NTT tables: the
original, an exact single-word high product, and the vector-friendly approximation
with two corrections. The exact single-word alternative was smaller but slower
than the retained vector loop. The following CPU 4 diagnostics averaged 20
instrumented BRs; aggregation includes reduction. They identify a cost to target,
not complete-request benchmark results.

| Profile | Aggregation ms | Final reduction ms | Aggregate NTT ms | External product ms |
| --- | ---: | ---: | ---: | ---: |
| STD128 r3 | 11.616 | 0.389 | 0.491 | 0.495 |
| STD128 r2 | 5.827 | 0.583 | 0.661 | 0.666 |
| Function r3 | 22.819 | 0.617 | 1.297 | 1.449 |
| Function r2 | 7.792 | 0.602 | 1.113 | 1.747 |

Reduction was roughly 3%–8% of the observed BR cost, so improving it cannot
remove the dominant rotation/memory cost. External-product timings include
its decomposition and transforms, not only pointwise multiplication. This step
keeps the existing 7-G multiply-add implementation and does not open a second
pointwise arithmetic experiment: no separate candidate has been justified here.
This is not a finding that further pointwise improvement is impossible.

The isolated microbenchmark reduces one 2,048-element u64 tile per iteration.
Inputs are deterministic values in the actual profile's bounded bucket range;
Setup uses rand 0.10.3 StdRng seed 9876, skips the 49,960 words consumed by
the independent arithmetic screen, then reduces the next words modulo
`(2*max_bucket_len+1)*Q`. Criterion `iter_batched_ref` restores them outside timing, so later iterations
do not accidentally measure only already-canonical values. CPU 4 results show
mean microseconds and individual 95% confidence intervals:

| Q bits | Original | Exact single-word | Retained vector loop |
| --- | ---: | ---: | ---: |
| 28 | 1.5246 [1.5242–1.5250] | 1.1531 [1.1528–1.1533] | 0.2925 [0.2885–0.2963] |
| 54 | 1.5307 [1.5304–1.5309] | 1.1580 [1.1576–1.1584] | 0.2962 [0.2932–0.2989] |

The roughly 81% isolated reduction is not a PBS speedup claim. The retained
private function was copied into this temporary microbenchmark without changing
its body; complete results below use the ordinary production benchmark.

## Fixed complete workloads

AMD Ryzen 9 9955HX3D, rustc/cargo 1.98.1, LLVM 22.1.8, stable/default features,
release and the repository's `target-cpu=native`. CPU 4 and CPU 8 use the
96/32 MiB L3 groups. All compared ciphertexts and controls are u64, including
the 28-bit case; no u32/u64 conversion is hidden in the timed workload.

| Profile | n / h / N | q / Q | r / buckets | BR b/L | Ring KS b/L |
| --- | --- | --- | --- | --- | --- |
| STD128 r3 | 1024 / 43 / 1024 | 512 / 268369921 | 3 / 46 | 7/4 | 7/4 |
| STD128 r2 | Same | Same | 2 / 86 | 7/3 | 7/4 |
| Function r3 | 2048 / 70 / 2048 | 4096 / 18014398509404161 | 3 / 73 | 27/2 | 5/10 |
| Function r2 | Same | Same | 2 / 140 | 27/1 | 5/10 |

These are the existing `std128_nand` and `std128_padded_func3` paper IDs,
with modes `sparse` and `sparse_candidate_r2`. Their q/Q conversions, LUT,
fixed-weight binary input secret, uniform ternary ring secret, all role noise
and ring return are unchanged. Client/server seeds remain 42/4242; inputs are
validated with 43/4343 and timing restores the seed-43 request. The same generated
public map and encrypted key coefficients are used by each paired algorithm.
The original and r2 configurations are separate controls, not mixed into a single
before/after comparison. No new parameter or security claim is made.

Criterion uses 40 flat samples, 0.3 s warmup and a 1.5 s measurement target.
Two release executables differ only in the bucket reduction implementation.
CPU 4 runs original/new then new/original; CPU 8 runs new/original then
original/new. Each process uses the existing benchmark's profile/stage order.
Compilation and tests finish before this timing matrix. Key/input preparation,
validation and reusable allocation happen before `b.iter`; online input lifting,
NAND preprocessing and complete return remain timed.

Cells show the two-run mean range followed by the union of their individual
95% intervals. That union is not an estimated cross-run confidence interval.
Reduction percentages compare the two-run means. All observations are retained;
in particular, the original STD128 r2 CPU 4 complete means vary from 7.036 to
7.259 ms, while function r3's small CPU 4 improvement has overlapping interval
envelopes. Use the measured range rather than assuming a fixed percentage.

### Complete PBS, including ring return

| CPU | Profile | Original ms | New ms | Mean reduction |
| --- | --- | ---: | ---: | ---: |
| 4 | STD128 r2 | 7.036–7.259 [7.014–7.316] | 6.734–6.752 [6.712–6.812] | 5.65% |
| 4 | STD128 r3 | 12.459–12.610 [12.377–12.690] | 12.133–12.213 [12.095–12.302] | 2.89% |
| 4 | Function r2 | 10.721–10.763 [10.691–10.837] | 10.324–10.442 [10.295–10.506] | 3.34% |
| 4 | Function r3 | 25.852–26.096 [25.727–26.297] | 25.539–25.624 [25.415–25.812] | 1.51% |
| 8 | STD128 r2 | 7.675–7.726 [7.641–7.784] | 7.233–7.244 [7.184–7.303] | 6.00% |
| 8 | STD128 r3 | 13.115–13.560 [13.023–14.023] | 12.909–12.911 [12.806–13.060] | 3.20% |
| 8 | Function r2 | 10.955–10.992 [10.895–11.108] | 10.500–10.762 [10.459–10.854] | 3.12% |
| 8 | Function r3 | 26.033–26.623 [25.897–27.240] | 25.390–25.495 [25.238–25.678] | 3.36% |

### Raw blind rotation

| CPU | Profile | Original ms | New ms | Mean reduction |
| --- | --- | ---: | ---: | ---: |
| 4 | STD128 r2 | 7.040–7.224 [6.999–7.263] | 6.712–6.724 [6.683–6.784] | 5.80% |
| 4 | STD128 r3 | 12.402–12.769 [12.337–13.036] | 12.086–12.114 [12.017–12.209] | 3.86% |
| 4 | Function r2 | 10.839–10.841 [10.786–10.921] | 10.195–10.736 [10.111–10.959] | 3.46% |
| 4 | Function r3 | 25.608–25.822 [25.473–26.006] | 25.352–25.461 [25.215–25.689] | 1.20% |
| 8 | STD128 r2 | 7.661–8.023 [7.631–8.239] | 7.172–7.225 [7.142–7.281] | 8.20% |
| 8 | STD128 r3 | 13.110–13.331 [13.016–13.604] | 12.723–12.781 [12.673–12.928] | 3.54% |
| 8 | Function r2 | 10.963–11.057 [10.920–11.158] | 10.362–10.391 [10.325–10.487] | 5.75% |
| 8 | Function r3 | 25.650–25.741 [25.488–25.948] | 24.990–25.238 [24.838–25.459] | 2.26% |

Do not subtract separately timed BR from complete requests to estimate return
cost: their sampling and cache states differ. No classic/sparse comparison or
other backend's performance is inferred from these numbers.

## Validation, resources and reproduction

- Independent full-word `% q` oracles check the reciprocal/correction boundaries,
  small and near-62-bit moduli, deterministic wide inputs and a vector tail.
  The existing direct ring-sum oracle checks rotated bucket tiles, zero and
  odd counts, and capacity boundaries. Both ordinary and nightly SIMD runs pass.
- A temporary replay checks full canonical BR coefficients and returned LWE
  coefficients for exact equality with the public evaluator: four paired key
  configurations, every NAND pair or function input and both input seeds
  (48 requests). Each final implementation is also compared to the original
  private arithmetic copied before modification. It uses no reduced key noise.
- Existing sparse BR, ordinary/interleaved PBS, feedback Boolean and CBS→CMux
  checks pass: seven tests per default/SIMD run, including the focused new
  private reduction oracle. All-targets compilation, strict Clippy, formatting
  and diff checks pass. No full-workspace test run is implied.
- The production benchmark's complete requests report zero online allocations.
  The change adds only scalar temporaries: key/workspace layouts, retained heap
  and required scratch are unchanged. There is no FFI allocation question in
  this Rust-only experiment, and no new benchmark target or CI parameter grid.

Run the maintained workload with:

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs -- \
  'glwe/ntt/u64/paper_2026_1730/std128[^/]*/sparse(_candidate_r2)?/' \
  --sample-size 40 --warm-up-time 0.3 --measurement-time 1.5 --noplot
```

For a pinned comparison, build `52589af6` and the new kernel separately, use
`taskset -c 4` / `taskset -c 8` on their executables, and keep distinct
`CRITERION_HOME` directories. Numerical validation uses the same public APIs as
[the paper request adapter](../../crates/primus_tfhe_glwe_ntt/benches/paper/request.rs).
The temporary replay, instrumentation, alternate kernels and generated timing
assets are removed after recording this report. The production change stays in
[the existing aggregation module](../../crates/primus_tfhe_glwe_ntt/src/sparse/aggregation.rs).

Large CBS/LUT consumers, MEDIUM, NTRU, Fourier and non-AVX-512 performance are
not remeasured here. Canonical equality preserves the consumer's arithmetic and
noise rather than establishing new consumer parameter validity. The earlier
[consumer-specific restrictions](sparse-consumer-measurements.md) still apply.
