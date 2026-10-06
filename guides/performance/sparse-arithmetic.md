# Sparse coefficient arithmetic

[Performance decisions and measurement method](README.md) · [Baseline and parameters](sparse-baseline.md) · [Layout and batching](sparse-layout-and-batching.md)

Retained exact-arithmetic choices are NTRU pairs, bounded NTT pairs, GLWE u64
whole-bucket accumulation with sufficient headroom, and NTRU Fourier u64 four-way
accumulation. Each section identifies its own baseline and measured scope.
The latest direct reassessments are [7-G plus 7-L](#combined-7-g-and-7-l-reassessment)
and [7-H with the current LUT consumer](#current-source-four-way-reassessment).
These comparisons preserve parameters; they are separate from the parameter studies.

All historical tables and counterexamples below remain evidence for their stated
revisions. Shared run discipline is in the [measurement method](README.md#measurement-method);
section-specific filters, seeds, settings and limitations remain with each result.

## NTRU paired coefficient aggregation

Measured on 2026-10-04 against `573dd919`. **Decision: retain pairs for u32 and
u64 in both NTRU backends.** Two adjacent selectors now share the initialized
aggregate traversal through the existing `Nlev` pair method. An odd final
selector uses the single method. The private helper preserves dummy copying,
key order, zero exponents, first-bucket NLEV lifting and later NGSW products.
There is no new backend word-width branch, key layout, scratch allocation,
transform, floating-point operation or public API. This does not change GLWE.

Conditions: Ryzen 9 9955HX3D, rustc 1.98.1,
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
moduli, bases, role-specific noise and fixed seeds follow the [baseline](sparse-baseline.md#conditions-and-workload-pairing).
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

Reproduce using the [common method](README.md#measurement-method) and these targets/settings:

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
this instrumentation in the latency binary.

## Bounded lazy NTT pair

**2026-10-05; baseline `344be16b`. Decision: retain for GLWE NTT and NTRU NTT
u64 sparse aggregation.** u32 keeps its existing single/pair choice. Fourier,
key layouts, aggregation tiles, pair order, dummy initialization, NTT and
external products are unchanged. Every selector is still consumed, including
zero exponents and encrypted zeros; no new workspace or strategy object is added.

### Arithmetic and shared kernel

The two [coefficient-batch functions](../../crates/primus_poly/src/monomial/lazy.rs)
`lazy_add_mul_monomial_pair_assign` and `lazy_add_mul_monomial_assign` accept
canonical sources and an initialized accumulator in `[0,2q)`. For one pair,
fixed interval signs select one of:

```text
acc + a + b
acc + a + q - b
acc + q - a + b
acc + 2q - a - b
```

Adding one `q` per negative source prevents underflow. All intermediates are
below `4q`, which fits the word under the existing Barrett bound
`q < 2^(BITS-2)`. One conditional subtraction of `2q` restores `[0,2q)`;
an odd tail has an intermediate below `3q` and uses the same correction.
At each bucket's end, `ReduceOnceSlice::reduce_once_slice_assign` restores
`[0,q)` before the ordinary NTT. Biases are multiples of `q`, so the canonical
aggregate and downstream ciphertext must be exactly unchanged. The ordinary
NTT input contract is not widened, and no division or full Barrett reduction
is introduced in the pair loop.

The private prototypes were consolidated into these two shared functions.
The flat coefficient kernel retains slice chunks, as does the existing
canonical pair kernel. A separate CPU 4 GLWE PBS BK comparison of otherwise
identical lazy kernels measured polynomial-view iteration at 16.096 / 16.411 ms
versus slice chunks at 15.471 / 15.473 ms. This supports the local traversal
choice, not a general claim about iterators or a diagnosed cache mechanism.
The surrounding NTRU control traversal still uses `NlevIter` and borrowed views.

### Complete requests and normalization cost

The [baseline](sparse-baseline.md#conditions-and-workload-pairing) hardware, toolchain and diagnostic profiles are unchanged:
n728/h32/N1024, r3/B64, Q=1125899906826241, BR base-log 8/L6; GLWE k1.
PBS uses t8, CBS t4, and NTRU nonzero one-hot uses t8/M4 and produces three
controls. Seeds, return keys, LUTs, bases and noise settings match each baseline.
These are functional comparison profiles, not assessed security parameters.

Each saved binary ran in a fresh process and Criterion directory, pinned to
CPU 4 in baseline/candidate/candidate/baseline order, then CPU 8 in the reverse
order for PBS. The normal settings were 30 samples, 0.5 s warmup and a 2 s
measurement target. One iteration performs one complete preallocated request;
setup, keygen, encryption and correctness checks are outside timing. Final
normalization is included. There are no stage timers in these binaries;
temporary fixture captures also run only outside timed iterations. Builds and
tests ran separately from measurements. No workspace SIMD feature was enabled.

Values are milliseconds. Each pair contains the two run means; the last column
is the envelope of their separate 95% CIs, not a pooled confidence interval.
Change compares the average of the two run means. BK means BR→KS, KB means KS→BR.

| CPU / request | Baseline means | Lazy means | Change | 95% CI envelopes, baseline → lazy |
| --- | ---: | ---: | ---: | --- |
| 4 / GLWE PBS BK | 16.263 / 16.263 | 15.414 / 15.437 | -5.2% | [16.243, 16.282] → [15.394, 15.459] |
| 4 / GLWE PBS KB | 16.390 / 16.365 | 15.510 / 15.600 | -5.0% | [16.340, 16.418] → [15.491, 15.726] |
| 4 / GLWE CBS BK | 16.381 / 16.352 | 15.481 / 15.494 | -5.4% | [16.323, 16.418] → [15.457, 15.514] |
| 4 / GLWE CBS KB | 16.430 / 16.412 | 15.661 / 15.665 | -4.6% | [16.387, 16.460] → [15.636, 15.692] |
| 8 / GLWE PBS BK | 17.146 / 17.130 | 16.275 / 16.219 | -5.2% | [17.107, 17.175] → [16.190, 16.301] |
| 8 / GLWE PBS KB | 17.412 / 17.289 | 16.280 / 16.233 | -6.3% | [17.259, 17.454] → [16.207, 16.314] |
| 4 / NTRU PBS | 4.651 / 4.688 | 4.518 / 4.521 | -3.2% | [4.647, 4.700] → [4.512, 4.532] |
| 4 / NTRU CBS | 3.277 / 3.347 | 3.217 / 3.254 | -2.3% | [3.275, 3.365] → [3.197, 3.275] |
| 8 / NTRU PBS | 5.251 / 5.289 | 5.117 / 5.112 | -3.0% | [5.243, 5.307] → [5.104, 5.131] |
| 4 / NTRU one-hot, 30 samples | 3.652 / 3.685 | 3.714 / 3.703 | +1.1% | [3.648, 3.691] → [3.676, 3.730] |
| 4 / NTRU one-hot, 50 samples | 3.659 / 3.636 | 3.547 / 3.545 | -2.8% | [3.634, 3.665] → [3.540, 3.554] |

The short one-hot run regressed, so the same saved binaries were repeated with
50 samples, 1 s warmup and an 8 s measurement target. Both longer candidate
runs improved; retain the short result to show sensitivity to measurement
conditions. Frequency and unrelated system activity were not controlled.
No claim is made that every parameter set, CPU or feature benefits equally.

A separate instrumented PBS binary summed a timer around just the normalization
call in each of the 64 buckets, printing only after the complete BR. On CPU 4,
after excluding the first five requests, the per-request median was **92.838 µs
for GLWE** (147 requests) and **18.376 µs for NTRU** (363 requests). This used
15 samples, 0.3 s warmup and a 1 s target. These diagnostic sums include timer
overhead; they are not subtracted from the complete-request results, and the
instrumented total latency is not used for acceptance.

### Correctness, resources and limits

One permanent [polynomial test](../../crates/primus_poly/tests/monomial.rs)
uses independent u128 scatter arithmetic, covering u32/u64, small and near-limit
Barrett moduli, all sign combinations, equal/wrapping/boundary exponents, empty
batches, multiple polynomials, canonical source endpoints and initialized
accumulators at `0`, `q-1`, `q`, `2q-1`. Repeated pair and odd-tail updates check
the redundant bound before final canonical comparison. Existing NTRU bucket
tests cover dummy reset, empty/odd buckets, nonconsecutive indices and first-NLEV
versus later-NGSW consumption. Existing PBS/CBS/one-hot/LUT tests cover consumers
and reuse, including zero-allocation assertions; no additional large CI case
or benchmark target was added.

Across the baseline, private prototypes and shared-kernel comparisons, all 128
setup captures across seven request IDs matched their coefficient-key
fingerprint, complete input and complete output. The public bucket map was not
separately fingerprinted. Decryption and CMux assertions passed outside timing.
Together with the coefficient oracle this verifies the selected deterministic
workloads, not a statistical noise study.

Key generation, retained key arrays, workspace owners and allocations are
unchanged by construction; the final pass reuses the existing aggregate.
No new retained/peak-memory or keygen-time measurements were made. Logical
source-key reads are unchanged. Cache/TLB counters remain unavailable on this
host; the timing differences do not identify a cache or bandwidth cause.

After removing probes, all-targets workspace check with `ntt,rustfft,tfhe-fft`
passed. The four affected packages (`primus_poly`, the two NTT backends and
`primus_tfhe_ntru_lut` with `ntt`) passed check and clippy (`-D warnings`),
49 default tests and the same 49 tests with nightly SIMD. Strict rustdoc for
the three implementation crates, the existing polynomial doctest and format
checks passed. SIMD performance, u32 performance and full high-precision LUT
latency were not measured here; correctness coverage is not a timing claim.

To reproduce, build and save separate binaries from the baseline and candidate
using `cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs --bench circuit_bootstrap --no-run`,
then repeat for `primus_tfhe_ntru_ntt`. Rebuild restored sources with fresh
timestamps. Run with `taskset -c 4` or `8`, a separate `CRITERION_HOME` per process,
`--bench --sample-size 30 --warm-up-time 0.5 --measurement-time 2 --noplot`.
Use `u64/.*sparse.*complete$` for GLWE, and
`u64/.*(sparse/complete|cbs/sparse/.*/complete|one_hot/sparse/.*/nonzero)$` for NTRU;
use the longer settings above for the one-hot confirmation. Capture full outputs
only in setup. All temporary probes, duplicate kernels and experiment artifacts
were removed; the existing benchmarks remain unchanged.

## Grouped NTT accumulation

**2026-10-05; baseline `1c4ffd97`. Decision: retain a whole-bucket group for
GLWE NTT u64 when at least four selectors fit the word's headroom.** Other
GLWE buckets keep the bounded lazy pair; NTRU keeps that pair for all buckets.
The measured GLWE gains are modest and variable, particularly for CPU 4 PBS.
No public API, key layout, tile size, workspace or online allocation changes.

### Bound and implementation choice

For `m` canonical sources, initialize each canonical aggregate coefficient with
an additional `m*q`. Each rotated source then contributes a value in
`[-(q-1), q-1]`. After any prefix of at most `m` contributions, every coefficient
is nonnegative and less than `(2m+1)*q`. A conservative capacity is therefore:

```text
max_group_len = floor((floor(T::MAX / q) - 1) / 2)
```

The calculation divides before multiplying and caps the result to `usize::MAX`.
The u64 Barrett modulus contract makes the subtraction safe; the chosen bound
also makes `m*q` representable. Other word widths return zero capacity. For the
measured Q=1125899906826241, capacity is 8191; all fixture buckets fit (PBS has
25–48 selectors per bucket, CBS 23–45; each request consumes 2184 selectors).

The private [GLWE aggregation helper](../../crates/primus_tfhe_glwe_ntt/src/sparse/aggregation.rs)
reuses the existing monomial pair and single kernels with `NativeModulus`.
Here native addition/subtraction performs the unreduced signed accumulation;
the bound prevents actual word overflow or underflow. Full Barrett reduction
at the end of each tile restores `[0,q)` before the ordinary NTT. Bias is a
multiple of q, so the canonical aggregate is exactly unchanged. The same pairs,
odd tail, dummy, zero exponents and encrypted zeros are processed.

Initial prototypes also supported several groups with a reduction between
them and copied the coefficient loops locally. The retained implementation
uses existing kernels and `GadgetSize`, and requires the entire bucket to fit.
Buckets shorter than four selectors or exceeding capacity retain the pair
path, avoiding repeated full reductions for short groups without performance
evidence. Group selection uses only public size and modulus. No generic
reduction policy or wider accumulator is introduced.

### Complete requests

Hardware, toolchain, profiles, seeds and request boundaries match the preceding
experiment: n728/h32/N1024, r3/B64, u64 Q1125899906826241, BR logB8/L6 and GLWE k1.
PBS uses t8, CBS t4; NTRU nonzero one-hot uses t8/M4. The complete request includes
bias initialization and final full reductions. Setup, captures and correctness
checks are outside timing; phase timers are absent. Builds/tests and timing
runs are separate, with no workspace SIMD feature.

CPU 4 uses baseline/candidate/candidate/baseline order, 50 samples, 1 s warmup
and an 8 s measurement target. CPU 8 reverses the order and uses 30 samples,
0.5 s warmup and a 2 s target. Each process has a fresh Criterion directory.
The table gives both run means in milliseconds, their average change, and the
envelope of separate 95% CIs; the envelope is not a pooled confidence interval.
BK means BR→KS; KB means KS→BR.

| CPU / GLWE request | Baseline means | Grouped means | Change | 95% CI envelopes, baseline → grouped |
| --- | ---: | ---: | ---: | --- |
| 4 / PBS BK | 15.462 / 15.428 | 15.557 / 14.913 | -1.36% | [15.380, 15.511] → [14.859, 15.641] |
| 4 / PBS KB | 15.577 / 15.566 | 15.811 / 15.080 | -0.81% | [15.522, 15.626] → [15.035, 15.902] |
| 4 / CBS BK | 15.491 / 15.649 | 15.144 / 14.986 | -3.24% | [15.447, 15.719] → [14.948, 15.213] |
| 4 / CBS KB | 15.655 / 15.766 | 15.244 / 15.513 | -2.12% | [15.611, 15.824] → [15.197, 15.716] |
| 8 / PBS BK | 16.556 / 16.358 | 15.679 / 16.194 | -3.17% | [16.215, 16.659] → [15.592, 16.605] |
| 8 / PBS KB | 16.868 / 16.323 | 15.776 / 15.577 | -5.54% | [16.179, 16.993] → [15.458, 15.864] |
| 8 / CBS BK | 17.114 / 16.311 | 15.608 / 15.545 | -6.80% | [16.151, 17.754] → [15.447, 15.687] |
| 8 / CBS KB | 16.980 / 16.369 | 15.848 / 15.902 | -4.79% | [16.224, 17.225] → [15.757, 16.018] |

Early short GLWE runs varied widely and did not establish a gain. Longer
comparisons of both the copied-kernel and reused-kernel prototypes showed
positive average trends, leading to the final restricted implementation above.
One final CPU 4 PBS candidate run is slower in each order and the CI envelopes
overlap. Retention rests on the repeated average trend, CBS and CPU 8 results;
it does not establish a reliable improvement on every invocation, modulus,
machine or feature. Frequency and unrelated activity were not controlled,
so differences between CPU groups do not identify a cache mechanism.

The reused-kernel NTRU prototype was tested independently on CPU 4 with the
same longer settings and order:

| NTRU request | Baseline means | Grouped means | Change | 95% CI envelopes, baseline → grouped |
| --- | ---: | ---: | ---: | --- |
| PBS | 4.550 / 4.593 | 4.484 / 4.470 | -2.07% | [4.531, 4.674] → [4.457, 4.501] |
| CBS | 3.302 / 3.216 | 3.273 / 3.275 | +0.47% | [3.205, 3.315] → [3.258, 3.297] |
| Nonzero one-hot | 3.591 / 3.603 | 3.619 / 3.582 | +0.10% | [3.571, 3.654] → [3.566, 3.635] |

PBS improves slightly, but CBS and one-hot do not show a repeatable gain.
The NTRU prototype is removed, without adding a consumer-specific strategy.
Its CPU 8 or full LUT performance was not measured in this experiment.

### Reduction cost, correctness and limits

A separate GLWE PBS BK diagnostic build timed bias initialization and final
full Barrett reduction around each tile, printing only after BR. There are
64 buckets × 12 tiles per request. On CPU 4, excluding the first five requests,
the medians of 147 per-request sums were **86.299 µs for bias** and
**806.594 µs for reduction**. Settings were 15 samples, 0.3 s warmup and a 1 s
target. Timer overhead is included; this binary is excluded from acceptance
latency. The preceding experiment timed one normalization call per bucket,
so subtracting the two differently instrumented measurements would not give
an isolated reduction-cost difference.

The permanent private oracle uses small N=32 controls and independent u128
negacyclic scatter arithmetic. It covers capacity boundaries, source endpoints,
both signs, zero/equal/wrapping exponents, empty/odd groups, nonconsecutive
indices, short final tiles, row/level crossings and dirty-buffer reuse. The
discarded general prototypes also exercised multiple groups and fallback.
Existing sparse PBS/CBS tests verify consumers and allocation-free reuse;
NTRU PBS/CBS/one-hot regression tests pass after restoring its source.
All **120 setup captures across seven request IDs** match exactly across
baseline, prototypes and final builds: coefficient-key fingerprint, full public
bucket map, complete input and complete output. Decryption and CMux checks run
outside timing. This is deterministic numerical verification, not a noise study.

Key generation, retained key arrays and workspace owners are unchanged;
the bias and reduction passes use the existing aggregate. No new retained/peak
memory or keygen timings were measured, and logical source-key reads are not
reduced. Cache/TLB counters remain unavailable. No u32, SIMD or high-precision
LUT latency claim follows from this experiment.

After removing instrumentation, both NTT backends pass all-targets check and
32 default tests. GLWE passes 17 nightly SIMD tests, all-targets clippy with
`-D warnings`, strict private-item rustdoc and formatting. Both backends'
existing PBS/CBS benchmarks compile. There is one new small oracle test, with
no benchmark/CI expansion; temporary probes, duplicate kernels and experiment
files are removed. Public contracts and recommended workflows are unchanged.

Reproduce with saved baseline and candidate binaries built by
`cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs --bench circuit_bootstrap --no-run`;
repeat for `primus_tfhe_ntru_ntt` when evaluating its rejected candidate.
Rebuild restored files with fresh timestamps. Use `taskset -c 4` or `8`, a fresh
`CRITERION_HOME`, and the filters from the preceding section. CPU 4 arguments
are `--bench --sample-size 50 --warm-up-time 1 --measurement-time 8 --noplot`;
CPU 8 uses `--sample-size 30 --warm-up-time 0.5 --measurement-time 2`. Keep any
fixture capture before `b.iter` and phase probes in a separate binary. The
ordinary benchmark files are unchanged.

## Fourier four-way accumulation

**2026-10-05; baseline `b6e2fa0f`. Decision: retain four-way accumulation for
NTRU Fourier u64 with both FFT engines.** NTRU u32 keeps pairs; GLWE and NTT are
unchanged. This round follows the selected backend/word scope; its positive
signal makes GLWE Fourier and u32 worth separate experiments, not automatic
enablement. No public API, key layout, workspace or online allocation changes.

### Exact arithmetic and code size

The private [aggregation kernel](../../crates/primus_tfhe_ntru_fourier/src/sparse/aggregation.rs)
adds four native coefficient rotations before the existing FFT. Four wrap
points split each polynomial into at most five contiguous intervals. Within an
interval, each contribution has a fixed sign, so one dispatch selects a loop
specialized for those four signs. Each coefficient loads/stores its aggregate
once and consumes all four sources in their original order. Wrapping addition
and subtraction are exact in Z/(2^64); the completed aggregate is identical to
two pair updates. No floating-point addition is moved ahead of coefficient
aggregation, and no FFT or external-product count changes.

The outer bucket traversal retains `NlevIter`, dummy initialization and all
selectors, including zero exponents and encrypted zeros. A tail of 1–3 controls
uses the existing pair/single methods. First-bucket NLEV lifting and subsequent
NGSW interpretation retain their existing shared external product.

A second candidate encoded negative terms as `(x ^ MAX) + 1`, with four sign
masks and one aggregate bias. This avoids 16 specialized loops but adds integer
operations. Both candidates passed the coefficient oracle and complete-output
comparisons. In separate CPU 4 short runs, mask-version average improvements
were PBS 2.21%/0.82%, CBS 1.23%/2.13%, and one-hot 4.78%/0.95%
(rustfft/tfhe_fft); these smaller signals include one-hot baseline variation.
The specialized version's initial short-run gains were 6.76%–17.28%, prompting
the longer final comparisons below. The initial TFHE-FFT one-hot result was
larger than the final confirmation and is not used as the headline gain.

Disassembly of the saved PBS binaries confirms packed `vpaddq`/`vpsubq` and
YMM/ZMM loops without the workspace SIMD feature. The u64 aggregate function,
including its tails, occupies 7125 bytes for pairs, 32591 bytes for the retained
specialization, and 9564 bytes for masks. Thus specialization costs about
25 KiB of machine code. The private two-function implementation is retained
because its complete-request benefit exceeds the smaller mask candidate's
benefit in these comparisons. No public multiway framework or macro-generated
API is introduced; the mask candidate is removed.

### Complete requests

Machine, compiler and native CPU flags match the preceding experiments.
Builds enable `rustfft,tfhe-fft`, without the workspace SIMD feature. Fixtures
remain n728/h32/N1024, r3/B64, native Q=2^64, external q=2^24, BR logB8/L8,
with the same keys, seeds, LUTs and noise. PBS uses t8 and includes return to
LWE; CBS uses t4; compact one-hot uses t8/M4 and produces three NGSW controls.
All 2184 selectors and 64 dummies are consumed. PBS has 519 four-way groups
and 108 tail selectors; CBS/one-hot have 522 groups and 96 tail selectors.
These are arithmetic diagnostic profiles, not assessed security parameters.

One iteration performs one complete preallocated request. Setup, keygen,
encryption, LUT preparation, output capture and validation are outside timing.
No phase timer is present. Builds and tests run separately from measurements.
Each saved executable runs in a fresh process and Criterion directory. CPU 4 uses
baseline/candidate/candidate/baseline order with 50 samples, 1 s warmup and an
8 s target. CPU 8 uses the reverse order with 30 samples, 0.5 s warmup and a
2 s target. The targeted CPU 8 PBS confirmation uses the same reverse order
and longer settings.

Values are milliseconds. Each pair gives both run means; change compares their
averages. CI envelopes combine the separate 95% intervals, not a pooled CI.

| CPU / engine / request | Pair means | Four-way means | Change | 95% CI envelopes, pair → four-way |
| --- | ---: | ---: | ---: | --- |
| 4 / rustfft / PBS | 5.291 / 5.301 | 4.942 / 4.904 | -7.04% | [5.269, 5.349] → [4.899, 4.956] |
| 4 / rustfft / CBS | 4.183 / 4.149 | 3.750 / 3.728 | -10.24% | [4.112, 4.203] → [3.727, 3.754] |
| 4 / rustfft / one-hot | 4.602 / 4.595 | 4.371 / 4.243 | -6.34% | [4.589, 4.617] → [4.241, 4.380] |
| 4 / tfhe_fft / PBS | 5.240 / 5.178 | 4.911 / 4.844 | -6.35% | [5.174, 5.263] → [4.838, 4.976] |
| 4 / tfhe_fft / CBS | 3.935 / 3.976 | 3.634 / 3.579 | -8.84% | [3.920, 3.985] → [3.578, 3.699] |
| 4 / tfhe_fft / one-hot | 4.238 / 4.303 | 3.893 / 3.867 | -9.15% | [4.225, 4.305] → [3.866, 3.894] |
| 8 / rustfft / PBS | 5.796 / 5.804 | 5.644 / 5.634 | -2.78% | [5.793, 5.809] → [5.621, 5.657] |
| 8 / rustfft / CBS | 4.542 / 4.556 | 4.443 / 4.509 | -1.60% | [4.538, 4.562] → [4.440, 4.585] |
| 8 / rustfft / one-hot | 4.960 / 4.982 | 4.872 / 4.850 | -2.21% | [4.957, 5.009] → [4.846, 4.903] |
| 8 / tfhe_fft / PBS | 5.689 / 5.654 | 5.550 / 5.923 | +1.14% | [5.650, 5.693] → [5.545, 6.179] |
| 8 / tfhe_fft / CBS | 4.361 / 4.358 | 4.232 / 4.246 | -2.77% | [4.356, 4.363] → [4.228, 4.258] |
| 8 / tfhe_fft / one-hot | 4.726 / 4.668 | 4.526 / 4.528 | -3.61% | [4.656, 4.842] → [4.521, 4.537] |
| 8 / tfhe_fft / PBS, longer | 5.716 / 5.740 | 5.533 / 5.535 | -3.39% | [5.709, 5.742] → [5.524, 5.552] |

CPU 4's longer comparisons improve by 6.34%–10.24%. CPU 8 generally shows
smaller gains: 1.60%–3.61%, with overlapping CBS intervals for rustfft. The last
short TFHE-FFT PBS candidate run is slower and has a wide interval, making
that pair of means regress by 1.14%. A targeted repeat of the same saved
binaries with longer sampling improves by 3.39%; both results are retained.
Frequency and unrelated system activity were not controlled. These comparisons
do not identify a cache or bandwidth cause or guarantee a gain on every machine.

### Correctness, resources and reproduction

The existing small private bucket oracle was extended, without adding another
test function. N=32 with three levels covers empty buckets, counts 0–13,
multiple four-way groups and every tail length, 16 global-sign patterns,
coincident/distinct wrap points, 0/MAX sources, nonconsecutive input indices and
dirty-buffer reuse. Independent u128 scatter arithmetic checks u64 four-way
aggregation and the retained u32 pair path. Existing consumer tests cover
first-NLEV/later-NGSW phases, PBS, MVB, CBS, one-hot, complete Fourier LUTs and
allocation-free reuse.

All **100 setup captures across six request IDs** match within each FFT engine
across baseline, specialized, mask and final builds: coefficient-key fingerprint,
complete public bucket map, complete input and complete output. Fourier outputs
are captured in full using round-trip float formatting; decryption and CMux
assertions run before timing. The exact coefficient aggregation preserves FFT
inputs; the comparisons verify selected deterministic workloads, not a noise
or security study.

Source-key reads, dummy/FFT/product counts, key generation and workspace owners
are unchanged. Only fixed-size stack arrays and existing buffers are used.
No new retained-key/peak-memory or keygen measurements were made. There is no
GLWE, u32, SIMD-performance or complete-LUT latency result in this round;
correctness coverage does not supply those missing measurements.

Validation: 23 backend/Fourier-LUT tests pass with default and nightly SIMD;
both packages pass all-targets check/clippy with `rustfft,tfhe-fft`. The backend
also passes no-default-feature library check and strict private-item rustdoc;
formatting and restored PBS/CBS benchmark compilation pass. No API or CI expansion.

Build and save baseline/final executables with
`cargo bench -p primus_tfhe_ntru_fourier --features rustfft,tfhe-fft --bench sparse_pbs --bench circuit_bootstrap --no-run`.
Run pinned with `taskset -c 4` or `8`, a fresh `CRITERION_HOME` per process and
filter `u64/.*(sparse/complete|cbs/sparse/.*/complete|one_hot/sparse/.*/nonzero)$`.
CPU 4 uses `--bench --sample-size 50 --warm-up-time 1 --measurement-time 8 --noplot`;
the normal CPU 8 comparison uses 30/0.5/2. The targeted longer CPU 8 PBS repeat
uses `tfhe_fft/u64/.*sparse/complete$` and only the sparse PBS executable.
Keep optional captures outside `b.iter`, and never compare an instrumented
stage-timing executable with an uninstrumented baseline.

### Current-source four-way reassessment

**2026-10-06; source `09e5f1b8`.** This reassesses 7-H against the current
pair counterfactual, retaining 7-J's two-input LUT traversal in both variants.
It does not compare old whole commits or alter FFTs, keys, parameters or noise.
**Recommendation: retain the private u64 specialization.** In the main matrix,
complete PBS/CBS/one-hot latency falls by 1.86%–9.38%; complete polynomial/dense
LUT latency falls by 3.44%–5.60%. These gains justify the measured code-size cost
for these configurations. No extra retained heap or public ownership contract is needed.

The isolated pair variant removes the four-control branch from
`aggregate_bucket`, feeds all controls to its existing pair/single loop, and
removes the private `aggregation` module. Both `INPUTS=1` and `INPUTS=2` remain;
the same dummies, selectors, tails, transforms, external products and returns
are evaluated. The original 16-way sign dispatch remains the candidate; the
previously rejected mask variant is not reopened.

The private two-function module costs 104 lines plus the bucket dispatch;
its [wrap/sign/tail proof](#exact-arithmetic-and-code-size) establishes exact native
sums before FFT without a new noise contract. Only fixed-size stack arrays are added;
public APIs, key fields and retained workspace are unchanged.
In the saved release PBS binary, the u64 single-input aggregate symbol grows from
7,156 to 32,601 bytes (about 25 KiB). Total `.text` grows by 23,008 bytes for PBS
and 42,864 bytes for LUT (about 22/42 KiB); those binary-wide differences include
compiler inlining/layout changes and are not a universal per-instantiation cost.
The LUT binary shares an out-of-line four-way helper between its one/two-input
instantiations. Keygen time and allocator peak were not remeasured. The LUT fixtures
also report identical retained key/workspace/output bytes in both variants.

Both variants pass all 23 existing backend/Fourier-LUT tests, including the
independent u128 ring-sum oracle for every group tail and both input counts.
All **108 untimed capture records** match within each FFT engine: full public
maps, complete inputs, complete returned LWE/Fourier outputs and source-key
fingerprints. PBS/LUT decoding and CBS/one-hot CMux checks pass, and all selected
online calls allocate zero times. Captures cover the fixtures' fixed requests;
this is not exhaustive message/noise sampling. Production sources, CI tests and
public diagnostic APIs are unchanged. Unchanged u32 sparse PBS and u64
classic PBS are negative controls for each FFT engine; their timing changes
are not credited as four-way arithmetic gains.

#### Parameters and complete-request protocol

The u64 PBS/CBS/compact-one-hot fixtures are unchanged from the original study above:
n728/h32/N1024, r3/B64, Q=2^64, external q=2^24, BR b8/L8 and the existing return,
trace and scheme-switch parameters. One-hot emits the three nonzero M=4 controls.
The public-key maps have 2,184 selectors plus 64 dummies; PBS uses 519 four-way
groups plus 108 tail selectors, CBS/one-hot use 522 plus 96.

The added complete LUT profiles use n800/h32/N1024, the same r3/B64 and BR basis,
and eight two-bit input/output chunks with d=5. The polynomial fixture evaluates
`x*x+3*x+7` modulo 2^16; the dense fixture uses the existing seed-42 mapping.
Their maps have 2,400 selectors plus 64 dummies, 575 four-way groups and 100 tails
per BR input. LUT compilation, keys, encryption, reusable buffers and checking
are outside timing; each measured call produces all eight output chunks, with
7-J's paired BR, selection and LWE return. These remain arithmetic diagnostic
parameters; this reassessment makes no parameter/security recommendation.

Ryzen 9 9955HX3D, rustc 1.98.1/LLVM 22.1.8, release, `rustfft,tfhe-fft`, repository
`target-cpu=native`, without portable SIMD. The LUT benchmark also enables its
required `ntt` feature, with only Fourier IDs selected. CPU 4/8 use different
L3 groups; `powersave` and unrelated system activity were not locked. No cache,
frequency or hardware-counter causality is inferred.

Each of 14 workloads runs in four separate processes on each CPU, in ABBA order,
reversing A/B for successive workloads and CPU 8. Each process uses a fresh
Criterion directory, 30 samples, 0.5 s warmup and a 3 s target. LUT keeps Flat
sampling; PBS/CBS/one-hot keep their existing ordinary mode. One iteration is
one complete request; CBS/one-hot output verification by CMux stays untimed.
Builds, tests and capture runs finish before measurements; no phase timers are
inserted. Temporary capture and allocation checks run outside `b.iter`.

[All 124 process measurements](data/sparse-fourier-four-way-reassessment.csv) retain
the individual Criterion means and 95% intervals (112 main plus 12 confirmation
processes, labeled separately). Cells average the two means
per algorithm; negative changes favor four-way. This is descriptive paired data,
not a pooled confidence interval. No process runs or outlier samples are removed.

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

Every neighboring comparison favors four-way in the ten u64 target workloads.
The unchanged controls mostly vary by less than 1%, but CPU 4 tfhe_fft classic
improves by 1.79%, and CPU 8 tfhe_fft u32 initially appears 3.95% faster. The latter
comes from pair means 6.825/6.321 ms against four-way 6.315/6.312 ms. Control
changes are not credited to the four-way arithmetic or subtracted from unrelated
request timings. Individual Criterion intervals do not cover all process-level
variation; no cache/frequency cause was established.

This prompted one bounded confirmation: the CPU 8 u32 control, weakest one-hot
case and tfhe_fft PBS were rerun with the same saved binaries, reversed ABBA
order, 50 samples, 1 s warmup and an 8 s target. Results are additional data,
not replacements for the initial observations:

| CPU 8 longer confirmation | Pair ms | Four-way ms | Change |
| --- | ---: | ---: | ---: |
| Control: tfhe_fft / sparse PBS, u32 | 6.326 | 6.312 | -0.21% |
| rustfft / Compact one-hot, u64 | 5.279 | 4.887 | -7.44% |
| tfhe_fft / PBS, u64 | 5.784 | 5.591 | -3.35% |

The u32 control returns to a 0.21% difference, while tfhe_fft PBS again improves
by about 3.35%. The one-hot pair means are 5.531/5.028 ms against 4.887/4.886 ms:
both comparisons favor four-way, but the changing pair time makes a fixed
one-hot percentage unreliable. The larger 7.44% confirmation mean is therefore
not promoted over the main matrix's modest 1.86% result. All observations remain
in the CSV. The recommendation rests on the complete-request results across
both engines/CPU groups, including the new LUT consumers, and the localized
implementation cost; it is not a guarantee for every processor or parameter.

Reproduce with the maintained `sparse_pbs`, `circuit_bootstrap` and `pipeline`
benchmarks at this commit; only apply the private pair substitution described
above to the comparison copy. Build and save both executables before sampling:

```sh
cargo bench -p primus_tfhe_ntru_fourier --features rustfft,tfhe-fft \
  --bench sparse_pbs --bench circuit_bootstrap --no-run
cargo bench -p primus_tfhe_ntru_lut --features ntt,rustfft,tfhe-fft \
  --bench pipeline --no-run
```

Run each saved executable pinned to CPU 4/8 with one exact CSV benchmark ID,
`--bench --sample-size 30 --warm-up-time 0.5 --measurement-time 3 --noplot`, and a
fresh `CRITERION_HOME`, preserving per-workload ABBA order. Setups differ only
by untimed capture/allocation checks. No SIMD-performance, other-machine, GLWE
four-way or u32 four-way conclusion follows from the controls/correctness checks.

## Compact sparse bucket reduction

Measured on 2026-10-05, with `52589af6` as the original implementation.
This follows the [consumer parameter study](sparse-consumer-measurements.md),
but holds parameters and cryptographic material fixed within each comparison.
The retained change is local to GLWE NTT's u64 whole-bucket accumulation:
canonicalize each tile with a vector-friendly single-word reciprocal instead
of the scalar two-limb reciprocal calculation. Complete PBS latency falls by
**1.5%–6.0%** across the four profiles and two CPU groups below, using the mean
of two runs per implementation. This is a small arithmetic improvement, not
another parameter reduction or reproduction of the paper's absolute latency.

The later [combined reassessment](#combined-7-g-and-7-l-reassessment) compares
7-G plus this reduction against the simpler lazy-pair path on the current source.

### Kernel and numerical contract

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

### Selection and isolated cost

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

### Fixed complete workloads

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

#### Complete PBS, including ring return

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

#### Raw blind rotation

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

### Validation, resources and reproduction

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
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- \
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

## Combined 7-G and 7-L reassessment

**2026-10-06; current source `09e5f1b8`. Recommendation: retain the combination.**
This compares the current whole-bucket accumulation **including vector reduction**
against removing both 7-G and 7-L while retaining the 7-F lazy pair. The eight
u64 target workloads improve by **5.12%–10.39%** across CPU 4/8,
using the means of two processes per algorithm. This is a new direct comparison,
not the sum of the older 7-G and 7-L percentages. Production sources were not changed.

### Controlled difference and validation

The isolated pair variant removes the group-capacity calculation and group branch
from the current GLWE NTT BR, removes its private aggregation module, and always
canonicalizes the lazy pair result once before NTT. It keeps the current 16 KiB
tiles, dummy initialization, source order, odd tails, transforms, external products,
return path, parameters, noise and key generation. Other backends are unchanged.
The original small-q paper adapters and the two diagnostic PBS orders remain
exactly the same consumers on both sides.

The group path adds a private module of 115 non-test lines including rustdoc,
plus the capacity/group dispatch in BR. Its real maintenance obligations are the
`(2m+1)q` bound, the reciprocal error/correction proof and the AVX-512 fallback.
It adds no public type, configuration, key layout or workspace field. Both paths
reuse the existing aggregate; there is no additional retained heap or scratch by
construction. Keygen time and allocator peak were not remeasured.

The selected group workloads all take the whole-bucket branch: observed entries
per bucket are 41–91 / 14–36 for STD128 r3/r2, 61–115 / 15–42 for function r3/r2,
and 25–48 / 23–45 for diagnostic PBS/CBS. All fit their modulus headroom.
The u32 and classic controls do not use this group optimization.

Before timing, the current variant passes 18 existing crate tests; the pair
variant passes the remaining 16 after removing the two group-only private tests.
Temporary untimed captures match in all **61 records**: full public bucket maps,
full inputs and full returned-Q LWE or transformed CBS output arrays are identical;
source-key coefficient fingerprints also match. Paper profiles cover all NAND
pairs or eight function inputs at input seeds 43/4343; diagnostics check PBS
decoding and CBS→CMux. The original paper q→Q exponent checks and q-output phase checks
pass. All selected online requests report zero allocations. No new CI tests or
public diagnostic APIs are retained; this is finite numerical validation, not a
new security/noise claim.

### Complete requests and controls

Same Ryzen 9 9955HX3D, rustc 1.98.1 / LLVM 22.1.8, release/default features and
repository `target-cpu=native`. CPU 4/8 belong to different L3 groups; both support
AVX-512F/DQ. The system's `powersave` governor was left unchanged; frequency and
unrelated host activity were not locked. No hardware-counter/cache-cause claim is
made. Non-AVX-512 performance was not measured; those machines use the scalar
whole-bucket reduction, so these combined gains cannot be extrapolated to them.

Each CPU/workload runs four separate processes in ABBA order, reversing A/B for
successive workloads and for CPU 8. Each process uses a fresh Criterion output
directory, 30 samples, 0.5 s warmup and a 3 s measurement target. Paper workloads
retain Flat sampling; diagnostic PBS/CBS retain their ordinary sampling mode.
One iteration is one complete request. Builds, ordinary tests and capture runs
finish before the timing matrix. Fixed client/server/input seeds, parameters and
LUTs are unchanged. Temporary capture/allocation checks are outside `b.iter`;
there are no phase timers or branch-selection probes in the online loop.

PBS includes its existing complete return; paper NAND also includes affine
preprocessing and q↔Q conversion. CBS times generation of the gadget ciphertext;
its CMux validation remains outside timing. Raw BR or reduction-only speed is not
used as the acceptance metric.

[All 80 process measurements](data/sparse-group-pair-reassessment.csv) retain each
Criterion mean and its individual 95% interval. The table averages the two means
for each algorithm; negative changes favor the group. These are paired descriptive
results, not a pooled confidence interval or a claim for every CPU/parameter.

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

Every neighboring before/after pair favors the group in the eight target
workloads. The two controls remain within −0.54% to +0.36% when comparing
two-process means. Their individual results can be reconstructed from the CSV;
no process runs or Criterion outliers were discarded and no profiles were selected
after seeing this matrix. The measured full-request benefit comes without extra
storage, public ownership contracts or changed ciphertext errors. The evidence
supports retaining it as a local exact-arithmetic optimization. A non-AVX-512
platform, different modulus/bucket geometry or changed compiler still needs its
own complete-request comparison; there is no new parameter recommendation.

### Reproduction and scope

Use the `sparse_pbs` and `circuit_bootstrap` targets at the recorded revision
`09e5f1b8`. At current HEAD the paper IDs moved to `sparse_paper`; the commands
below retain the historical target for that pinned comparison.
For the pair counterfactual, remove only `group_capacity`, `use_groups`, the
`add_rotated_group_assign` branch and the `aggregation` module, then change the
post-bucket condition from `T::BITS == 64 && !use_groups` to `T::BITS == 64`.
Do not revert other commits, alter the lazy pair kernel, or replace the paper
parameters. Save both executables before alternating runs. Representative filters:

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs -- \
  'glwe/ntt/u64/paper_2026_1730/std128[^/]*/sparse(_candidate_r2)?/.*/complete_ring_return$' \
  --sample-size 30 --warm-up-time 0.5 --measurement-time 3 --noplot
cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap -- \
  'glwe/ntt/u64/cbs/sparse/.*/complete$' \
  --sample-size 30 --warm-up-time 0.5 --measurement-time 3 --noplot
```

For the recorded process-level protocol, invoke each saved executable with one
exact CSV benchmark ID, `taskset -c 4` or `8`, `--bench`, the settings above and a
fresh `CRITERION_HOME`. The original and temporary benchmark setups differ only
by untimed capture/allocation checks; these are not a production interface.
Temporary copies, captures and binaries are removed after exporting the results.
No full-workspace/SIMD benchmark or independent 7-L-only attribution is implied.
