# Sparse PBS comparison with ePrint 2026/1730

[Performance decisions and measurement method](README.md)

The GLWE NTT `sparse_paper` benchmark has `paper_2026_1730` IDs.
They compare the current implementation using the geometry of Table 3 in
[New Techniques for Fast and Shallow FHE Bootstrapping and Beyond](https://eprint.iacr.org/2026/1730).
They are an explicit adaptation, not a reproduction of the authors' executable
or a new set of assessed security parameters. The older n728/h32 IDs retain
their original parameters and Criterion histories.

With the initial profiles, sparse is slower than Primus dense classic for gates and
1.47–1.55 times faster for the three-bit function on the two measured cores.
These ratios use Primus classic as their baseline; they do not directly test
the paper's 4.5–7.5 times improvement over OpenFHE. The same-machine OpenFHE
reference below illustrates this distinction without reproducing the authors'
sparse implementation.
Separate stage diagnostics identify coefficient aggregation as the dominant
cost; fewer external products alone do not predict the measured speedup.

The current gate fixtures now evaluate **NAND on two fresh ciphertexts**, rather
than NOT through a PBS. Their IDs are `std128_nand` / `medium_nand`; the function
ID is `std128_padded_func3`. `complete_ring_return` names the actual return
algorithm. The original NOT results below remain explicitly historical, not
silently relabeled NAND measurements. The alignment audit below distinguishes
matched contracts from remaining implementation differences.

A subsequent [copy/bucket parameter experiment](sparse-parameter-measurements.md)
holds these profiles' decomposition, noise and return path fixed. Two copies
with B=2h reduce complete-request latency by 15.7–45.1% against the original
sparse configurations on the two measured CPU groups. The report also records
the h70/B73 map-matching failure rate and conditioning limits. These remain
research candidates; the registered benchmarks and historical comparisons below
retain their original parameters.

## Parameters and comparison boundary

Section 7.1/Table 3 uses three copies and h+3 buckets for general sparse binary
secrets. Matching failure causes map resampling during key generation; it does
not authorize skipping encrypted zero selectors online. The paper's STD128 and
MEDIUM labels refer to its reported estimates of 120 and 103 bits, respectively.
Those estimates are not transferred to this adapted return path.

| Profile | Dense n | Sparse n / h / buckets | N | External q | Actual NTT Q | BR log base / levels / dropped bits | Ring KS log base / levels / dropped bits |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| std128_nand | 503 | 1024 / 43 / 46 | 1024 | 512 | 268369921 | 7 / 4 / 0 | 7 / 4 / 0 |
| medium_nand | 422 | 1024 / 31 / 34 | 1024 | 512 | 268369921 | 10 / 2 / 8 | 7 / 4 / 0 |
| std128_padded_func3 | 1350 | 2048 / 70 / 73 | 2048 | 4096 | 18014398509404161 | 27 / 2 / 0 | 5 / 10 / 4 |

Q is the largest prime below 2^28 or 2^54 with Q=1 mod 2N. Gates use the
same Q in u32 and u64; the 54-bit profile cannot fit u32. `PowOf2Modulus`
represents q, `BarrettModulus` represents Q. The GLWE dimension is one and
the ring secret is uniform ternary. Input, BR-key and ring-KS noise each use
sigma=3.19 in their own coefficient domain. The input is actually sampled at q;
the family parameters' rescaled small-LWE sigma is not used to sample it at Q.

Each profile has three independently named comparisons:

- `dense_ternary_classic`: dense ternary at the reference dimension. The cited
  [OpenFHE key generator](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/lwe-pke.cpp#L43-L46)
  uses ternary secrets; treating this baseline as binary would change its work.
- `fixed_weight_classic`: classic BR with the sparse side's identical fixed-weight
  binary secret, ciphertext and LUT. This isolates algorithm cost within Primus.
- `sparse`: the same fixed-weight secret, three copies, h+3 buckets. All 3n
  selectors and all dummies remain encrypted and processed.

Fixed-weight classic is a control experiment, not a cheaper dense-classic
configuration. For STD128 gates the work differs as follows; counts ignore the
small number of skipped public zero exponents:

| Mode | Secret | Coordinate or bucket external products | Additional sparse aggregation |
| --- | --- | ---: | --- |
| Dense classic | 503 uniform ternary coefficients | 503 fused ternary products | None |
| Fixed-weight classic | 1024 binary coefficients, exactly 43 ones | 1024 binary products | None |
| Sparse | The same 1024/43 secret | 46 bucket products | Rotate/add all 3072 selector controls |

Classic cannot skip secret zero coordinates: their encryptions still contain
full random masks and noise, and the server does not know their locations.
Ternary's two controls are combined before one external product per coordinate.
Consequently fixed-weight classic performs roughly twice as many decomposition
and transform rounds here, despite almost the same control-key payload. Its
being slower does not mean that binary CMux is slower than ternary CMux at a
fixed dimension. MEDIUM compares 422 versus 1024 coordinates, and the function
profile compares 1350 versus 2048. Only fixed-weight classic versus sparse holds
the entire client parameter set and input fixed.

The 503/1350 dense dimensions are the paper's introductory examples. MEDIUM's
422, sigma and gadget radices come from its cited
[OpenFHE context revision](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/binfhecontext.cpp).
That revision's STD128 preset actually lists n=512, q=1024, a 27-bit Q and
Q'=2^14; its functional constructor lists n=1305. Thus combining the paper's
geometry with that revision's omitted values is not a fully specified replica.
In particular, MEDIUM's q changes from OpenFHE's 1024 to Table 3's 512. No
lattice-estimator run or equality of failure probabilities has been established.

## What is adapted

The existing GLWE evaluator uses one Q for small-LWE, accumulator and ring KS.
Only the benchmark adds this pipeline:

```text
LWE at q -> coefficient lift to Q -> existing BR -> ring KS at Q
         -> compact extraction -> coefficient switch back to q
```

Both switches are timed in `complete_ring_return`; buffers and conversion
precomputation are reused. Since q divides 2N, the lift preserves the exact
exponents a*(2N/q).
Setup checks this equality for every mask/body coefficient in its input corpus.
The same signed secret is re-encoded at q without scaling its coefficients.

OpenFHE's sampled LWE switch at the paper's Q'=2^12/2^35 is **not** present.
Our return key encrypts ring material at Q under the padded small secret; this
changes the key/noise/security setting as well as computation. No production
parameter capability or public key-return interface is changed for this bench.

Other differences that matter to interpretation:

- MEDIUM uses this library's approximate floor(28/10)=2 levels, dropping eight
  bits; OpenFHE's full base-2^10 expansion would use three digits. The functional
  ring KS similarly retains ten base-2^5 levels at Q, rather than switching LWE
  at Q'. These adaptations are explicit in the table and numerical checks.
- Gate timing evaluates NAND with unsigned Boolean input scale q/4 (t=4): add
  two independent fresh inputs at q, use a signed LUT at floor(Q/8)+1, perform
  one PBS, add that positive bias and switch back to q. The functional workload is
  `f(m)=(m*m+3*m+1) mod 8`, t=16 including padding, using one PBS. Table 2 reports
  Boolean gate evaluation and arbitrary-function evaluation in OpenFHE. Its
  sparse arbitrary-function times carry an asterisk: microbenchmark estimates.
  The cited OpenFHE [EvalFunc implementation](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/binfhe-base-scheme.cpp#L188-L269)
  uses one bootstrap for a negacyclic function and two for its general-function
  branches. Thus the reported arbitrary-function workload needs its exact
  function, padding/domain and bootstrap count identified before comparison
  with Primus's single padded PBS; Table 2 alone does not resolve this.
- Primus [classic ternary BR](../../crates/primus_lattice/src/ggsw/ntt/ternary.rs)
  combines its two controls into one external product:
  `input + (positive - X^-a * negative) ⊠ ((X^a - 1) * input)`.
  It reuses all online workspace. The cited
  [OpenFHE update](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/rgsw-acc-cggi.cpp)
  shares decomposition but accumulates two control matrix products and constructs
  temporary storage during updates. Sparse BR aggregates coefficient controls,
  transforms each aggregate, then applies an external product. These are source
  differences, not an isolated measurement of their contribution to the gap.
- This comparison has no structured-sparse preprocessing, tree-shaped
  bootstrapping, NTRU adaptation or Fourier timing. Their assumptions and moduli
  cannot inherit these profiles by replacing a backend name.

## Alignment audit: what the millisecond numbers mean

Table 2's sparse-binary Boolean **7.9 / 5.8 ms are measured**, not the estimated
arbitrary-function entries marked with an asterisk. A slower OpenFHE baseline
does not explain those absolute sparse times. Section 7.2 explicitly describes
the Boolean TFHE and Algorithm 2 arithmetic as **32-bit**. This supports comparing
the gate profiles with Primus u32; it does not identify the authors' exact
compiler flags or prove that they selected CMake `NATIVE_SIZE=32`.

Algorithm 2 replaces hundreds of coordinate products by 46/34 bucket products,
at the cost of rotating/adding all 3072 encrypted selectors. Section 4.3 also
describes storing each coefficient polynomial as `[-p, p, -p]`: a monomial
rotation becomes a contiguous N-element view, and the following addition reads
that view directly. This triples that key storage, but avoids materialized
rotations and online coefficient negation. Table 2's “No Prep.” excludes the
large NTT-domain preprocessing scheme; it must not be read as excluding all
coefficient-layout optimization. The paper supplies no executable with which
to verify the exact layout used for each timing.

This is an **Algorithm 2** optimization. Algorithm 3 begins in Section 5 and
uses the separate low-depth construction; it is not needed for bucket-based
sparse blind rotation or the expanded coefficient layout.

Primus already fuses rotation into aggregation, with no temporary rotated
polynomial. It retains one copy of each coefficient polynomial and performs
signed segment additions online. The three-copy layout is therefore a distinct
tradeoff, measured in the follow-up below, not an automatic threefold speedup. The old u32
STD128 sparse result, 8.239 ms, was already close in absolute scale to 7.9 ms;
the old u64 result, 12.466 ms, used twice the coefficient storage. Neither is
an equal-machine reproduction. MEDIUM also changes the number of gadget levels.

The current alignment is:

| Contract | Primus benchmark | Cited OpenFHE / paper boundary |
| --- | --- | --- |
| Gate operation | Two independent fresh Boolean inputs, NAND, one PBS | Same NAND and input convention in the fresh-input check below; the original OpenFHE benchmark refreshes its inputs during setup |
| Gate encoding | Unsigned 0/1 at q/4; internal opposite values floor(Q/8)+1, followed by a positive bias | Same semantic gate scale and truth table |
| q, Q and dense dimension | q=512, Q=268369921, n=503/422, N=1024 | Matched in the explicit-parameter OpenFHE check below; its unmodified presets differ |
| LUT coefficient layout | Dense negacyclic LUT, rotations on the q grid | OpenFHE `BootstrapGateCore` fills every `2N/q`-th coefficient and leaves the others zero; same values at reachable noiseless phases, different intermediate layout |
| STD128 BR basis | Base 128, four signed levels, no dropped bits | Same base and level count in the explicit-parameter check; decomposition conventions need not produce identical digits |
| MEDIUM BR basis | Base 1024, two levels, eight dropped bits | The cited OpenFHE implementation uses three full digits. The authors' sparse artifact is unavailable; do not claim their exact retained levels are known |
| Return | Ring KS at Q, compact extraction, Q→q | OpenFHE extracts at Q, switches Q→Q', applies a digit-value-table LWE KS, then switches Q'→q; Table 3 specifies Q'=4096 for gates |
| Three-bit function | Eight inputs in t=16, one padded PBS | OpenFHE's general `EvalFunc` paths use two bootstraps; this benchmark does not reproduce that full-domain operation |
| Online resources | Reused outputs/workspace, zero allocations | The unmodified OpenFHE call allocates and destroys temporary/returned objects; both timers exclude key generation |

In particular, OpenFHE's
[LWE return](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/lwe-pke.cpp)
stores an encryption of `s[i] * digit * B^level` for **every digit value**. Online
switching selects and subtracts one entry per digit; it does not multiply a
single encrypted gadget weight by that digit. Primus's ordinary
`LweKeySwitchingKey` uses the latter multiplication strategy. Merely substituting
it at Q'=4096 would change both key size and key-switch noise, even at identical
base and level count. This audit does not silently implement a new return scheme
or change the production parameter API to manufacture an end-to-end match.

Use `blind_rotation` to exclude return costs within Primus. Cross-library full
timings below remain implementation diagnostics; the unresolved basis, layout,
return and noise/security settings prevent declaring an equal-security speedup.

## Initial measurement: NOT through PBS

These measurements precede the NAND alignment. The old `*_gate/complete` IDs
ran NOT through one PBS, not a two-input gate. Their parameters, stage probes
and payload counts remain useful historical diagnostics. Use the current NAND
IDs below for new gate measurements; do not compare Criterion histories across
the workload change.

Measured on 2026-10-05 after `ff6969e4`, with only benchmark/document changes.
AMD Ryzen 9 9955HX3D, rustc 1.98.1 / LLVM 22.1.8, repository native release
configuration, no workspace SIMD feature. CPU 4 has the 96 MiB shared L3 group;
CPU 8 has the 32 MiB group. Single-thread requests, no concurrent builds/tests.
Frequency and background system activity were not controlled.

The screen uses 20 samples, 0.5 s warmup and a 2 s measurement target, flat
sampling, with separate Criterion directories for each CPU. One iteration is
one request. `complete` includes the adapter, BR, ring KS and extraction;
`blind_rotation` starts from the lifted input and excludes the adapter/return.
Setup, keygen, LUT creation, validation and allocations are untimed.

The complete-request confirmation uses 40 samples, 1 s warmup and a 4 s target.
It runs CPU 8 then CPU 4, reversing the screen's CPU order; each ID runs in a
fresh process, in reverse ID order (sparse, fixed-weight classic, dense classic
within each profile). The table contains confirmation mean point estimates in
milliseconds. Ratios are **classic / sparse**; values above one favor sparse.

| CPU | Profile / word | Dense classic | Fixed-weight classic | Sparse | Dense / sparse | Fixed / sparse |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 4 | std128_gate / u32 | 4.658 | 6.583 | 8.239 | 0.57 | 0.80 |
| 4 | std128_gate / u64 | 7.805 | 12.231 | 12.466 | 0.63 | 0.98 |
| 4 | medium_gate / u32 | 2.234 | 3.832 | 2.937 | 0.76 | 1.30 |
| 4 | medium_gate / u64 | 3.313 | 6.095 | 5.548 | 0.60 | 1.10 |
| 4 | std128_func3 / u64 | 41.408 | 50.657 | 26.686 | 1.55 | 1.90 |
| 8 | std128_gate / u32 | 5.174 | 7.800 | 8.877 | 0.58 | 0.88 |
| 8 | std128_gate / u64 | 7.780 | 12.211 | 13.073 | 0.60 | 0.93 |
| 8 | medium_gate / u32 | 2.265 | 4.073 | 4.361 | 0.52 | 0.93 |
| 8 | medium_gate / u64 | 3.691 | 7.472 | 6.332 | 0.58 | 1.18 |
| 8 | std128_func3 / u64 | 38.458 | 48.344 | 26.189 | 1.47 | 1.85 |

The screen gives the same ordering against dense classic. Differences between
runs remain: CPU 8's dense u32 STD128 gate moves from 4.748 to 5.174 ms. This
does not change the gate/function conclusion, but small fixed-weight gaps,
especially 0.98 times, are not established performance advantages. MEDIUM u32
changes its fixed-weight ordering across cores; do not generalize one core's
result to all cache topologies.

In the CPU 4 screen, `blind_rotation` alone costs 8.325/12.589 ms for sparse
STD128 gates (u32/u64) and 25.674 ms for the sparse three-bit function. Its
corresponding complete times are 8.335/12.547/26.174 ms. BR dominates these
requests. These are independent estimates; subtracting them is not a reliable
measurement of the return stage.

Table 2 reports OpenFHE-to-sparse gate times of 36.5 to 7.9 ms for STD128 and
30.1 to 5.8 ms for MEDIUM, and 391.5 to an **estimated** 53.5 ms for arbitrary
functions: about 4.62, 5.19 and 7.32 times. The current experiment uses different
software, hardware and the adaptations above. It compares implementations
inside Primus and does not establish an equal-security reproduction or refute
the paper's operation counts.

### Key payload and numerical diagnostics

For GLWE dimension one, each control contains `4*L*N` coefficients. Dense
ternary has `2*n` controls, fixed-weight classic `n`, and sparse `3*n+B`.
The exact payload below is in MiB (2^20 bytes); it excludes map metadata, return
keys, workspaces and allocator overhead. Classic stores transformed controls;
sparse stores coefficient controls. Both use the stated coefficient word.

| Profile / word | Dense classic MiB | Fixed-weight classic MiB | Sparse MiB | Maximum q-phase error, dense / fixed / sparse |
| --- | ---: | ---: | ---: | --- |
| std128_gate / u32 | 62.875 | 64 | 194.875 | 7 / 4 / 2 |
| std128_gate / u64 | 125.750 | 128 | 389.750 | 7 / 1 / 4 |
| medium_gate / u32 | 26.375 | 32 | 97.0625 | 13 / 3 / 7 |
| medium_gate / u64 | 52.750 | 64 | 194.125 | 6 / 4 / 6 |
| std128_func3 / u64 | 337.500 | 256 | 777.125 | 16 / 4 / 5 |

Every fixture decodes the checked corpus correctly and makes zero online
allocations. The nearest-message margins are 64 at q=512/t=4 and 128 at
q=4096/t=16. These finite-corpus residuals do not establish failure probabilities.

### Sparse stage diagnosis

A temporary probe timed, per bucket, (1) dummy initialization, rotated selector
aggregation and normalization, (2) aggregate-control NTT, and (3) external
product. Input quantization, initial LUT rotation, final copy and log printing
are outside those phase timers. The probe was removed and the original source
restored byte-for-byte afterward; none of the full timings above are instrumented.

Two fresh smoke processes per CPU checked the same inputs, dropping the first
BR after each key generation. This leaves 10 observations per gate profile and
34 per function profile. The table gives component medians in milliseconds on
CPU 4. The aggregate fraction uses the sum of those medians, not the complete
request's independently measured mean.

| Profile / word | Aggregate | Control NTT | External product | Aggregate fraction |
| --- | ---: | ---: | ---: | ---: |
| std128_gate / u32 | 7.678 | 0.260 | 0.290 | 93.3% |
| std128_gate / u64 | 11.555 | 0.519 | 0.498 | 91.9% |
| medium_gate / u32 | 3.443 | 0.106 | 0.137 | 93.4% |
| medium_gate / u64 | 5.310 | 0.196 | 0.218 | 92.8% |
| std128_func3 / u64 | 23.078 | 1.259 | 1.440 | 89.5% |

CPU 8 gives aggregate fractions of 92.9%, 91.4%, 94.2%, 92.8% and 88.7% in
the same order. Instrumentation changes code layout and timing; for example,
the CPU 4 MEDIUM/u32 component sum is noticeably above its uninstrumented
complete time. Use these probes to identify the dominant phase, not to derive
precise overheads or speedups from the two timing methods.

### Implications for further work

The [sparse loop](../../crates/primus_tfhe_glwe_ntt/src/sparse/blind_rotation.rs)
already performs one external product per bucket, as intended. Reducing that
count to 46/34/73 still leaves all 3n selector controls to rotate and add. It also
needs `4*L` control NTTs per bucket before the external product's `2*L` forward
and two inverse transforms. The key payload and the phase measurements explain
why counting only external products is insufficient.

Prioritize aggregation and its source-key traffic in subsequent experiments.
Fewer copies or decomposition levels could reduce that work, but require joint
matching, noise and security analysis before becoming parameter recommendations.
These measurements do not isolate memory bandwidth, cache misses, writeback
latency or arithmetic cost inside aggregation; hardware counters or a controlled
kernel experiment are still needed for such attribution. The three-bit profile
already shows a useful algorithmic gain, whereas these gate profiles do not.

A strict comparison with the paper additionally needs the authors' exact
baseline parameters, Q'-based LWE return and failure/security assessment. No
production parameter or return-path redesign is part of this benchmark change.

## NAND measurements after alignment

The new `*_nand/complete_ring_return` IDs use the same machine, compiler and
parameters as above. Each ID runs in a fresh process with 40 flat samples,
one-second warmup and four-second measurement target. CPU 4 runs lexicographic
ID order; CPU 8 reverses it. The two CPUs run sequentially, without concurrent
builds/tests. Both input messages are one, independently encrypted from input
RNG seed 43. Means are milliseconds per complete NAND.

| CPU | Profile / word | Dense classic | Fixed-weight classic | Sparse |
| ---: | --- | ---: | ---: | ---: |
| 4 | std128_nand / u32 | 4.632 | 6.655 | 8.313 |
| 4 | std128_nand / u64 | 8.053 | 12.135 | 12.500 |
| 4 | medium_nand / u32 | 2.224 | 3.757 | 2.929 |
| 4 | medium_nand / u64 | 3.265 | 5.999 | 5.522 |
| 8 | std128_nand / u32 | 4.683 | 8.105 | 8.846 |
| 8 | std128_nand / u64 | 8.358 | 12.269 | 13.143 |
| 8 | medium_nand / u32 | 2.307 | 4.072 | 4.298 |
| 8 | medium_nand / u64 | 3.736 | 7.302 | 6.268 |

All four NAND inputs passed under both input seeds in every fixture. Maximum
q-phase residuals, in dense/fixed/sparse order, were 14/3/4 for STD128 u32,
5/4/5 for STD128 u64, 8/11/10 for MEDIUM u32 and 8/7/9 for MEDIUM u64, below
the finite corpus's q/8=64 decoding margin. Each timed request allocates zero
times. The corpus is not a tail bound. No production arithmetic optimization
was introduced by this alignment, and the difference from old NOT timings is
not reported as a performance improvement.

STD128 u32 now takes 8.31–8.85 ms, close in absolute scale to the paper's 7.9 ms.
This resolves the apparent conflict that sparse must take tens of milliseconds;
it does not reproduce the paper's machine or demonstrate its acceleration over
Primus classic. MEDIUM's two-level decomposition must remain visible when
reading its 2.93–4.30 ms beside the paper's 5.8 ms.

## Availability of the authors' implementation

On 2026-10-05, the paper, its
[ePrint entry](https://eprint.iacr.org/2026/1730), the checked author publication
pages and Zeyu Liu's public GitHub repository list supplied no sparse-code
download or build instructions. This is a search result, not proof that no public
artifact exists. OpenFHE's
[official publication list](https://github.com/openfheorg/awesome-openfhe#publications-with-new-crypto-algorithms)
lists this work among algorithms not yet included in its official distribution.
The workspace's `temp/openfhe-development` reference is ordinary OpenFHE 1.5.1,
not an identified copy of the authors' sparse implementation.

The paper explicitly cites OpenFHE commit
`122f470e0dbf94688051ab852131ccc5d26be934` (version 1.0.3). Its original classic
benchmark is available and can establish a same-machine reference. It cannot
substitute for the missing sparse implementation or by itself reproduce the
paper's speedup. A complete reproduction must first match both author binaries
and their parameter/measurement settings, then compare Primus with each side.

### Same-machine OpenFHE classic reference

The cited commit and its original `benchmark/src/binfhe-ginx.cpp` were built and
run without source changes, separately from the workspace. GCC 15.2.0, CMake
4.2.3, Release/O3, `WITH_NATIVEOPT=ON`, `NATIVE_SIZE=64`, `MATHBACKEND=4`, no
OpenMP/HEXL/TCMalloc. Cereal and Google Benchmark use the submodule commits
`984e3f194862b17916536b5fade40cba6e47a6fe` and
`e451e50e9b8af453f076dec10bd6890847f1624e`. CMake's minimum-policy compatibility
was set to 3.5 for this old dependency. No arithmetic or parameter patch was
needed. A separate untimed check passed all four NAND inputs for both presets.

The original benchmark generates two refreshed encryptions of one and measures
one complete `EvalBinGate(NAND, ct1, ct2)` per iteration, including its internal
allocations and returned-object destruction. Key generation and input setup are
outside the timer. Each CPU runs sequentially, with a one-second minimum target
and three repetitions. OpenFHE uses its original random key/input generation;
these are not Primus's fixed seeds. Values are mean wall milliseconds with the
standard deviation of the three repetition means; this is not a confidence
interval or an individual-request latency distribution.

| Native word | CPU | OpenFHE STD128 NAND | OpenFHE MEDIUM NAND |
| ---: | ---: | ---: | ---: |
| 64 | 4 | 76.985 ± 0.258 | 49.568 ± 0.185 |
| 64 | 8 | 76.516 ± 1.566 | 49.819 ± 0.118 |
| 32 | 4 | 68.455 ± 0.021 | 44.355 ± 0.164 |
| 32 | 8 | 67.676 ± 0.108 | 45.112 ± 1.096 |

The second build changes only `NATIVE_SIZE=32`; its generated `config_core.h`
confirms `NATIVEINT 32`. It runs the same unmodified benchmark with the same
one-second target and three repetitions. A 32-bit build alone does **not**
recover Table 2's 36.5/30.1 ms. The 64-bit results are the previous run, not an
interleaved build comparison; do not ascribe the entire difference to word size.

The actual unmodified presets are:

| Preset | n / N | q | Q | Q' | BR base / digits | LWE KS base |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| STD128 | 512 / 1024 | 1024 | 134215681 | 16384 | 128 / 4 | 128 |
| MEDIUM | 422 / 1024 | 1024 | 268369921 | 16384 | 1024 / 3 | 128 |

The OpenFHE baseline is clearly much more expensive in this experiment.
Comparing sparse only with Primus classic therefore answers a different
question from the paper.
However, dividing these cross-library times is **not** an equal-parameter or
equal-security speedup: q, Q, dimensions, MEDIUM decomposition, input convention,
return algorithm and gate workload differ. These observations do not isolate
how much of the difference comes from kernel optimization versus parameters.
They also do not explain why the paper's OpenFHE absolute times are lower than
this run; the authors' hardware/build settings are not established here.

### Fresh inputs and explicit parameter check

A temporary harness used only the pinned version's public `LWEEncryptionScheme`
and `BinFHEScheme(GINX)` APIs. It called `Encrypt(params, sk, m, 4, q)` to obtain
fresh inputs, verified all four NAND cases before each benchmark invocation,
and timed one `EvalBinGate` on two independent encryptions of one. The unmodified
library still owns its accumulator and Q'-based return algorithms. Setup and
validation were untimed; returned ciphertext destruction was timed. CPU 4,
native 32-bit build, one-second target, three repetitions:

| Parameters / fresh inputs | STD128 mean ± stddev (ms) | MEDIUM mean ± stddev (ms) |
| --- | ---: | ---: |
| Original presets | 68.462 ± 0.063 | 44.360 ± 0.118 |
| Explicit q/Q/Q' and dense n below | 67.554 ± 0.135 | 44.381 ± 0.091 |

The explicit contexts are constructed as follows, with `n=503, baseG=128` for
STD128 and `n=422, baseG=1024` for MEDIUM. These are diagnostic adaptations,
not a claim to recover the authors' unlisted dense presets:

```cpp
auto lwe = std::make_shared<LWECryptoParams>(
    n, 1024, 512, 268369921, 4096, 3.19, 128);
auto ring = std::make_shared<RingGSWCryptoParams>(
    1024, 268369921, 512, baseG, 32, GINX, 3.19);
auto params = std::make_shared<BinFHECryptoParams>(lwe, ring);
LWEEncryptionScheme encryption;
BinFHEScheme scheme(GINX);
auto secret = encryption.KeyGen(n, 512);
auto key = scheme.KeyGen(params, secret);
auto lhs = encryption.Encrypt(lwe, secret, 1, 4, 512);
auto rhs = encryption.Encrypt(lwe, secret, 1, 4, 512);
// Timed once per Google Benchmark iteration; all setup above is untimed.
auto output = scheme.EvalBinGate(params, NAND, key, lhs, rhs);
```

The printed contexts confirm four full BR digits for STD128 and three for
MEDIUM, and Q'=4096 for both. The fresh/refreshed choice and these parameter
corrections do not explain the large absolute baseline gap in this run. There
is still no author sparse executable or verified experimental-machine setup.

### Which OpenFHE build options matter here

This is a check of **v1.0.3 / commit 122f470e**, not a recommendation to treat
today's OpenFHE implementation as identical to that revision:

- `CMAKE_BUILD_TYPE=Release` and `WITH_NATIVEOPT=ON` were already enabled in
  both builds. The generated compiler flags contain `-O3 -march=native -DNDEBUG`.
- `NATIVE_SIZE=32` is supported by the pinned CMake code, despite nearby comments
  mentioning only 64/128. It changes the native integer/vector representation;
  it is appropriate to check for these 28-bit gates, but cannot hold the
  54-bit arbitrary-function modulus. It was measured above, not assumed faster.
- `WITH_OPENMP` is off for the single-core comparison. In this revision's GINX
  path, parallel-for directives are in key generation; `EvalAcc`, digit products
  and the sampled LWE return are serial. Enabling it does not provide a hidden
  parallel sparse implementation. Newer-version threading behavior may differ.
- `WITH_INTEL_HEXL` is an optional alternative arithmetic backend. The pinned
  source contains hooks but omits the corresponding integration files. It needs
  a compatible [openfhe-hexl overlay](https://github.com/openfheorg/openfhe-hexl),
  not just the CMake flag or an installed HEXL library. The follow-up below uses
  the compatible historical overlay and measures its effect. That overlay
  requires `NATIVE_SIZE=64`; combining it with the 32-bit build is unsupported.
- `MATHBACKEND` chooses a big-integer backend; the checked BinFHE path uses
  native polynomials. Changing it to NTL is not a switch that replaces these
  native kernels. TCMalloc was not tested; no allocator speedup is claimed.

The official [CMake guide](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/cmake_in_openfhe.html)
and [performance guide](https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md)
are useful for a current build. Version-specific claims above come from the
pinned source and generated flags, so newer automatic narrowing or threading
must not be retroactively attributed to the cited executable.

### Reproduce the OpenFHE builds

To reproduce the reference, first obtain the pinned checkout and its submodules.
The following builds only the needed libraries, then compiles the original
benchmark source without pulling in the unrelated PKE library:

```bash
openfhe_src=/path/to/openfhe-at-122f470e
openfhe_build=/tmp/primus-openfhe-reference
cmake -S "$openfhe_src" -B "$openfhe_build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DCCACHE_PROGRAM=OFF -DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON \
  -DWITH_NATIVEOPT=ON -DWITH_OPENMP=OFF -DGIT_SUBMOD_AUTO=OFF \
  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=ON \
  -DWITH_BE2=OFF -DWITH_BE4=ON -DNATIVE_SIZE=64
cmake --build "$openfhe_build" --target OPENFHEbinfhe benchmark -j 4
g++ -O3 -DNDEBUG -std=c++17 -march=native \
  -DBUILTIN_INFO_AVAILABLE -DMATHBACKEND=4 \
  -I"$openfhe_src/src/core/include" -I"$openfhe_src/src/binfhe/include" \
  -I"$openfhe_src/third-party/cereal/include" \
  -I"$openfhe_src/third-party/google-benchmark/include" \
  -I"$openfhe_build/src/core" "$openfhe_src/benchmark/src/binfhe-ginx.cpp" \
  -L"$openfhe_build/lib" -Wl,-rpath,"$openfhe_build/lib" \
  -lOPENFHEbinfhe -lOPENFHEcore -lbenchmark -lpthread \
  -o "$openfhe_build/binfhe-ginx"
taskset -c 4 "$openfhe_build/binfhe-ginx" \
  --benchmark_filter='FHEW_BINGATE/(MEDIUM|STD128)_NAND$' \
  --benchmark_min_time=1 --benchmark_repetitions=3 \
  --benchmark_out=/tmp/primus-openfhe-cpu4.json --benchmark_out_format=json
```

Use a separate build directory and `-DNATIVE_SIZE=32` for the 32-bit run, and
compile the benchmark with that build's generated headers and libraries.
Repeat on CPU 8 with a different output file. The authors' sparse code and a
functional OpenFHE runtime remain unmeasured. Next, obtain the sparse artifact
if available, align complete-operation contracts, and compare common arithmetic
kernels at identical public dimensions/bases before attributing the remaining
difference to a particular implementation technique.

## Algorithm 2 coefficient layout and HEXL follow-up

This experiment covers Algorithm 2 only. It neither implements Algorithm 3 nor
stores all possible monomial rotations in the NTT domain. The same Table 3
adaptations above, secrets, matching, encrypted controls, input and LUT are used
within each word-width comparison. The timer measures **one raw blind rotation**,
excluding input lifting and the return path.

### Expanded coefficient storage

A temporary implementation expands each polynomial to `[-p, p, -p]`, using
canonical residues for the negative copies. It reads an N-element slice at
`start = (N - exponent) mod (2N)`. Section 4.3's printed formula for exponents
at least N is inconsistent with its stated layout: substituting N reads `p`
instead of `-p`. The experiment uses the corrected index and checks all 2N
exponents against independent scatter-and-sign arithmetic, including zero
coefficients and the half-ring boundaries.

All encrypted selectors and dummies remain present. Aggregation retains the
16 KiB destination tiles. u32 reduces additions as before; u64 accumulates a
complete bucket with unsigned additions, then reduces once. Canonical negative
copies eliminate the signed kernel's initial bias. Paired source additions,
aggregate NTT, gadget basis and external products retain their roles. Thus this
measures the usable expanded-layout algorithm, including its changed address
stride and unsigned aggregation, rather than just an isolated slice lookup.

The coefficient payload in MiB changes as follows:

| Profile / word | Compact | Expanded |
| --- | ---: | ---: |
| STD128 / u32 | 194.875 | 584.625 |
| STD128 / u64 | 389.750 | 1169.250 |
| MEDIUM / u32 | 97.063 | 291.188 |
| MEDIUM / u64 | 194.125 | 582.375 |
| Padded function / u64 | 777.125 | 2331.375 |

Only N values per source polynomial are read online; threefold storage does
not mean threefold useful bytes read per call. For the temporary comparison,
both variants retain compact and expanded owners, so their combined allocated
payload is four times compact storage. The expanded path reads coefficients
only from the expanded owner; the compact owner supplies public map metadata
and the untimed oracle. A production expanded owner would replace the compact
coefficients. These numbers describe key payload, not process RSS.

### Direct HEXL NTT comparison

A temporary C ABI connects Intel HEXL 1.2.5 to `NttTable`, using the exact
Primus primitive root, ordering and normalization. Canonical and lazy forward /
inverse transforms are compared with the existing table before key generation.
The first matrix changes **only NTT/INTT**, leaving modular aggregation and
pointwise external-product arithmetic in Primus. HEXL's interface uses u64;
there is no u32 HEXL column or hidden conversion in the timer.

Both Primus tables already select AVX-512 at construction on this machine,
without needing the workspace's nightly `simd` feature. The u64 AVX-512 NTT
is itself a documented [HEXL translation](../../crates/primus_ntt/src/ntt/prime64/avx512/mod.rs).
Linking HEXL therefore does not change
this comparison from scalar transforms to SIMD transforms. The runtime CPU
probe confirms AVX512DQ, IFMA and VBMI2, and the HEXL build enables those kernels.

Stable Rust 1.98.1, GCC 15.2.0, Release/O3 and the existing native target are
used. CPU 4 has 96 MiB L3 and CPU 8 has 32 MiB L3. Each exact ID runs in a fresh
process, ascending on CPU 4 and descending on CPU 8, with 40 flat samples,
1 s warmup and a 4 s target. CPUs and builds run sequentially. Fixtures and
expanded material are cached outside `b.iter`; the preliminary run that rebuilt
fixtures for Criterion callbacks was discarded. Means in milliseconds:

| CPU | Profile / word | Compact + Primus NTT | Expanded + Primus NTT | Compact + HEXL NTT | Expanded + HEXL NTT |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 | STD128 / u32 | 8.296 | 8.790 | — | — |
| 4 | STD128 / u64 | 12.014 | 12.651 | 11.990 | 12.686 |
| 4 | MEDIUM / u32 | 2.907 | 3.781 | — | — |
| 4 | MEDIUM / u64 | 5.341 | 5.791 | 5.357 | 5.786 |
| 4 | Padded function / u64 | 25.383 | 27.259 | 25.637 | 27.251 |
| 8 | STD128 / u32 | 8.977 | 9.631 | — | — |
| 8 | STD128 / u64 | 12.777 | 14.169 | 12.794 | 14.205 |
| 8 | MEDIUM / u32 | 4.282 | 4.355 | — | — |
| 8 | MEDIUM / u64 | 6.064 | 6.478 | 6.084 | 6.562 |
| 8 | Padded function / u64 | 25.386 | 28.553 | 25.550 | 28.652 |

Expanded storage is slower in every measured row, by approximately 2–30%
with Primus NTT. Substituting HEXL NTT changes compact total time by less than
1.1% and establishes no useful improvement. This does not support adopting
threefold key storage in Primus. It does not isolate a particular cache/TLB or
writeback cause: no PMU attribution was performed. The comparison starts from
Primus's existing fused rotation/addition, not a materialized-rotation baseline.

### HEXL reduction and pointwise products as well

A separate same-executable follow-up keeps expanded storage and compares HEXL
NTT alone with HEXL NTT **plus** bucket-final `EltwiseReduceMod` and the external
product's `EltwiseMultMod` / `EltwiseAddMod`. The latter uses a preallocated
product buffer and the same Primus signed decomposition / gadget order. This
checks more than just substituting a transform. Bounded unreduced source-pair
addition remains an ordinary integer loop: it requires no modular operation.
The key, input and complete ciphertext outputs remain identical.

HEXL reduction uses `input_mod_factor=Q`, as required by version 1.2.5 for its
Barrett case; these bucket sums fit both the word and the stated Q-squared bound.
Multiplication/addition inputs and outputs are canonical. Table construction,
all buffers and the extra pointwise-product scratch remain outside the timer.
The sampling, CPU order and parameters match the preceding matrix, but these
are separate runs and should be compared within this table:

| CPU | u64 profile | Expanded + HEXL NTT / ms | Expanded + HEXL NTT and vector arithmetic / ms |
| --- | --- | ---: | ---: |
| 4 | STD128 | 12.827 | 12.340 |
| 4 | MEDIUM | 5.967 | 5.758 |
| 4 | Padded function | 26.282 | 27.485 |
| 8 | STD128 | 14.226 | 13.939 |
| 8 | MEDIUM | 6.951 | 6.347 |
| 8 | Padded function | 27.544 | 27.468 |

The expanded Boolean means are about 2–9% lower with additional HEXL arithmetic;
the CPU 4 MEDIUM confidence intervals overlap. This does not establish a uniform
gain, or yield a comparable gain to the OpenFHE backend switch below.
The 54-bit function regresses on CPU 4 and changes little on CPU 8. This is not
a measurement of full HEXL arithmetic on compact storage, or proof that the
extra vector kernels should become a dependency of Primus. A future compact
kernel comparison can isolate useful arithmetic changes without tripling keys.
For now the production layout and numerical kernels remain unchanged.

Validation covered 16 layout/NTT combinations and six arithmetic combinations.
Every case checked eight complete BR outputs for exact coefficient equality
against the existing compact kernel, in addition to the all-exponent slice
oracle and canonical/lazy transform checks. Existing fixture checks cover all
four NAND pairs or eight padded-function inputs under two input seeds. The
Rust allocation counter reports zero online allocations; it does not intercept
C++ allocations. The inspected HEXL numerical calls use their prepared tables
and caller-provided buffers. The temporary adapter, expanded owner and alternate
external product were removed from the ordinary benchmark after measurement;
there is no new production API, Cargo feature or C++ dependency.
After removal, formatting, all-targets compilation, strict all-targets Clippy
and the five ordinary paper-profile sparse-BR smoke cases pass.

The subsequent [compact-layout reduction study](sparse-arithmetic.md#compact-sparse-bucket-reduction)
isolates bucket-final arithmetic while keeping Primus NTT and pointwise products
unchanged. A local Rust u64 vector reduction improves complete PBS means by
1.5%–6.0% on the measured CPU/profile pairs, without extra scratch or a HEXL
dependency; its applicability and exact-ciphertext checks are recorded separately.

### OpenFHE with the complete historical HEXL backend

The same OpenFHE commit `122f470e0dbf94688051ab852131ccc5d26be934` was rebuilt
with and without the official
[historical overlay at 7a24b589](https://github.com/openfheorg/openfhe-hexl/tree/7a24b589379369b38e7405c8940446b45f6b1c98)
and [HEXL 1.2.5](https://github.com/IntelLabs/hexl/tree/v1.2.5).
Both builds use the same source tree containing the overlay; only
`WITH_INTEL_HEXL` selects its backend. All other build settings remain the reference
settings above, with `NATIVE_SIZE=64`, `WITH_NATIVEOPT=ON` and OpenMP off.
This is the full official arithmetic integration, including transforms and
vector products, not the NTT-only Primus adapter.

The unmodified `binfhe-ginx.cpp` benchmark runs classic NAND using its original
STD128/MEDIUM presets and setup-refreshed inputs. It does **not** supply the
paper's unavailable sparse implementation. Each row below is the mean ± sample
standard deviation of three 1 s Google Benchmark repetitions, using process
CPU time. The previous preset / paper-parameter differences still apply.

| CPU | Preset | Native / ms | HEXL / ms | Native / HEXL |
| --- | --- | ---: | ---: | ---: |
| 4 | STD128 | 77.135 ± 0.129 | 26.093 ± 0.047 | 2.96 |
| 4 | MEDIUM | 49.511 ± 0.030 | 16.377 ± 0.174 | 3.02 |
| 8 | STD128 | 75.614 ± 0.124 | 27.104 ± 0.881 | 2.79 |
| 8 | MEDIUM | 49.475 ± 0.069 | 17.477 ± 0.089 | 2.83 |

Both builds also pass all four NAND truth-table pairs on fresh inputs for each
preset. Generated compiler flags, dynamic symbols and the CPU probe confirm
that HEXL is actually linked and its AVX-512 kernels are available. The large
OpenFHE speedup cannot be transferred to Primus's already accelerated NTT or
used as evidence that the authors enabled HEXL. Their exact build remains
unknown; neither library's measurements reproduce the authors' sparse binary.

To reproduce the HEXL build, stage that overlay's `src`, `benchmark` and
`third-party` directories into a disposable copy of the pinned OpenFHE source.
Build/install HEXL 1.2.5 into a private prefix, with `HEXL_SHARED_LIB=ON`,
`HEXL_TESTING=OFF` and `HEXL_BENCHMARK=OFF`. Its pinned CpuFeatures dependency
is `32b49eb5e7809052a28422cfde2f2745fbb0eb76`. Add these flags to the reference
OpenFHE configuration above:

```bash
-DWITH_INTEL_HEXL=ON -DINTEL_HEXL_PREBUILT=ON \
-DINTEL_HEXL_HINT_DIR=/path/to/private/hexl-prefix
```

Compile the original benchmark with `-DWITH_INTEL_HEXL`, the HEXL include and
library paths, `-lhexl`, and a runtime library path covering that prefix. Build
the native control separately with `WITH_INTEL_HEXL=OFF`. Keep both builds at
64 bits: this overlay explicitly rejects other `NATIVE_SIZE` values. Run the
same NAND filter/repetitions as above; CPU 4 used native then HEXL, and CPU 8
used the reverse order. No external project under `temp/` was modified and no
system-wide install was performed.

## Reproduction and validation

```bash
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- \
  'paper_2026_1730/' --test

CRITERION_HOME=/tmp/primus-paper-cpu4 taskset -c 4 \
  cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- \
  'paper_2026_1730/.*_nand/.*/complete_ring_return$' \
  --sample-size 40 --warm-up-time 1 --measurement-time 4 --noplot
```

Use CPU 8 with a separate Criterion directory to check cache-topology
sensitivity; run sequentially. Omit the final `/complete_ring_return$` filter to include
raw BR. `--list` performs no key generation for paper IDs. The ordinary fixed-weight comparison remains in `sparse_pbs`; retained u64
keygen cases are now in `setup`, selected by `fixed_weight/n728_h32_N1024`.
The command runs the selected groups in registration order. To reproduce the
NAND comparison order, build once with `--no-run`, list the executable's NAND
complete IDs with `--list`, sort ascending for CPU 4 or descending for CPU 8,
and invoke each exact ID in a fresh process with `--bench` and the same timing
options. The earlier NOT confirmation used descending order for both CPUs.

The fixtures use client seed 42, server seed 4242 and independent input seeds
43/4343. Before timing, all four NAND pairs/eight function inputs are checked
against the public function, q-phase residuals are reported, and one complete
request must allocate zero times. Timed inputs are the independently encrypted pair (1,1) for NAND,
or message one for the function, using seed 43 for every algorithm.
This covers 15 parameter/word/mode combinations and 30 stage IDs; it does not
estimate a tail probability or matching-retry distribution. Ordinary CI keeps
its existing small-parameter tests.

Validation for this change passed formatting, all-targets compilation, strict
all-targets Clippy and all 17 GLWE NTT library/integration tests. A final smoke
run passed all 42 IDs (30 paper stages and 12 existing diagnostics), including
the numerical and allocation checks above. `--list` enumerated those IDs without
generating paper keys. Nightly SIMD and other backends were not measured.
