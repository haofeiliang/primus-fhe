# Sparse PBS comparison boundaries

[Performance guide](README.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks)

The studies related to [New Techniques for Fast and Shallow FHE Bootstrapping
and Beyond, ePrint 2026/1730](https://eprint.iacr.org/2026/1730) have three distinct
sources: the paper's tables, earlier Primus/OpenFHE experiments without the
authors' sparse code, and a later user-supplied OpenFHE fork. **The authors' code
was subsequently obtained and tested.** Neither the early comparisons nor the
later fork experiment establish an equal-security reproduction of the paper.

This report preserves algorithm, parameter, storage and build boundaries.
Detailed early measurements remain in Git at `b54a4b3c`. The later fork's patches,
binaries and raw measurements were removed; only a limited technical summary
survives. No new experiment accompanies this consolidation. Historical profile
labels describe these studies, not current Cargo targets.

## Parameters and comparison boundary

Table 3 uses three replicas and h+3 buckets for general sparse binary secrets.
Its STD128/MEDIUM labels refer to reported estimates of 120/103 bits; they do
not certify the adapted Primus profiles. The earlier GLWE NTT experiment used:

| Historical profile | Dense n | Sparse n / h / buckets | N | External q | Ring Q | BR logB / levels / dropped bits | Ring KS logB / levels / dropped bits |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| STD128 NAND | 503 | 1024 / 43 / 46 | 1024 | 512 | 268369921 | 7 / 4 / 0 | 7 / 4 / 0 |
| MEDIUM NAND | 422 | 1024 / 31 / 34 | 1024 | 512 | 268369921 | 10 / 2 / 8 | 7 / 4 / 0 |
| STD128 padded function | 1350 | 2048 / 70 / 73 | 2048 | 4096 | 18014398509404161 | 27 / 2 / 0 | 5 / 10 / 4 |

GLWE k=1, with a uniform ternary ring secret. Gates were measured in u32/u64;
the 54-bit function used u64. q uses PowOf2Modulus and Q uses BarrettModulus;
Q is the largest prime below 2^28 or 2^54 congruent to one modulo 2N.
Input, BR and ring-KS noise each used sigma=3.19 in their own coefficient domain.
Inputs were sampled at q, not using a rescaled Q-domain sampler.

Three algorithms were compared. Dense classic used a uniform ternary secret at
the smaller reference n; fixed-weight classic and sparse shared the same
fixed-weight binary secret, ciphertext and LUT at the larger n. For STD128,
Primus classic requires roughly 503 fused ternary products or 1024 binary
products, ignoring skipped public zero exponents; sparse requires 46 bucket
products **plus aggregation of all 3072 selector controls and 46 dummies**. Classic cannot skip secret-zero coordinates.
Its ternary implementation combines two controls before one external product;
binary at 1024 coordinates need not beat ternary at 503. Only the fixed-weight
classic/sparse pair holds the complete client parameter set fixed.

The dense 503/1350 examples come from the paper; MEDIUM n=422 and omitted values
were taken from its cited [OpenFHE revision
122f470e](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/binfhecontext.cpp).
That revision's unmodified STD128 preset instead has n=512/q=1024/Q=134215681,
and its functional constructor uses n=1305. Combining these sources is an adaptation,
not recovery of every paper setting. Later [replica/decomposition candidates](sparse-parameters.md)
change matching and consumer error budgets and must not be mixed into this baseline.

## Operation and return differences

The historical Primus adapter used

```text
LWE at q → coefficient lift to Q → BR → ring KS at Q
         → compact extraction → coefficient switch back to q.
```

Both conversions were timed in complete requests, with prepared buffers. Since
q divides 2N, lifting preserved each input's quantized rotation exponent; the
secret coefficients were re-encoded, not rescaled. This was benchmark composition,
not a claim that ordinary GLWE PBS supports independent input/output moduli.

| Boundary | Primus experiment | Cited OpenFHE / paper |
| --- | --- | --- |
| Boolean operation | NAND of two independent fresh inputs at scale q/4; one PBS using signed values ±(floor(Q/8)+1), then positive bias | Same truth table/scale in the explicit-parameter check; the unmodified OpenFHE benchmark refreshed inputs in setup |
| Accumulator layout | Dense negacyclic LUT on the q rotation grid | Gate core fills every 2N/q-th coefficient; reachable noiseless phases agree, intermediate layouts differ |
| MEDIUM decomposition | Two base 1024 levels, eight bits dropped | Cited OpenFHE uses three full digits; the paper alone does not establish the author's retained-level convention |
| Return | Ring KS at Q under the padded small secret, compact extraction, Q→q | Extraction, Q→Q', sampled LWE KS, Q'→q; Table 3 specifies Q'=4096 for gates and 2^35 for the function |
| Three-bit function | `f(m)=(m*m+3*m+1) mod 8`, eight inputs in padded t=16, one PBS | General EvalFunc branches in the cited version use two bootstraps; exact function/domain and bootstrap count must match |
| Online lifetime | Reused outputs and workspaces | Library calls allocate/destroy temporaries and returned objects; key generation is untimed in both |

OpenFHE's [sampled LWE return](https://github.com/openfheorg/openfhe-development/blob/122f470e0dbf94688051ab852131ccc5d26be934/src/binfhe/lib/lwe-pke.cpp)
stores an encrypted row for **every digit value** and selects/subtracts that row
online. Primus's ordinary LWE KS multiplies one encrypted gadget weight by the
digit. Substituting it at the same Q'/base changes key size and noise; aligning
only the numeric parameters would not reproduce the return scheme.

Primus's [fused ternary update](../../crates/primus_lattice/src/ggsw/ntt/ternary.rs)
and the cited OpenFHE update also do different matrix-product work and allocate
differently. Their timings do not isolate these causes. The earlier comparison
covered neither Algorithm 3, structured-sparse preprocessing, NTRU nor Fourier.

## Earlier complete-request measurements

The paper's Table 2 reports sparse-binary Boolean 7.9/5.8 ms as **measured**;
its arbitrary-function 53.5 ms is a microbenchmark estimate. The corresponding
OpenFHE references are 36.5/30.1/391.5 ms. Section 7.2 describes 32-bit Boolean
arithmetic; it does not identify an exact compiler configuration. A slower local
OpenFHE baseline cannot explain away the paper's absolute sparse-gate times.

The early Primus experiment ran on 2026-10-05 after `ff6969e4`, Ryzen 9 9955HX3D,
rustc 1.98.1 / LLVM 22.1.8, native release flags, no Cargo SIMD. CPU 4/8 are the
same machine's 96/32 MiB L3 groups. Each NAND case used a fresh process, 40 flat
samples, 1 s warmup and 4 s target; CPU 8 reversed CPU 4's case order. One iteration
was a complete request on independently encrypted (1,1), seed 43. Setup and checks
were untimed. Frequency and background activity were not controlled. These are
means in ms, not cross-process confidence intervals:

| CPU | Profile / word | Dense classic | Fixed-weight classic | Sparse |
| ---: | --- | ---: | ---: | ---: |
| 4 | STD128 / u32 | 4.632 | 6.655 | 8.313 |
| 4 | STD128 / u64 | 8.053 | 12.135 | 12.500 |
| 4 | MEDIUM / u32 | 2.224 | 3.757 | 2.929 |
| 4 | MEDIUM / u64 | 3.265 | 5.999 | 5.522 |
| 8 | STD128 / u32 | 4.683 | 8.105 | 8.846 |
| 8 | STD128 / u64 | 8.358 | 12.269 | 13.143 |
| 8 | MEDIUM / u32 | 2.307 | 4.072 | 4.298 |
| 8 | MEDIUM / u64 | 3.736 | 7.302 | 6.268 |

STD128/u32's 8.31–8.85 ms is close in scale to 7.9 ms, but not an equal-machine
reproduction. MEDIUM's two-level approximation matters when comparing its
2.93–4.30 ms with 5.8 ms. Earlier NOT-through-PBS timings are a different workload
and cannot be relabeled NAND. The single padded function measured sparse 26.686 /
26.189 ms versus dense 41.408 / 38.458 ms on CPU 4/8; it does not reproduce a general
full-domain EvalFunc. Its earlier confirmation used the same 40/1 s/4 s settings,
CPU 8 then CPU 4 with reverse ID order. All four NAND truth-table pairs passed
in every gate fixture under both input seeds; this is not a failure-rate estimate.

Earlier CPU 4/8 stage probes put aggregation at roughly 89–94% of the sparse
stage sums for NOT/function workloads. For k=1, each bucket additionally needs
4L control NTTs before the external product's 2L forward and two inverse
transforms. Fewer external products alone do not
predict full latency. Instrumented stage sums and independent complete means
cannot be subtracted to derive a precise return cost, or diagnose cache traffic.

## Expanded coefficient layout and HEXL

`[-p,p,-p]` is an **Algorithm 2** coefficient-layout optimization, not Algorithm 3
or precomputation of every NTT-domain rotation. With canonical negative copies,
`X^e*p` is the N-coefficient slice starting at `(N-e) mod 2N`. This yields `-p`
at e=N; the early experiment corrected the paper's inconsistent printed index
and checked all 2N exponents against signed scatter. Primus already fuses rotation
with addition, so this compares contiguous source slices with signed segment
addition, not with allocating a rotated polynomial.

For k=1, one control has 4LN coefficients. Sparse storage has 3n+B controls;
tripling their polynomials changes the STD128/u32 payload from 194.875 to 584.625
MiB, and the function/u64 from 777.125 to 2331.375 MiB. Online each source still
reads only N coefficients. The experiment retained both owners outside timing
(four times compact payload); a production expanded owner would replace the
compact coefficients. Payload is not RSS or measured memory traffic.

The raw-BR study retained 16 KiB aggregation tiles. u64 used unsigned bucket
accumulation and one final reduction; canonical negative copies removed its
initial signed bias. All encrypted selectors/dummies, decomposition, transforms
and products remained. Thus the comparison includes the usable aggregation
schedule, not only a slice-index change. Mean raw BR times in ms:

| Profile / word | CPU 4 compact → expanded | CPU 8 compact → expanded |
| --- | ---: | ---: |
| STD128 / u32 | 8.296 → 8.790 | 8.977 → 9.631 |
| STD128 / u64 | 12.014 → 12.651 | 12.777 → 14.169 |
| MEDIUM / u32 | 2.907 → 3.781 | 4.282 → 4.355 |
| MEDIUM / u64 | 5.341 → 5.791 | 6.064 → 6.478 |
| Padded function / u64 | 25.383 → 27.259 | 25.386 → 28.553 |

The host/Rust configuration was the same as above; C++ used GCC 15.2.0/O3/native.
Each case ran separately, 40 flat samples/1 s warmup/4 s target, ascending order
on CPU 4 and descending on CPU 8, without concurrent builds. Raw BR excludes
input lifting and return. Expanded storage was 2–30% slower here, insufficient
to justify threefold key storage; no PMU evidence attributes the cause.

A temporary **u64-only** HEXL 1.2.5 NTT adapter matched Primus roots, ordering,
normalization and canonical/lazy outputs. Replacing only NTT/INTT changed compact
raw BR by less than 1.1%, with no useful established improvement. Primus already
selected AVX-512 tables on this host; its [u64 kernels](../../crates/primus_ntt/src/ntt/prime64/avx512/mod.rs)
were translated from HEXL. This was not scalar versus SIMD.

A separate expanded-layout comparison added HEXL bucket reduction and pointwise
multiply/add with prepared scratch. Boolean means improved by about 2–9%, but
the 54-bit function regressed on CPU 4 (26.282 → 27.485 ms) and was nearly unchanged
on CPU 8. It did not measure full HEXL arithmetic on compact storage. No expanded
owner, C++ dependency or alternate product API was retained. The independent
[compact reduction study](sparse-arithmetic.md#compact-sparse-bucket-reduction)
has its own baseline and evidence; these gains cannot be added together.

## OpenFHE builds and the later author fork

The early classic reference pinned OpenFHE 1.0.3 at `122f470e0dbf94688051ab852131ccc5d26be934`.
Release/O3, `WITH_NATIVEOPT=ON`, GCC 15.2.0/CMake 4.2.3, `MATHBACKEND=4`, OpenMP and
TCMalloc off. Native32 and native64 were separate builds; 32 bits cannot hold the
54-bit function modulus. The original presets differ from the adaptation:
STD128 n=512/q=1024/Q=134215681 and MEDIUM n=422/q=1024/Q=268369921, both N=1024/Q'=16384.
MEDIUM retains three BR digits. Fresh-input/explicit q=512, Q=268369921, Q'=4096
checks still retained OpenFHE's return and decomposition conventions.

The full historical [OpenFHE HEXL overlay](https://github.com/openfheorg/openfhe-hexl/tree/7a24b589379369b38e7405c8940446b45f6b1c98)
with HEXL 1.2.5 supplied missing integration files; a CMake flag alone was not
sufficient. That overlay required native64. The original classic NAND benchmark,
including returned-object destruction and setup-refreshed inputs, measured:

| CPU / preset | Native64 → HEXL 64, ms |
| --- | ---: |
| 4 / STD128 | 77.135 → 26.093 |
| 4 / MEDIUM | 49.511 → 16.377 |
| 8 / STD128 | 75.614 → 27.104 |
| 8 / MEDIUM | 49.475 → 17.477 |

These are process-CPU-time means of three 1 s repetitions, native then HEXL on
CPU 4 and reversed on CPU 8. Compiler flags/symbols confirmed actual linkage.
This large classic-OpenFHE change cannot be transferred to Primus's accelerated
NTT, or prove how the paper's authors built their sparse executable. The earlier
native32/fresh-input checks likewise did not recover the paper's absolute classic
times. In this pinned GINX path OpenMP parallelized key generation, not the
online update; MATHBACKEND did not replace its native-polynomial kernels.

The **later supplied tree** was an OpenFHE 1.4.1 fork named
`newFHEboot-withoutPreprocessing`. Its original source was left unchanged;
experiments used disposable copies. The recorded build used Release/native
optimization, OpenMP off, separate native32/native64 builds. A temporary copy
integrated openfhe-hexl overlay v1.4.0.0 with HEXL 1.2.6 and adapted the author's
`Shift/ShiftNeg/AddSpecialTwo`. Actual AVX-512 NTT and EltwiseMultMod calls were
observed. Only general sparse binary was checked; native32 is not “HEXL 32”.

Its aligned fixture was n=N=1024, q=1024, Q=134176769, h=42, three replicas and
**67 buckets**, BR base 512/two levels, sigma=3.19. The supplied program initialized
buckets from h=64 and did not recompute them after `main` changed h. This is neither
Table 3's h+3 profile nor the earlier Primus paper fixture. Return KS and raw-BR
timing boundaries also differed. The surviving summary records improved author
native64 timings with HEXL, but not reproduction of the paper's 7.9 ms complete
NAND. Without raw data and the exact adaptation, no speed ratio or current
ranking is retained here.

The recorded source audit also limits any security-equivalence claim:

- Constructing repeated `NativePoly(dug,...)` elements via a vector fill copied
  one random mask across rows. Public row differences could expose the gadget
  selector; matching dimensions/noise did not make that key generation equivalent.
- The fork's `rd() % distribution(rd)` could divide by zero and did not sample
  positions uniformly. The comparison consumer used independent uniform
  fixed-weight sampling.
- Non-power-of-two Q representative selection and the highest decomposition
  carry differed from Primus, despite nominally matching base/level counts.

These are historical findings about that supplied tree. The full patch/build
record is no longer retained; recheck the actual revision before using or
attributing them elsewhere. They are not claims about current upstream OpenFHE.
A renewed comparison must retain exact sources, sampling, bases, return path,
operation boundaries and actual binaries. Current crate-local benchmarks use
other profiles and cannot reconstruct these experiments by changing an ID.
