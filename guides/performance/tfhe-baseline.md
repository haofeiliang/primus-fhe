# TFHE benchmark baseline and storage check

> Archive note (2026-10-10): the TFHE benchmark suite and report tools were removed. Commands and source paths below refer to historical revisions; the last complete suite is available at `8d7c4b1a`. Measurements remain evidence for their recorded versions, not current validation.

[Performance decisions and measurement method](README.md)

The historical workload guide (`benchmarks/tfhe/BENCHMARKS.md` at `8d7c4b1a`) recorded target purposes
and timing boundaries; the [parameter matrix](../development/tfhe-parameters.md) owns the
numerical profiles. This report records historical measurements, not production
security recommendations or a performance comparison between equal-security systems.

For the newer matched classic/sparse PBS and CBS comparison, see the
[2026-10-04 sparse baseline](sparse-baseline.md). It also rechecks
the CPU-dependent CBS regression and distinguishes retained heap from requested
live-heap peak. The cleanup measurements below remain historical.

## Public-key sampler reuse, 2026-10-09

The 2026-10-10 follow-up retains the raw LWE generator's explicit
`dimension/modulus/uniform/noise` inputs and inline hint. GLWE public-key
generation keeps its original preparation: small-LWE resources for BR→KS,
fresh LWE parameters derived from the ring sigma for KS→BR. Reusing the existing
ring sampler was rejected; KS key noise does not enter public-key generation.
This changes the low-level API, not the row algorithm or online PBS/CBS work.

Frozen binaries isolate the raw API, inline hint and GLWE sampler reuse from
`fe4111a4`. Measurements use CPU 4 of an AMD Ryzen 9 9955HX3D, stable rustc
1.98.1, repository CPU flags, the default bench profile and features
`glwe-ntt,glwe-fourier`. Each case has 30 samples, 1 s warm-up and 2 s
measurement, with original/modified runs repeated in reverse order. Each
iteration allocates and generates all n zero rows; output drop and all fixture
preparation are excluded. Binary secrets use client seed 42 and public-key
seed 4242. No FFT is performed. Snapshots outside timing compare all matrix
coefficients and the next RNG word; all five variants agree in all four cases.

| Full generation, u64 | n | Raw API + inline, retained | Also reuse samplers within each order, rejected |
| --- | ---: | ---: | ---: |
| Q50 Barrett, BR→KS | 800 | −0.41% to −0.15% | +0.44% to +1.06% |
| Native64, BR→KS | 800 | −0.17% to +0.57% | −3.10% to −2.50% |
| Q50 Barrett, KS→BR | 1024 | −0.48% to −0.07% | +3.42% to +5.19% |
| Native64, KS→BR | 1024 | −2.24% to −2.23% | −3.09% to −2.64% |

Each column uses its own original/modified pair; ranges are the two observed
mean changes, not confidence intervals. Q50 is 1,125,899,906,826,241. The earlier
combined-order reuse implementation had inconsistent results. Removing the
inline hint also failed to establish a consistent improvement. These runs do
not identify the cause or establish a general speedup; no CPU 8 or SIMD timing
was taken. The raw API is retained for its explicit sampling dependencies and
ability to borrow caller-prepared state, with required caller adaptations.

An earlier allocator probe showed KS→BR reuse saving two CDT allocations and
624 B of peak live requested storage at Q50, or six Ziggurat allocations and
7,353 B at Native64. The n1024 matrix remains 8,396,800 B and the arithmetic
remains O(n²). That small saving does not justify the repeatable Q50 regression;
GLWE sampler reuse remains a candidate rather than the current implementation.

```sh
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench setup \
  --features glwe-ntt,glwe-fourier -- 'public_key/' \
  --sample-size 30 --warm-up-time 1 --measurement-time 2
```

## Complete high-precision lookup workflow, 2026-10-09

`NttHighPrecLutContext` / `FourierHighPrecLutContext` move the complete CBS
operation into one backend owner, retaining checked chunk geometry and prepared
q/Q codecs beside it. Integer clients extract/join digits directly; they retain
no digit buffer. Evaluator factories return the existing numerical evaluator,
with the same workspaces and online schedule. No table/key copy, second transform
environment or new online allocation is introduced by these factories.

Before: `4c5c3e5b`, with manually assembled lookup fixtures. After: complete
Context, plan-directed paired keygen and integer input encryption. CPU 4, stable
rustc 1.98.1, repository CPU flags, scalar u64, NTT/RustFFT. Both use
n800/h32/N1024, q24, Q50/native64, t8/M4, c8/d5/o8, the same decompositions/noise,
seed 42 keygen and seed 43 inputs. Each case uses 15 samples, 1 s warm-up and
3 s target measurement. One iteration measures `evaluate_to` for all eight
output chunks; setup, LUT compilation, encryption and binding are excluded.

| Complete lookup, u64 | Manual fixture, ms | Complete Context, ms | Difference |
| --- | ---: | ---: | ---: |
| classic/ntt | 49.487 | 49.825 | +0.68% |
| classic/rustfft | 57.720 | 56.497 | −2.12% |
| sparse/ntt | 36.838 | 36.644 | −0.53% |
| sparse/rustfft | 36.872 | 36.432 | −1.19% |

These single before/after pairs show no large increase and do not establish a
speedup. Arithmetic kernels are unchanged. Paired generation reuses the accepted
ring transform/inverse; the extra sparse lift is now generated before BR/CBS,
so evaluation-key row randomness differs from the old fixture despite identical
secrets and input seeds. Outputs were decoded against the same cleartext oracle.
No CPU 8, SIMD, TFHE-FFT or keygen-cost timing was taken in this comparison.

On x86_64, `size_of` with u64, `U64NttTable`/`RustFftTable` and external
`PowOf2Modulus` is 696 B/472 B, versus 288 B/88 B for the underlying backend
Context: 408 B/384 B of inline lookup geometry/codecs. These exclude referenced
heap and peak construction storage; Context creates no additional shared-owner
allocation or sampler copy. Classic reuses its BR initializer. Sparse retains independent NLEV[1]
only if the compiled plan needs a lift: its transformed coefficient payload is
`L_BR*N*sizeof(T)` for NTT or `L_BR*(N/2)*sizeof(Complex64)` for Fourier, plus
generation metadata sharing the existing ring sampler state. This is the same
material required by the previous explicit fixture; cloning that metadata also
copies its small basis/mask vectors once at setup. No new evaluator buffer or
whole-domain cleartext cache is retained. These storage conclusions follow from
the layouts and call paths; this round did not repeat allocator instrumentation
or measure peak keygen memory.

```sh
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut \
  --features lut,ntru-ntt,ntru-fourier,rustfft -- \
  'c8_d5_o8/evaluate/' --save-baseline lookup-context \
  --sample-size 15 --warm-up-time 1 --measurement-time 3
```

## Default CBS and one-hot workflow, 2026-10-09

`CbsEvaluator` and NTRU `OneHotEvaluator` combine the existing low-level operation
state with `BootstrapResources`. Their owned buffer sets are the same as the
previous separate owners: input/BR/EP/FFT resources and projection storage, without
ordinary output-return scratch. Keys and the Context's transform table remain
borrowed. `into_parts()` moves both owners out for serial composition; it copies
and allocates no buffers. No new Context field or online buffer is introduced.
The configured Context already retains CBS input/gadget metadata; migrated
fixtures now enable that capability. This comparison excludes configuration,
compilation/binding, keygen, encryption, allocation and CMux correctness probes.

Before: `0b93d616`, with manually paired low-level CBS/one-hot state. After: default
Context workflow factories and borrowed ciphertext views. Both measure one
complete CBS or one selector batch into reused output storage. CPU 4, stable
rustc 1.98.1, repository CPU flags, features `ntt,fourier,rustfft`; the same
n728/h32/N1024 secrets, seed 42 keygen, seed 43 inputs, moduli, decompositions,
noise and timing boundaries. Ordinary CBS uses t=4; one-hot uses t=8, M=4.
GLWE measures KS→BR; classic/sparse use their existing matched fixed-weight
fixtures. Each case uses 15 samples, 1 s warm-up and 3 s target measurement.

| Complete workload, u64 | Separate owners, ms | Default workflow, ms |
| --- | ---: | ---: |
| classic/complete/glwe/ntt | 12.661 | 12.630 |
| classic/complete/glwe/rustfft | 15.792 | 15.655 |
| classic/complete/ntru/ntt | 4.232 | 4.193 |
| classic/complete/ntru/rustfft | 5.235 | 5.174 |
| one_hot/classic/M4/full/ntru/ntt | 4.824 | 4.837 |
| one_hot/classic/M4/full/ntru/rustfft | 5.915 | 5.710 |
| one_hot/classic/M4/nonzero/ntru/ntt | 4.582 | 4.597 |
| one_hot/classic/M4/nonzero/ntru/rustfft | 5.689 | 5.528 |
| one_hot/sparse/M4/full/ntru/ntt | 3.935 | 3.779 |
| one_hot/sparse/M4/full/ntru/rustfft | 4.475 | 4.463 |
| one_hot/sparse/M4/nonzero/ntru/ntt | 3.755 | 3.589 |
| one_hot/sparse/M4/nonzero/ntru/rustfft | 4.273 | 4.254 |
| sparse/complete/glwe/ntt | 14.315 | 14.376 |
| sparse/complete/glwe/rustfft | 15.764 | 15.887 |
| sparse/complete/ntru/ntt | 3.234 | 3.246 |
| sparse/complete/ntru/rustfft | 3.747 | 3.759 |

The single matched pairs range from −4.41% to +0.78%. They show no large
measured increase in these workloads; the negative differences do not establish
an optimization, since arithmetic kernels and schedules were not changed.
This is an API/storage check limited to CPU 4/u64/RustFFT scalar performance;
u32, TFHE-FFT and SIMD are covered by correctness/compilation, not these timings.
It does not measure keygen/binding cost or establish security-equivalent profiles.

```sh
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench cbs --features ntt,fourier,rustfft -- \
  '^cbs/(classic|sparse|one_hot)/' --sample-size 15 --warm-up-time 1 --measurement-time 3
```

## Shared operation owner and optional KS, 2026-10-09

These measurements describe an intermediate revision. The current API requires
KS for both PBS and CBS and composes `CircuitBootstrapServerKey` from `ServerKey`
and required CBS material. The timings below do not measure the additional KS
generation/storage of a previously ring-only CBS bundle.

The boxed-owner revision measured below uses one `PbsConfig`/`PbsParameters`
domain with optional KS;
CBS adds gadgets and selector encoding. A context moves complete parameters into
one boxed owner, with no additional shared BR Arc or common sampler clone.
The existing ring-sampler Arcs remain shared by BR/trace/scheme-switch. Moving
PBS into combined PBS/CBS state replaces the owner box at setup, without copying
sampler tables; no context mutation or allocation is added to online requests.
Keys and evaluation scratch retain separate ownership.

Measured inline context sizes for that revision on x86_64 were 288 B for both NTT backends (`U64NttTable`)
and 88 B for both RustFFT backends. NTRU uses external `PowOf2Modulus<u64>`.
These exclude boxed parameters and all referenced heap. A preliminary inline-owner
variant measured 1288/1064 B for GLWE and 1696/1448 B for NTRU with its default
external modulus types; the boxed owner avoids reserving that space in CBS-only
contexts. These are type sizes, not a peak-memory or allocation-count measurement.
The change moves existing parameter metadata to the owner box; it does not claim
a proportional reduction in total retained memory.

Frozen executables compare the preceding complete-context implementation with
the measured boxed-owner design. CPU 4, stable rustc 1.98.1, repository native CPU
flags, features `ntt,fourier,rustfft`, identical numerical fixtures and timing
boundaries. Point estimates in milliseconds; 15 samples, 1 s warm-up, 3 s target
measurement. All listed ordinary workloads still use KS and independent secrets.
A following intermediate cleanup renamed BSK geometry and the BR-selection enum,
centralized numerical constructors, and removed the ordinary shared-secret
no-KS path; optional KS then served ring-output CBS. The current API subsequently
made KS required for both operations, as described above. The table records the
earlier revision, not a measurement of the current required-KS configuration.
No speedup is claimed for the cleanup; PBS/return kernel schedules are unchanged.

| Complete workload, u64 | Before consolidation | Final owner |
| --- | ---: | ---: |
| pbs GLWE NTT | 6.915 | 7.292 |
| pbs GLWE RustFFT | 8.212 | 8.364 |
| pbs NTRU NTT | 16.231 | 16.203 |
| pbs NTRU RustFFT | 19.894 | 19.953 |
| cbs GLWE NTT | 13.009 | 12.646 |
| cbs GLWE RustFFT | 14.831 | 15.645 |
| cbs NTRU NTT | 4.160 | 4.152 |
| cbs NTRU RustFFT | 5.063 | 5.084 |
| high_precision_lut LUT NTT | 48.927 | 48.729 |
| high_precision_lut LUT RustFFT | 56.548 | 56.857 |
| setup GLWE NTT | 19.135 | 17.450 |
| setup GLWE RustFFT | 19.421 | 17.026 |
| setup NTRU NTT | 63.331 | 61.512 |
| setup NTRU RustFFT | 70.016 | 70.207 |

The first pair showed positive differences in GLWE NTT PBS and GLWE RustFFT CBS.
Repeating those cases with the final executable first and the preceding executable
second gave the following point estimates, with 20 samples, 1 s warm-up and 4 s
target measurement:

| Reverse-order repeat, u64 | Before consolidation | Final owner | Difference |
| --- | ---: | ---: | ---: |
| GLWE NTT PBS | 7.093 ms | 7.145 ms | +0.74% |
| GLWE RustFFT CBS | 14.588 ms | 14.612 ms | +0.16% |

These repeats did not reproduce the initial roughly 5% differences. Earlier
inline-owner trials also showed process/order drift in PBS and Fourier lookup;
the measurements do not identify its cause or prove that smaller differences
are absent. This is an API/storage check, not an algorithmic speedup claim.
Context access remains a small inlined borrow; kernels retain their mathematical
schedules and allocate no new online storage. These results do not cover CPU 8,
u32 performance, TFHE-FFT performance, SIMD performance or a security-equivalent
system comparison.

Reproduce with the existing targets and matched filters:

```sh
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench pbs --features ntt,fourier,rustfft -- \
  '^pbs/binary/shortint_2_2/(KeyswitchBootstrap/)?complete/.*/u64$' --sample-size 15 --warm-up-time 1 --measurement-time 3
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench cbs --features ntt,fourier,rustfft -- \
  '^cbs/classic/(KeyswitchBootstrap/)?complete/.*/u64$' --sample-size 15 --warm-up-time 1 --measurement-time 3
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features ntt,fourier,rustfft -- \
  '^high_precision_lut/classic/c8_d5_o8/evaluate/.*/u64$' --sample-size 15 --warm-up-time 1 --measurement-time 3
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench setup --features ntt,fourier,rustfft -- \
  '^setup/binary/boolean/(BootstrapKeyswitch/)?server_keygen/.*/u64$' --sample-size 15 --warm-up-time 1 --measurement-time 3
```

## Complete-context API recheck, 2026-10-09

This intermediate implementation preceded the consolidation above. It retained
prepared PBS/CBS operation state. Numerical
tables, key buffers and online workspaces retain their existing ownership and
layouts. Historical inline context sizes on x86_64, excluding referenced heap:

| Backend, u64 | Previous BR-only context | Complete context |
| --- | ---: | ---: |
| GLWE NTT | 312 B | 624 B |
| GLWE RustFFT | 112 B | 424 B |
| NTRU NTT | 304 B | 1000 B |
| NTRU RustFFT | 104 B | 800 B |

PBS state is inline; optional CBS state has a setup-time box only when enabled.
The shared BR domain and sampling state use their existing shared owners. This
is a metadata-size check, not a new allocation-count measurement. Context setup
does not allocate evaluation scratch or copy a transform table or evaluation key.

CPU 4, stable rustc 1.98.1, repository `target-cpu=native`, features
`ntt,fourier,rustfft`: frozen before/after executables used identical fixtures
and timing boundaries for binary shortint PBS, classic CBS, c8/d5/o8 lookup and
Boolean server keygen. Complete-request repeats did not reproduce the initially
large PBS/CBS differences. This does not establish a speedup or cover other CPUs,
u32 performance, TFHE-FFT performance or SIMD performance.

Configured GLWE RustFFT server keygen initially measured 19.355/19.373 ms,
against 18.468/18.756 ms before the API change. An explicit-parameter call in the
new implementation measured 18.462 ms against 18.634 ms for the old executable.
Inlining the small imported-client preparation boundary, while retaining the
shared material-generation kernel, removed the observed regression:

| Ordered pair | Before | Configured keygen with inlined preparation |
| --- | ---: | ---: |
| before then after | 18.466 ms | 18.500 ms |
| after then before | 18.489 ms | 18.538 ms |

Each pair used 20 Criterion samples, 1 s warm-up and 3 s target measurement.
These are point estimates from complete server-key generation, with returned-key
drop outside timing. They support retaining this small inlining adjustment for
the measured setup path; they do not identify a hardware cause or establish an
algorithmic gain. Recheck when the compiler, FFT engine or keygen layout changes.

```sh
taskset -c 4 cargo bench -p primus_tfhe_benchmarks --bench setup --features ntt,fourier,rustfft -- \
  '^setup/binary/boolean/BootstrapKeyswitch/server_keygen/glwe/rustfft/u64$' \
  --sample-size 20 --warm-up-time 1 --measurement-time 3
```

## Scope and enumeration cost

The cleanup starts from `e76ed14`. It changes benchmark harnesses, parameters
and documentation, not production algorithms or APIs. It retains binary,
ternary, fixed-weight classic/sparse, both GLWE orders, both words and both FFT
engines. Duplicate wrappers/ManyLUT measurements and the legacy two-CMux reference
are removed; the real ternary algorithm remains. CBS owns NTRU one-hot timing.
The lookup pipeline now uses public APIs instead of production-source includes.

| Target | Previous IDs | IDs after cleanup |
| --- | ---: | ---: |
| `primus_tfhe/lookup_table` | 12 | 18 |
| `primus_tfhe_glwe_fourier/circuit_bootstrap` | 8 | 16 |
| `primus_tfhe_glwe_fourier/mvb` | 40 | 80 |
| `primus_tfhe_glwe_fourier/pbs` | 96 | 40 |
| `primus_tfhe_glwe_fourier/sparse_pbs` | 20 | 24 |
| `primus_tfhe_glwe_fourier/ternary_pbs` | 10 | merged into pbs |
| `primus_tfhe_glwe_ntt/circuit_bootstrap` | 4 | 8 |
| `primus_tfhe_glwe_ntt/mvb` | 27 | 40 |
| `primus_tfhe_glwe_ntt/pbs` | 48 | 20 |
| `primus_tfhe_glwe_ntt/sparse_pbs` | 10 | 12 |
| `primus_tfhe_glwe_ntt/ternary_pbs` | 5 | merged into pbs |
| `primus_tfhe_ntru_fourier/circuit_bootstrap` | 4 | 12 |
| `primus_tfhe_ntru_fourier/mvb` | 10 | 28 |
| `primus_tfhe_ntru_fourier/pbs` | 64 | 20 |
| `primus_tfhe_ntru_fourier/sparse_pbs` | 24 | 16 |
| `primus_tfhe_ntru_lut/pipeline` | 30 | 10 |
| `primus_tfhe_ntru_ntt/circuit_bootstrap` | 2 | 6 |
| `primus_tfhe_ntru_ntt/mvb` | 5 | 14 |
| `primus_tfhe_ntru_ntt/pbs` | 32 | 10 |
| `primus_tfhe_ntru_ntt/sparse_pbs` | 12 | 8 |

This table and the full-suite smoke timings below describe the cleanup snapshot.
The lookup pipeline subsequently added ten `dense_seed42` and ten
`shared_middle_chunk` IDs, bringing that target to 30 IDs. The historical
382-case smoke does not cover those additions or later algorithm changes.
Their mapping and timing boundaries are documented in the
[lookup fixture](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#historical-measurements).

There are 20 → 18 targets and 463 → 382 IDs. The previous executables spent
36.83 s collectively running `--list`, including unconditional key generation,
encryption and correctness checks. The current executables took about 0.02 s
on the same machine: Criterion lists names without invoking the callbacks that
create cached fixtures. This is a setup/enumeration improvement, not a claim
about cryptographic execution speed.

Full `--test` smoke passed all 382 IDs with default features (114.83 s) and
nightly SIMD (115.52 s), including key generation. These are unpinned wall times
for functional checks, not a feature-speed comparison; compilation is excluded.
Only selected IDs initialize fixtures. Dense large-parameter benchmarks remain
opt-in and do not add work to the ordinary small-parameter test suite.

The old pipeline used n64/c7/d5/o3, only u64, base8 return keys and sigma0.7 in
all roles. Current n800/c8/d5/o8 changes both table volume and online work; old
latencies are historical, not a before/after ratio. NTRU PBS likewise replaces
q=Q/base9 with independent q24 and backend-specific bases/noise.

## Measurement conditions

Measured on 2026-09-28, AMD Ryzen 9 9955HX3D, x86_64 Linux, logical CPU 0,
repository `target-cpu=native`. Main-workload baseline: stable rustc 1.98.0
(88d9e12ae), LLVM 22.1.8, default features, release bench profile. Storage
comparison: the same nightly rustc 1.100.0-nightly (bff8e12ff), LLVM 23.1.0,
for both default and SIMD configurations. FFT dependencies may use SIMD even
without the workspace feature.

Each measurement uses 15 samples, 300 ms warmup and a 1.2 s target measurement
time, sequentially without concurrent compilation/benchmarks. Criterion can
extend measurement time for slow key generation. Tables below are mean point
estimates; do not interpret small differences as stable improvements. The main
baseline covers 78 IDs across the retained workflow categories. GLWE rows use
BootstrapKeyswitch; the other order remains smoke-covered.

Reproduce a selected ID with the source target named in the workload guide:

```sh
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft -- \
  '^lookup/ntt/u32/n800_N1024/c8_d5_o8/evaluate$' \
  --sample-size 15 --warm-up-time 0.3 --measurement-time 1.2 --noplot \
  --save-baseline cleanup12
```

Criterion saves estimates and confidence intervals under `target/criterion`.
The pipeline IDs formerly named `complete` and `compile_and_drop` are now
`evaluate` and `create_lut_and_drop`; timing boundaries are unchanged. Historical
Criterion results remain under the old IDs.
Record exact parameters and features when making a later comparison; do not
reuse historical baseline names across different geometries.

## Main-workload means

Times are milliseconds per iteration. PBS is binary n866/N2048/t32; sparse PBS
is n728/h32/N1024/t8; CBS is classic n800/N1024/t4; MVB produces all 17 threshold
outputs from D64. Different bases/moduli prevent an equal-security backend ranking.

| Family / backend / word | PBS | Sparse PBS | CBS | MVB, 17 outputs |
| --- | ---: | ---: | ---: | ---: |
| glwe/ntt/u32 | 16.937 | 22.051 | 23.824 | 18.644 |
| glwe/ntt/u64 | 7.191 | 17.372 | 14.836 | 13.446 |
| glwe/rustfft/u32 | 19.883 | 22.483 | 34.591 | 29.596 |
| glwe/rustfft/u64 | 8.422 | 16.117 | 19.215 | 17.256 |
| glwe/tfhe_fft/u32 | 15.571 | 21.501 | 28.949 | 24.533 |
| glwe/tfhe_fft/u64 | 6.461 | 15.855 | 16.154 | 14.113 |
| ntru/ntt/u32 | 17.340 | 5.462 | 6.879 | 11.386 |
| ntru/ntt/u64 | 16.611 | 5.525 | 4.676 | 15.892 |
| ntru/rustfft/u32 | 34.376 | 7.359 | 11.841 | 16.653 |
| ntru/rustfft/u64 | 21.068 | 7.456 | 5.712 | 16.229 |
| ntru/tfhe_fft/u32 | 26.444 | 6.958 | 10.287 | 15.072 |
| ntru/tfhe_fft/u64 | 17.010 | 6.909 | 4.540 | 15.272 |

NTRU one-hot and complete lookup means (ms):

| Backend / word | Full M4 one-hot | Nonzero M−1 one-hot | c8/d5/o8 lookup | LUT compile/drop |
| --- | ---: | ---: | ---: | ---: |
| ntt/u32 | 8.009 | 7.627 | 75.785 | 0.647 |
| ntt/u64 | 5.205 | 4.997 | 52.598 | 0.644 |
| rustfft/u32 | 14.017 | 13.161 | 117.929 | 0.418 |
| rustfft/u64 | 6.462 | 6.237 | 63.701 | 0.410 |
| tfhe_fft/u32 | 11.310 | 10.918 | 97.786 | same native compilation as RustFFT |
| tfhe_fft/u64 | 4.951 | 4.841 | 51.362 | same native compilation as RustFFT |

Sparse server-key generation at u64, n728/h32/N1024 (ms; returned-key drop
excluded), and public native LUT compilation/drop (µs):

| Operation | NTT | RustFFT | TFHE-FFT |
| --- | ---: | ---: | ---: |
| glwe sparse keygen | 387.196 | 548.492 | 537.756 |
| ntru sparse keygen | 214.438 | 256.575 | 251.439 |

Native u32, t255/k4/N1024 public LUT compile/drop: 0.848 µs.

Native u64, t255/k4/N1024 public LUT compile/drop: 0.916 µs.

## Retained heap and online allocation

Bytes requested by the complete lookup fixture, measured separately from timing.
Context/transform tables, input ciphertexts, allocator metadata, stack and peak
transient keygen memory are excluded. Client/server keys are a combined row;
workspace and caller outputs are separate. All six configurations observed zero
online allocations. The public LUT contains 8×64×1024 coefficients.

| Backend / word | Client+server keys | Public LUT | Workspace | Outputs |
| --- | ---: | ---: | ---: | ---: |
| ntt/u32 | 76273288 | 2097152 | 553992 | 25824 |
| ntt/u64 | 92550336 | 4194304 | 877584 | 51456 |
| rustfft/u32 | 132855432 | 2097152 | 1102856 | 25824 |
| rustfft/u64 | 105895472 | 4194304 | 1033232 | 51456 |
| tfhe_fft/u32 | 132855432 | 2097152 | 1102856 | 25824 |
| tfhe_fft/u64 | 105895472 | 4194304 | 1033232 | 51456 |

## Aligned-key recheck

A temporary lattice harness repeated one NTRU coefficient external product with
identical transformed key data borrowed as either Vec-backed or cache-aligned
ABox-backed slices. Setup/conversion/drop were outside timing, and the two
outputs were checked equal before measurement. N1024 uses Q30/base2/L15 for u32
NTT and Q50/base8/L6 for u64; native Fourier uses base2/L16 and base8/L8. These
are the new circuit/lookup internal decompositions, not the previous base9
fixture. Coefficients were deterministic arithmetic data, not encrypted keys.

Means in microseconds, ordinary Vec → aligned ABox:

| Backend / word | Default | SIMD |
| --- | ---: | ---: |
| ntt/u32 | 7.945 → 7.915 | 7.981 → 7.960 |
| ntt/u64 | 5.184 → 5.162 | 5.261 → 5.222 |
| rustfft/u32 | 10.581 → 10.557 | 10.676 → 10.647 |
| rustfft/u64 | 6.249 → 6.233 | 6.237 → 6.223 |
| tfhe_fft/u32 | 7.735 → 7.679 | 7.648 → 7.559 |
| tfhe_fft/u64 | 4.604 → 4.568 | 4.655 → 4.633 |

The small differences do not justify migrating every key container. The ordinary
allocator produced base offsets of 0, 16 or 32 modulo 64 in these runs; aligned-vec
guarantees CACHELINE_ALIGN=128 on this target. This is a container comparison,
not a controlled offset sweep. Vec was measured before ABox, so order/system
drift is not isolated; sub-percent differences are not a stable speedup claim.

Reproduce from the existing lattice `ntru_ntt` / `ntru_fourier` external-product
fixtures by using the bases above and preparing
`AVec::<_, ConstAlign<CACHELINE_ALIGN>>::from_iter(CACHELINE_ALIGN, key.as_ref().iter().copied()).into_boxed_slice()`
outside timing, then borrow each through the same NTT/Fourier NGSW slice view.
Use the same nightly compiler and fixed CPU for default and SIMD runs. The
temporary harness is removed rather than making containers a permanent matrix.

N1024 polynomial strides preserve base alignment. LWE rows have n+1 coefficients
and generally do not; aligning an outer vector does not align separately owned
inner allocations. Capacity and alignment are separate: fixed buffers are
constructed at their final lengths, while resizable workspaces retain Vec/AVec
capacity. No padding, representation change or extra online conversion is
introduced by the current storage policy.

## Fixed-workspace container recheck

A second temporary variant changed only the NTRU external-product workspace's
fixed Box/ABox fields back to Vec/AVec, retaining lengths, initial capacity,
alignment, shared-workspace reuse, key data and all numerical parameters. This
is the same isolated container question as the historical RustFFT investigation.
The comparison uses complete c8/d5/o8 lookup on nightly SIMD for both variants,
with the same CPU and sampling settings; Box was measured first.

| Backend / word | Current Box/ABox (ms) | Temporary Vec/AVec (ms) |
| --- | ---: | ---: |
| ntt/u32 | 69.046 | 68.575 |
| ntt/u64 | 51.882 | 52.699 |
| rustfft/u32 | 115.140 | 116.080 |
| rustfft/u64 | 62.972 | 63.192 |
| tfhe_fft/u32 | 96.293 | 96.059 |
| tfhe_fft/u64 | 50.875 | 50.798 |

Both variants decoded every sampled output correctly and allocated nothing
online. Retained requested workspace heap was identical: buffers already have
exact capacity, and the changed container metadata is inline rather than a new
coefficient allocation. Vec/AVec was about 0.7% faster to 1.6% slower across these
cases, without a consistent advantage. Keep fixed-length ownership and serial
workspace reuse; claim neither a boxed-storage speedup nor an alignment benefit.
The temporary source variant was restored byte-for-byte before final validation.

The larger current public table and deeper output work explain why its retained
memory and latency differ from the historical n64/c7/d5/o3 run. That workload
change is independent of alignment, capacity or container metadata.
