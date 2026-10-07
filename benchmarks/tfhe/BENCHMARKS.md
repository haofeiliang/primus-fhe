# TFHE benchmark workloads

Targets for the four backends and high-precision LUT live in
[`primus_tfhe_benchmarks`](README.md). The [target map](README.md#targets) gives
the seven operation targets and old-to-new ID mapping.
Measurement schema 2 changes grouping and defaults, while keeping numerical profiles and timed operations.
The standalone `primus_tfhe/lookup_table` target remains in its original crate.

The five ordinary operation targets and two explicit setup/paper targets use the shared
[parameter profiles](../../guides/development/tfhe-parameters.md).
The suite retains representative u32/u64, FFT-engine and GLWE PBS-order
comparisons without crossing those axes for every operation. These are arithmetic
cost fixtures, not assessed security parameters or equal-security comparisons.

## Reduced suite specification

The ordinary registrations follow the matrix below. Setup and stage timings
live in `setup`; GLWE NTT paper comparisons live in
`sparse_paper`. Neither is registered by ordinary `pbs` or `sparse_pbs`. Numerical profiles, key
layouts, aggregation windows and workspace layouts are unchanged.

Use one primary Fourier engine per build: RustFFT when available, otherwise
TFHE-FFT. This follows the teaching workflow, not a measured engine ranking.
With both features enabled, retain an explicit engine comparison only for u64
binary shortint PBS in each family. Enable `rustfft` or `tfhe-fft` independently;
select the backend separately (`glwe-fourier` or `ntru-fourier`).
The LUT pipeline selects `lut` plus `ntru-ntt` and/or `ntru-fourier`.
Cargo's `required-features` cannot express an OR: these targets select their
cases with cfg and register no IDs if no applicable backend
is enabled. GLWE uses `KeyswitchBootstrap` unless a row says otherwise;
`BootstrapKeyswitch` retains an explicit complete-request comparison in `pbs`.

| Target / retained cases | IDs across all four backends | Reason |
| --- | ---: | --- |
| Dense `pbs`: each backend keeps u32 binary Boolean, u64 binary shortint, and u64 ternary Boolean; each GLWE backend also keeps u64 binary shortint with the other order | 14 | Retain both words, both secret distributions and both orders without crossing every axis |
| Fourier `pbs`: secondary engine, u64 binary shortint, one per family | 2 when both engines are enabled | Compare engines using the same workload as the primary-engine case |
| `sparse_pbs`: u64 classic/sparse fixed-weight pairs in every backend; u32 pairs in GLWE NTT and NTRU Fourier | 12 | Retain all four BR comparisons plus representative prime/native u32 arithmetic |
| Ordinary `cbs`: u64 classic/sparse pair in each backend | 8 | Measure the complete gadget-producing operation |
| NTRU one-hot: u64, classic/sparse, full M4 and compact M-1 in both backends | 8 | Measure the real saving from omitting selector zero |
| `mvb`: each backend keeps u64 D8/k3 classic/sparse with independent/interleaved/factorized; D64/k17 classic with independent/factorized | 32 | Preserve capacity-inside/outside comparisons and sparse factorized consumption |
| LUT `high_precision_lut`: u64 NTT and primary Fourier; polynomial, dense_seed42 and shared_middle_chunk; classic/sparse evaluation | 12 | Distinguish general evaluation, polynomial structure and cross-output sharing |
| LUT `high_precision_lut`: the same three public tables, u64 Q50 Barrett and Native64 construction/drop | 6 | Construction depends on the coefficient modulus, not the BR variant or FFT engine |
| `lookup_table`: u64 Native for all three geometries; t32/k1 additionally at u64 PowOf2 q24, u64 Barrett Q50, and u32 Barrett Q27 | 6 | Retain each packing shape and modulus family without their full cross-product |

This selects 98 ordinary IDs, or 100 with the two secondary-engine PBS IDs,
including the six `primus_tfhe/lookup_table` IDs outside this package. This package has 92 ordinary IDs (94 with both FFT engines), plus 20 setup and 36 paper IDs. It is a selection of benchmark
workloads, not a CI run list or a restriction on supported APIs. Other word,
order and engine combinations remain covered by focused correctness tests and
independent feature compilation. D64/k17 sparse remains supported; it is not a
second default timing matrix. Each backend contributes eight primary MVB IDs; the lookup
pipeline has eighteen with NTT and one Fourier engine enabled.

Keep the existing dense, circuit and fixed-weight parameter constructors,
including modulus types, noise units, decomposition and seeds. In particular,
ordinary sparse pairs keep n728/h32/N1024, three copies and 64 buckets; the
lookup pipeline keeps c8/d5/o8 and n800/h32/N1024. Ternary and binary profiles
still differ, so those IDs do not isolate the cost of the secret distribution.
No claim of equal security follows from choosing these cases.

## Explicit diagnostics

| Entry | Retained work |
| --- | --- |
| Four backends' `setup` | u64 dense binary/ternary and fixed-weight classic/sparse keygen; GLWE also keeps binary raw BR/KS at n800/N1024. Primary FFT engine only: six GLWE / four NTRU IDs per backend, 20 total |
| GLWE NTT `sparse_paper` | The 36 original/candidate paper IDs, including u32/u64 at the same small prime and raw-BR versus complete-return boundaries |
| LUT `high_precision_lut`, `PRIMUS_LUT_DIAGNOSTICS=1` with `--test` | Existing fixture's final phase error; no extra workload matrix |
| `validate_parameters` binary | Numerical profiles and detailed intermediate phase checks; `--list` discovers profiles without keys, backend and engine features select profiles; no arguments only lists, --all explicitly runs everything |

Setup keeps the existing numerical profiles for the retained cases.
u32 and secondary-engine setup timings are no longer default registrations;
the numerical diagnostic retains their parameter coverage. Historical measurements
remain in the performance guides; use their pinned revisions for removed IDs.
Listing and filtering stay lazy: unselected cases do not generate keys.

```sh
cargo bench -p primus_tfhe_benchmarks --bench setup --features glwe-ntt -- --list
cargo bench -p primus_tfhe_benchmarks --bench setup --features ntru-fourier,tfhe-fft -- --list
cargo bench -p primus_tfhe_benchmarks --bench sparse_paper --features glwe-ntt -- 'std128_' --list
PRIMUS_LUT_DIAGNOSTICS=1 cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt -- \
  'sparse/.*/shared_middle_chunk/evaluate/lookup/ntt/u64$' --test
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters --features validation,ntt -- --list
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters --features validation,fourier,tfhe-fft -- --list
```

Named ordinary targets do not include setup or paper timings. Cargo `--benches`
selects all bench targets, including diagnostics; prefer a named target/filter
for an ordinary timing or smoke run. These are not CI execution requirements.

Lower-level arithmetic benchmarks and historical measurement records are
outside this registration reduction.

## Targets and measurement boundaries

| Target | Question answered / one iteration |
| --- | --- |
| `primus_tfhe/lookup_table` | Compile and drop one public LUT: ordinary t32/k1, padded interleaving t16/k3, or tight cells t255/k4; N1024, Native/PowOf2 q24/Barrett |
| Four backends' `pbs` | One complete dense binary PBS at u32 n800/N1024/t4 or u64 n866/N2048/t32; u64 ternary at n800/N1024/t4 |
| GLWE `setup` stage IDs | One BR or one GLWE key switch at binary n800/N1024; excludes extraction and prerequisite operations |
| Four backends' `sparse_pbs` | One complete classic or bucket-sparse PBS for the same n728/h32/N1024/t8 secret profile |
| GLWE NTT `sparse_paper` | Table-3-shaped NAND and padded 3-bit PBS: dense ternary classic, fixed-weight classic and sparse; complete q-to-q request with ring KS and raw BR, with explicit return/decomposition adaptations |
| Four backends' `mvb` | Produce k Scaled threshold bits from one input: D8/k3 compares independent PBS, interleaved ManyLUT and factorized MVB; D64/k17 compares independent and factorized because interleaving does not fit |
| Four backends' `cbs` | One ordinary CBS into a reused gadget ciphertext; all backends pair classic/sparse at n728/h32/N1024/t4; NTRU also pairs full M4 / compact M-1 one-hot batches at t8 |
| `primus_tfhe_benchmarks/high_precision_lut` | `create_lut_and_drop`: create/drop one public high-precision LUT; `evaluate`: homomorphically evaluate all eight outputs at c8/d5/o8 (16 input/output bits), paired classic/sparse n800/h32/N1024, excluding public LUT creation |

CBS and NTRU one-hot fix the client seed and give input encryption its own seed, so both
BR variants receive identical fixed-weight secrets, input ciphertexts and LUTs.
The current [sparse measurement report](../../guides/performance/sparse-baseline.md)
records paired latency, stage costs, setup and memory accounting.

GLWE NTT's separate `sparse_paper` target provides `paper_2026_1730` IDs. These use q=512/4096,
N=1024/2048, fixed weights 43/31/70 and three copies with h+3 buckets. Gate
cases measure one NAND on two fresh Boolean inputs and compare u32/u64 at the
same 28-bit prime. The 54-bit `padded_func3` case uses u64 and one padded PBS,
not full-domain arbitrary-function evaluation. `complete_ring_return` includes
Primus's ring KS return at Q; `blind_rotation` excludes that return. The original
fixed-weight IDs remain regression diagnostics. See the
[paper comparison](../../guides/performance/sparse-paper-comparison.md) for
exact parameters, the benchmark-only q-to-Q adapter, full measurement commands,
and the limits of comparison with OpenFHE. No paper safety claim is inherited.

MVB compares classic and sparse keys in all four backends. D8/k3 compares
independent PBS, interleaved ManyLUT and factorized MVB; D64/k17 keeps a classic
independent/factorized pair beyond interleaved capacity.
Each backend registers eight u64 MVB IDs; GLWE uses `KeyswitchBootstrap`, and
Fourier uses the primary engine.
Throughput for MVB and complete lookup counts **output ciphertexts**; latency
still measures the whole batch. NTRU output phases are decoded at external q24,
while their public coefficient tables are encoded at ring Q.

Repeated ManyLUT cases now live in `mvb`, not in both PBS files. Boolean AND/MUX
wrappers and the legacy two-CMux ternary implementation are no longer separate
timings. Ternary PBS itself remains. The former `ternary_pbs` targets have been
merged into `pbs`. One-hot belongs to the NTRU CBS target. The LUT pipeline uses
the public evaluator, without compiling a second copy of production sources to
access private stages. Primitive arithmetic remains in the lattice/scheme
benchmarks; additional stage probes should have a concrete diagnostic purpose.

The lookup pipeline includes both the polynomial example and `dense_seed42`,
a fixed dense mapping with the same geometry. Use these to distinguish
subtable-reuse gains from general evaluation costs; their construction and
evaluation remain separately timed.

## Numerical parameters

[Shared constructors](src/parameters/mod.rs) separate
numerical choices from timing code. The parameter guide records every modulus,
noise unit, decomposition and secret distribution. Dense binary GLWE PBS
retains the profiles below; ternary uses the separate circuit profile and must
not be treated as a matched-parameter binary/ternary speed comparison.

| Dense binary GLWE | BR (log basis, levels) | KS (log basis, levels) |
| --- | --- | --- |
| u32 NTT Q27 | (5,5) | (2,13) |
| u32 Fourier Native32 | (8,3) | (2,13) |
| u64 NTT Q50 / Fourier Native64 | (23,1) | (3,5) |

NTRU uses independent `PowOf2Modulus(2^24)` external LWE and return keys.
The ring uses Q27 for ordinary u32 NTT PBS, Q30 for circuit products, Q50 for
u64 NTT, or Native32/64 for Fourier. Full internal decomposition uses log basis
2 for u32 and 8 for u64; return KS uses (3,8) at q24. Ring sigma is 0.7,
return-key sigma is 3.2, and external sigma follows the dense/fixed-weight
profile. These replace the former q=Q/base9/sigma0.7-everywhere benchmark.

The reference is pinned to
[TFHE-rs 1.8.1, `V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128`](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_8/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs#L5-L7).
In that release the V1_8 constant aliases V1_4. The
[resolved values in the same release](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_4/classic/gaussian/p_fail_2_minus_128/ks_pbs.rs#L258-L280)
are unchanged, so updating the reference does not require changing this fixture's
numerical parameters.
The u64 GLWE workload borrows its dimensions, decomposition and normalized
Gaussian standard deviations. This project's API takes **coefficient-unit**
standard deviations, so multiplication by the ciphertext modulus is required.
The u32 choices use separate decomposition shapes instead of truncating the
u64 parameters. In particular, the former NTT `(7, 3)` PBS decomposition failed
a t=32 LUT output check; `(5, 5)` reduces digit-amplified key noise while keeping
more decomposition bits. NTRU's full decomposition means the maximum complete
levels accepted by `ApproxSignedBasis` (`None`), not necessarily zero dropped bits.

This is not a TFHE-rs parameter port: this project uses GLWE key switching,
supports both PBS orders, lacks the reference's centered-mean modulus-switch
noise reduction, and also uses explicit prime moduli. NTRU is a separate
construction. The reference's failure probability and security claim do not
transfer to these workloads.

## Selecting the TFHE-rs 1.8.1 counterpart

Choose the explicit Gaussian constant above for the current shortint comparison.
Our LWE/GLWE encryption APIs take Gaussian noise parameters. TFHE-rs 1.8.1's
[default `PARAM_MESSAGE_2_CARRY_2` alias](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/aliases.rs#L54-L60)
instead selects TUniform. These are distinct comparison targets:

| TFHE-rs 1.8.1 parameter | Width | `n` | `k` | `N` | PBS `(base_log, levels)` | KS `(base_log, levels)` |
| --- | --- | ---: | ---: | ---: | --- | --- |
| Explicit Gaussian 2+2 | u64 | 866 | 1 | 2048 | (23, 1) | (3, 5) |
| Default TUniform 2+2 | u64 | 918 | 1 | 2048 | (23, 1) | (4, 4) |
| Boolean `DEFAULT_PARAMETERS` | u32 | 805 | 3 | 512 | (10, 2) | (3, 5) |
| Boolean `DEFAULT_PARAMETERS_KS_PBS` | u32 | 739 | 3 | 512 | (10, 2) | (3, 4) |

The [TUniform 2+2 values](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_4/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs#L29-L47)
are reached through the
[V1_8 TUniform alias](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/shortint/parameters/v1_8/classic/tuniform/p_fail_2_minus_128/ks_pbs.rs#L5-L7).
They use `new_t_uniform(45)` for LWE and `new_t_uniform(17)` for GLWE. Those
arguments are TUniform parameters, not Gaussian standard deviations; copying
only `n=918` and KS `(4,4)` would not reproduce the default parameter set.

The [Boolean values](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.1/tfhe/src/boolean/parameters/params.rs#L10-L45)
also differ from our common `boolean` fixture (`n=800, k=1, N=1024`). Keep that
fixture for regression and common GLWE/NTRU geometry; it is not a reproduction
of TFHE-rs's Boolean defaults. Likewise, NTT prime moduli, u32 shortint and NTRU
remain adaptations. Report the exact parameter name and PBS order alongside any
TFHE-rs timing, and distinguish a workload comparison from matching parameters.

## Running and comparing

```sh
# Listing does not generate keys, encrypt inputs, or execute correctness probes.
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- --list
# Run one retained workload once, including its untimed known-result check.
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- \
  'binary/boolean/KeyswitchBootstrap/complete/glwe/ntt/u32$' --test
# Measure one complete workload; pin an available CPU for revision comparisons.
taskset -c 0 cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- \
  'binary/shortint_2_2/BootstrapKeyswitch/complete/glwe/ntt/u64$' \
  --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

Targets use 30 samples, 3 s warmup, 5 s requested measurement and flat sampling; Criterion CLI can override the sample count and durations. Owned fixtures are created
inside the selected benchmark callback and cached across samples. Evaluators
borrow those fixtures locally. Encryption, table preparation, workspace/output
allocation and correctness probes stay outside online timing. Key-generation
IDs include generation allocations but use `iter_batched` so returned-key drop
is untimed. Compilation IDs explicitly include LUT allocation, filling and drop.

There is no manual repetition to amplify timings. Independent multi-output PBS
performs k calls because its real workload is k outputs. Dispatch between
algorithms occurs outside `b.iter`; inputs are fixed encrypted messages and
outputs/scratch are overwritten. Seed 42 establishes the client fixture; sparse
keygen uses seed 4242. A known-result probe checks the measured operation, while
exhaustive/phase-margin diagnostics remain in `validate_parameters` and tests.

High-precision `evaluate` IDs report final phase error only with
`PRIMUS_LUT_DIAGNOSTICS=1`. Ordinary runs retain known-result checks.
Phase probes are untimed. See the [pipeline boundaries](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#benchmark-fixture).

Build before timing and avoid concurrent compilation or benchmarks. Record CPU,
affinity, compiler, features, profile and exact ID. The repository already uses
`target-cpu=native`. Default FFT dependencies may still use SIMD internally;
the workspace `simd` feature is a distinct configuration.

For the SIMD benchmark configuration only:

```sh
taskset -c 0 cargo +nightly bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt,ntru-fourier,simd,rustfft -- \
  '/evaluate/' --sample-size 20 --warm-up-time 0.5 --measurement-time 2 --noplot
```

The [historical measurement record](../../guides/performance/tfhe-baseline.md)
records the baseline and storage experiment. Earlier n16/n64 lookup or
q=Q/base9 NTRU results have different work and cannot be divided by these
results to claim an implementation speedup or regression.

The [runner and report guide](README.md#measurement-and-reports) records schema-2 identities, frozen artifacts, actual parameters and process-level pairing. Do not merge these baselines with the earlier registration layout.
