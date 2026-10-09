# TFHE benchmarks

English | [简体中文](README.zh_CN.md)

`primus_tfhe_benchmarks` is an unpublished workspace tool, outside the production
crates. Four concrete TFHE backends and high-precision NTRU lookup share
[arithmetic profiles](src/parameters/mod.rs), registration policy and reports.
These profiles have no assessed security or failure-probability guarantee.

## Quick start

From the workspace root, select an operation:

```sh
just bench pbs          # Ordinary PBS
just bench sparse       # Matched fixed-weight classic/sparse PBS
just bench cbs          # Ordinary CBS, classic/sparse
just bench one-hot      # NTRU one-hot, full/compact outputs
just bench mvb          # D8/k3: three paths, classic/sparse
just bench lut-create   # Public high-precision LUT creation, including drop
just bench lut          # Homomorphic high-precision lookup, classic/sparse
```

The operation is required: bare `just bench` does not implicitly run PBS.
By default, commands run **common u64 workloads across all four backends**;
`one-hot`, `lut` and `lut-create` run the supported NTRU NTT and NTRU Fourier backends.
Compilation finishes first, then one Criterion process measures the backends serially.
PBS selects binary shortint; LUT selects the polynomial example with eight
input/output chunks. Parameters and timing policy match the full entry point.

To run only one backend, supply the second argument; Fourier defaults to RustFFT:

```sh
just bench sparse ntru-ntt
just bench sparse glwe-fourier
just bench lut ntru-fourier
```

Append `--list` to list cases without keys, or `--test` for correctness smoke only.
Add `--simd` for nightly SIMD, or `--fft tfhe-fft` to select the other Fourier engine.

Results appear in the terminal. The sections below cover the full matrix, custom
sampling and multi-run reports; everyday runs need no package, feature or long ID.
Without just, use `python3 benchmarks/tfhe/tools/measure.py quick pbs`.

## Full Cargo entry point

Run from the workspace root; discover IDs before selecting a measurement:

```sh
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- --list
cargo bench -p primus_tfhe_benchmarks --bench pbs --features glwe-ntt -- \
  'binary/boolean/KeyswitchBootstrap/complete/glwe/ntt/u32$' --test
cargo bench -p primus_tfhe_benchmarks --bench pbs --features ntru-fourier,rustfft -- \
  'binary/shortint_2_2/complete/ntru/rustfft/u64$'
cargo bench -p primus_tfhe_benchmarks --bench high_precision_lut --features lut,ntru-ntt -- \
  '/create_lut_and_drop/'
```

`--list` generates no keys. `--test` performs correctness probes and one smoke
iteration, without statistical sampling. Omit it to measure. Use named targets:
`--benches` also selects expensive setup and paper diagnostics.

## Features

No backend is enabled by default. An empty selection registers no cases.

| Feature | Selection |
| --- | --- |
| `glwe-ntt`, `glwe-fourier` | Corresponding GLWE backend |
| `ntru-ntt`, `ntru-fourier` | Corresponding NTRU backend, also used by LUT when enabled |
| `lut` | High-precision lookup; combine with an NTRU backend |
| `rustfft`, `tfhe-fft` | Engine for already-selected Fourier dependencies |
| `ntt` / `fourier` | Both backends of that representation plus LUT; Fourier still needs an engine |
| `validation` | Opt-in `validate_parameters` binary and public LUT compiler |
| `simd` | Forward SIMD only to selected backends; requires nightly |

With both FFT engines, RustFFT is primary; each family's PBS includes one extra
TFHE-FFT shortint case. This keeps the matrix small and is not an engine ranking.
Single-engine features can be compiled and run independently.

## Targets

| Target | One measured iteration |
| --- | --- |
| `pbs` | Dense binary/ternary PBS; GLWE orders are explicit |
| `sparse_pbs` | Complete classic/sparse PBS with matched fixed-weight parameters |
| `cbs` | Ordinary CBS, or NTRU one-hot full M / compact M−1 outputs |
| `mvb` | The same k thresholds via independent PBS, ManyLUT or factorized MVB |
| `high_precision_lut` | Separate `create_lut_and_drop` and complete `evaluate` |
| `setup` | Evaluation/public-key generation, or explicitly named raw GLWE BR/KS stages |
| `sparse_paper` | Paper-shaped original/candidate profiles and adapted return path |

All backends in an operation share a Criterion group, enabling HTML comparisons.
IDs place the workload before `family/engine/word`; different orders, output
contracts and profiles remain distinct. Same n/N does not mean equal security.
See [BENCHMARKS.md](BENCHMARKS.md) for the retained matrix and numerical contracts.

The separate `primus_tfhe/lookup_table` benchmark remains in its original crate.

## Source organization

`benches/<operation>.rs` is the feature-gated entry point. Its sibling directory
contains concrete backend implementations, so equivalent workloads can be read
side by side: [PBS](benches/pbs/glwe_ntt.rs), [CBS](benches/cbs/ntru_ntt.rs),
[MVB](benches/mvb/ntru_ntt.rs), and [high-precision lookup](benches/high_precision_lut/ntt.rs).

- [Workloads](src/benchmark.rs) own shared geometry, the matched sparse mapping,
  and the threshold function/path matrix. Numerical profiles remain in `src/parameters/`.
- [Case](src/measurement.rs) supplies the same explicit identity to Criterion and
  metadata. Registration does not reconstruct IDs from historical names.
- Each operation keeps its owned fixture construction separate from measurement.
  `LazyCell` defers setup until a selected callback runs; evaluators borrow those
  owners locally. The paper request uses mutable cached state for its input/output buffers.
- MVB has separate independent, interleaved and factorized measurement methods.
  Ordinary and one-hot NTRU CBS share key/input/candidate construction; selector
  validation is separate from timing. NTT/Fourier kernels and modulus roles remain explicit.

When adding a case, update the workload/profile and retained matrix, then keep
its setup, correctness probe and `b.iter` workload visibly separate. Avoid a
backend trait or a registration macro that hides the operation being measured.

## Measurement and reports

Measurement schema **2** uses 30 samples, 3 seconds warmup and 5 seconds requested
measurement time, with flat sampling. Criterion CLI overrides sample count and
durations. One iteration is one real request; independent PBS performs k calls
because its result is k outputs. MVB/LUT throughput counts output ciphertexts;
latency always covers the whole request. Construction includes drop; keygen uses
`iter_batched` to exclude returned-key destruction.

Selected callbacks lazily cache owned keys/input. Borrowed evaluators and output
buffers are created per callback and reused across its timed iterations. Setup,
verification and metadata stay outside timing. Metadata records actual numerical
parameters; MVB records input and output plaintext moduli separately. Reports reject
strict comparisons with older MVB records that lack these fields, even though the
workload and timing are unchanged. Measurement schema 2 keeps the current fixture
lifetime and sampling policy.

Criterion HTML is enabled. For repeatable Linux measurements, the small standard-
library [runner](tools/measure.py) first builds and freezes Cargo-reported binaries,
then starts serial, CPU-pinned processes. Run `--help` for details:

```sh
python3 benchmarks/tfhe/tools/measure.py build --features glwe-ntt --target sparse_pbs \
  --output target/benchmark-results/artifacts-A
python3 benchmarks/tfhe/tools/measure.py run \
  --build target/benchmark-results/artifacts-A/build.json --cpu 4 --rounds 3 --label A \
  --case 'sparse_pbs:sparse_pbs/fixed_weight/KeyswitchBootstrap/classic/complete/glwe/ntt/u64' \
  --case 'sparse_pbs:sparse_pbs/fixed_weight/KeyswitchBootstrap/sparse/complete/glwe/ntt/u64'
python3 benchmarks/tfhe/tools/report.py target/benchmark-results --output target/benchmark-summary
```

Choose an available CPU. Source snapshots, dirty patch/untracked archive, lockfile
hash, toolchain/features, CPU topology/policy, executable hashes and actual case
parameters accompany each run. Separate source identities use separate build
directories. Unique run/CPU/round/case directories prevent Criterion `new/base`
overwrites. HTML remains under each case's `criterion/`; CSV and Markdown retain
all individual processes. No tool starts parallel PBS/CBS requests or builds while
sampling. Final phase-error diagnostics remain opt-in
(`PRIMUS_LUT_DIAGNOSTICS=1` with `--test`).

Reports make no automatic speedup claim. Pass `--baseline-label A
--candidate-label B` for same-case revision pairs. Explicit `--pair BASE_ID CAND_ID`
with `--comparison algorithm` permits a BR/MVB algorithm change at otherwise equal
parameters; `--comparison arithmetic` allows differing numerical profiles and
lists unequal fields, without an equal-security claim. Positive percentage means
slower. Missing/failed/duplicate pairs, parameter or CPU/feature mismatches and
changed FFT layouts remain visible. FFT APIs do not expose their private selected
algorithm: reports record policy and permutation fingerprints, flag this limitation,
and do not equate equal layouts with equal plans. Within-process intervals do not
measure between-process reproducibility; CPU IDs and rounds are never pooled.

## Validation and asset ownership

Teaching examples and ordinary small-parameter tests stay with their libraries.
Shared Boolean truth tables live in
[`primus_tfhe/tests/common`](../../crates/primus_tfhe/tests/common/boolean.rs) and
are included as test modules, without a separate support package. The numerical diagnostic
uses exactly the same parameter source as benchmarks and lists profiles by default:

```sh
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters \
  --features validation,ntru-ntt -- ntru/ntt/u32
cargo run --release -p primus_tfhe_benchmarks --bin validate_parameters \
  --features validation,glwe-fourier,tfhe-fft -- --list
python3 -m unittest discover -s benchmarks/tfhe/tools -p 'test_*.py'
cargo clippy -p primus_tfhe_benchmarks --all-targets \
  --features validation,ntt,fourier,rustfft,tfhe-fft -- -D warnings
```

Use `--help` for CLI help. Choose one of `--list`, `--all` or a nonempty
substring filter; unknown options, extra arguments and unmatched filters report
an error. No arguments only lists profiles; `--all` explicitly runs all compiled
diagnostic profiles. Ordinary nextest
uses `--lib --tests`; the diagnostic has `test=false` and Criterion is not a test
runner. Workspace `just`/`tfhe` compile and lint these targets; nightly all-features
also checks SIMD. CI runs neither parameter diagnostics nor benchmark sampling.
See the [testing guide](../../guides/development/testing.md).

[Initial schema-2 baseline](../../guides/performance/tfhe-benchmark-schema2.md): six workloads, three independent processes each; a workflow baseline, not a production optimization claim.
