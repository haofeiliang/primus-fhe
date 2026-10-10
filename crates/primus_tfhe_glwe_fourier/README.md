# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with the native torus and Fourier transforms. Provides PBS, ManyLUT, factorized MVB, Boolean gates and CBS with classic binary/ternary or sparse fixed-weight binary blind rotation, in both PBS orders. See the [operation and encoding guide](../primus_tfhe/README.md#choosing-an-operation) and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

## Quick start

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

The [basic example](examples/fourier_basic.rs) combines encrypted inputs as `z=2*x+y`, computes `score=min(z,6)`, then feeds that ciphertext to a second PBS for `price=2*score+[score>=4]`. It uses `Word = u64`, message modulus t=32 and reusable keys, LUTs, evaluator and buffers. Client/server stages are marked in the source; only the final result is decrypted. Feedback requires both the padded input range and an adequate noise budget, not just equal message moduli.

## Experimental paired parameters

```rust
use primus_tfhe_glwe_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// The context uses config.messages; change its output_modulus before construction to override the default.
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

Start with an operation config from [experimental](src/experimental.rs). `PbsConfig` contains BR/KS, PBS order and input/output messages; `CbsConfig` adds CBS gadgets and uses `TfheContext::try_from_cbs_config`. These are arithmetic teaching fixtures with **unassessed security and failure probability**. Numerical choices and noise roles are described in the [family guide](../primus_tfhe_glwe/README.md#experimental-paired-parameters).

`PbsMessageConfig::new(t_in)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes the output independently. Set `config.messages` before PBS context creation, or `config.pbs.messages` for CBS. Clients and compilers derive their encodings from that choice. Same-key overrides are described in [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

## Operation examples

All examples use u64 and prepare reusable state outside the request loop. Replace the example name in the quick-start command to run another workflow.

| Workflow | Config in `experimental` | Complete example |
| --- | --- | --- |
| Two successive PBS calls | `CLASSIC_PBS_U64` | [fourier_basic](examples/fourier_basic.rs) |
| `admin OR (member AND NOT revoked)` | `CLASSIC_PBS_U64`, messages 4→4 | [fourier_boolean](examples/fourier_boolean.rs) |
| The same scoring workflow with sparse BR | `SPARSE_PBS_U64` | [fourier_sparse](examples/fourier_sparse.rs) |
| ManyLUT grade/flag, then encrypted combination | `CLASSIC_MANY_LUT_U64` | [fourier_many_lut](examples/fourier_many_lut.rs) |
| CBS predicate → CMux → ring addition | `CLASSIC_CBS_U64` | [fourier_circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| The same CBS workflow with sparse BR | `SPARSE_CBS_U64` | [fourier_sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| 17 numeric threshold flags from one input | `CLASSIC_THRESHOLD_MVB_U64` | [fourier_mvb_thresholds](examples/fourier_mvb_thresholds.rs) |

Ordinary PBS/ManyLUT and MVB use `context.try_generate_keys(rng)`. Bind the external secret from `client.external_lwe_secret_key()` to `context.encryptor`; decode PBS/ManyLUT with `pbs_decryptor`, and Scaled MVB output with `mvb_decryptor`. Public-key input uses `public_encryptor`. Clients need no LUT or manual codec.

ManyLUT compiles through `pbs_lookup_table_compiler` / `compile_interleaved_fn` and uses `context.evaluator`. Its example maps t_in=16 to t_out=8 and combines the returned grade/flag ciphertexts; they cannot feed the differently encoded input PBS directly. MVB uses `compile_mvb_fn` and `mvb_evaluator`, retaining full input resolution while factor norms amplify noise. Its Scaled flags are not Boolean gate ciphertexts; see the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

CBS uses `context.try_generate_circuit_bootstrap_keys(rng)`, `compile_cbs_fn` and `circuit_bootstrap_evaluator_with_lookup_table`. The examples compile `[m>=2]`, select an encrypted fee plan and add encrypted extra fees. `accumulator_client(client.glwe_secret_key(), t_ring)` encrypts candidates with Scaled encoding; their t_ring=8 is independent of external messages. Ring coefficients are not independent SIMD slots. CMux requires a bit-valued function throughout the input domain, paired secrets and compatible candidates; see the [CBS contract](../primus_tfhe/README.md#cbs-output-and-consumption). Ordinary PBS can reuse `server.server_key()` from the CBS bundle.

## Parameters and representation

Input, accumulator and returned ciphertexts share q. `PbsOrder::BootstrapKeyswitch` exposes the small LWE secret (dimension n); `KeyswitchBootstrap` exposes the flattened ring secret (dimension kN). `context.allocate_lwe_ciphertext()` uses the selected external dimension. The basic example uses BR→KS; the MVB example uses KS→BR. Required KS and its independent noise are described in the [family guide](../primus_tfhe_glwe/README.md#parameters-and-external-key-domain).

The backend supports `NativeModulus<T>` only; `PowOf2Modulus` rings are unsupported. `RustFftTable` and `TfheFftTable` both support u32/u64.

Transformed keys, values and evaluators must use the **same FFT table instance**. Equal length does not establish representation identity. Account for FFT approximation as well as encryption, decomposition and key-switching noise; see the [Fourier contracts](../primus_fft/README.md).

Factorized MVB requires an even actual Scaled output scale `round(2^BITS/t_out)`; an odd scale returns `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling. Budget their amplification and FFT error. See the [MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Sparse BR must be selected explicitly with `BlindRotationMethod::Sparse` in `config.method`; a fixed-weight secret alone still permits classic BR. Sparse requires binary weight `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`. Both orders support PBS, ManyLUT, MVB and CBS. A working PBS configuration does not by itself establish CBS output precision or CMux noise margin.

Keep the context, keys and compiled programs across requests. `_to` methods reuse evaluator scratch and caller outputs; concurrent requests need separate mutable evaluators. MVB programs stay bound to their context. Advanced material composition and per-call borrowing contracts are documented on [KeyGenerator](src/key.rs), [Evaluator](src/evaluator.rs) and [CircuitBootstrapEvaluator](src/circuit_bootstrap/evaluator.rs). Context factories prepare the default workflow directly.

## Features

RustFFT is enabled by default. Normal dependencies enable `fourier`; standalone use does not pull in NTT. Optional `simd` enables nightly SIMD arithmetic in dependencies without selecting an FFT engine.

| Cargo flags | Available engines |
| --- | --- |
| Default | RustFFT |
| `--no-default-features --features tfhe-fft` | TFHE-FFT only |
| `--features tfhe-fft` | Both, chosen by the concrete table type |
| `--no-default-features` | Generic API without a concrete engine |

The examples import `primus_fft::RustFftTable as Table` and declare `required-features = ["rustfft"]` in [Cargo.toml](Cargo.toml). Adding `--features tfhe-fft` alone does not switch them. To run an example with TFHE-FFT alone, change its import to `primus_fft::TfheFftTable as Table` and its target's `required-features` to `["tfhe-fft"]`, then use `--no-default-features --features tfhe-fft`.

Benchmarks already instantiate every enabled engine separately, so their engine selection needs no source changes.

## Benchmarks

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

| Target | Timed request |
| --- | --- |
| [pbs](benches/pbs.rs) | One complete PBS; dense u32/u64 and fixed-weight classic/sparse u64 |
| [many_lut](benches/many_lut.rs) | One two-output grade/flag ManyLUT, u64 |
| [mvb](benches/mvb.rs) | One 17-output threshold MVB, u64 |
| [cbs](benches/cbs.rs) | One predicate CBS plus CMux, u64 |

Each iteration measures one server request with prebuilt keys, LUTs and buffers; setup and decryption checks are untimed. The ManyLUT/CBS targets do not include the examples' subsequent ciphertext arithmetic. Only the fixed-weight classic/sparse PBS pair changes the BR algorithm alone; dense cases use different parameters. Timing boundaries and comparison limits are in the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks).

Measure TFHE-FFT alone with:

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs --no-default-features --features tfhe-fft
```

Use `--features tfhe-fft` with default features to measure both engines separately.

## Further reading

[API sources](src/lib.rs) · [Shared encoding and errors](../primus_tfhe/README.md) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Performance notes](../../guides/performance/README.md)
