# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [NTRU parameter and key domains](../primus_tfhe_ntru/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

The [basic example](examples/ntru_fourier_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `compile_lookup_table_fn(function)` defaults to the parameter codec. For a different output plaintext modulus, use `compile_lookup_table_with_codec_fn(&output_codec, function)`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public)`; see the [family guide](../primus_tfhe_ntru/README.md#clients-and-luts). The example uses external `q=2^24`, distinct from ring `Q`: LUT compilation is at `Q` and the returned LWE is at `q`.

Examples default to u32; change `type Word = u32` to `u64`; select TFHE-FFT by replacing the `RustFftTable as Table` import with `TfheFftTable as Table`. Rerun the same command after the edit. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/ntru_fourier_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/ntru_fourier_sparse.rs); `SPARSE=false` selects classic ManyLUT |
| Classic CBS → CMux | [circuit_bootstrap](examples/ntru_fourier_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/ntru_fourier_mvb_thresholds.rs) |
| One-hot CBS → CMux | [one_hot](examples/ntru_fourier_one_hot.rs) |
| High-precision lookup | [lookup](../primus_tfhe_ntru_lut/examples/fourier_lookup.rs) |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface. NTRU sparse supports ordinary/interleaved PBS, but not CBS, one-hot or factorized MVB.

## Parameters and representation

The Fourier ring supports only `NativeModulus`; `PowOf2Modulus` rings are unsupported. NTRU may independently use `PowOf2Modulus` for external LWE modulus q.

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `NativeModulus`. `LM` in `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` selects the independent external modulus type, defaulting to the backend modulus type. `accumulator_modulus` supplies ring `Q`.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

## Reusing evaluators

Ordinary/interleaved `Evaluator` `_to` calls reuse workspace and caller outputs. See the [resource reuse guide](../primus_tfhe/README.md#reusing-evaluators) for PBS/MVB/CBS ownership conversions. NTRU conversions retain the ordinary PBS return workspace.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn` and bind a `FactorizedEvaluator`. The program borrows that context; outputs use unsigned Scaled encoding. Compile with a codec at Q and decode at q with the same plaintext modulus; budget the difference between `(q/Q)*round(Q/t_out)` and `round(q/t_out)`, plus return noise.

The actual scale `round(2^BITS/t_out)` must be even (`t_out=10` works for u32/u64). Odd scales return `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling; budget their amplification and FFT error.

Classic binary/ternary keys share encrypted initialization and BR, then key-switch each product. Factor norms amplify initialization and BR noise; return-KS noise is added afterward.

Run the [17-threshold example](examples/ntru_fourier_mvb_thresholds.rs) with `--example ntru_fourier_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

Select a fixed-weight binary external-LWE distribution and choose sparse generation explicitly; a low-weight distribution alone still selects classic BR. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Ordinary/interleaved PBS use the same evaluator. CBS/MVB reject sparse keys, including CBS binding with standalone material. `server.sparse_bootstrapping_key()` exposes selectors.

## Optional circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Create `context.circuit_bootstrap_evaluator(&server)` or consume ordinary workspace as above. With a classic key generated using `None`, binding CBS returns `MissingCircuitBootstrapKey`. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/ntru_fourier_circuit_bootstrap.rs) shows their complete consumption chain.

The output is `FourierNgswCiphertext` under `f_acc`. The circuit key binds the complete output basis; `try_from_parts(context, server, circuit_key)` obtains parameters from that key. Budget native trace halving and FFT error against the smallest output gadget scale.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples).

## One-hot CBS

The [one-hot example](examples/ntru_fourier_one_hot.rs) generates four selectors and uses δ₂, selected by `TARGET=2`, in a CMux. Change `TARGET` for another branch. Bind `OneHotCircuitBootstrapEvaluator::try_new(&context, &server)`, allocate once and reuse `_to` calls.

See the [family one-hot contract](../primus_tfhe_ntru/README.md#one-hot-cbs) for full/nonzero output APIs, layout and input guards. NLEV output contains coefficients at Q; use `write_fourier_form` before a public-polynomial external product. NGSW is already in Fourier representation. Inputs, keys and candidates must satisfy this page's transform contract.

## High-precision lookup

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) composes one-hot CBS with table selection, aggregated negative rotations and the independent LWE return. It supports uniform input/output chunk widths and independently chosen counts. For lower-level composition, `ServerKey::initializer()` exposes the classic NLEV[1] under the context's BR basis; `key_switching_key()` exposes the Q→q, f→s return key.

A complete chunk-encryption and lookup workflow is in [fourier_lookup.rs](../primus_tfhe_ntru_lut/examples/fourier_lookup.rs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports.

## Further reading

Default features are empty; optional `simd` enables nightly SIMD arithmetic in dependencies.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../primus_tfhe/BENCHMARKS.md)
