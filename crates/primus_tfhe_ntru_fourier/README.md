# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [NTRU parameter and key domains](../primus_tfhe_ntru/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

The [basic example](examples/ntru_fourier_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=16` encoding for both input and output, and decodes with `decrypt`. `compile_lookup_table_fn(function)` defaults to the parameter codec. For a different output plaintext modulus, use `compile_lookup_table_with_codec_fn(&output_codec, function)`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public)`; see the [family guide](../primus_tfhe_ntru/README.md#clients-and-luts).

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `NativeModulus`.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

There is one PBS order: encrypted initialization and BR under `f_acc`, then return KS and compact extraction under `f_client`. Binary/ternary client secrets must pass invertibility screening; Fourier additionally screens inverse stability.

## Reusing evaluators

Ordinary/interleaved calls reuse `Evaluator`; use `_to` with existing outputs. For PBS/MVB/CBS alternation, follow the [shared ownership workflow](../primus_tfhe/README.md#reusing-evaluators).

Use `FactorizedEvaluator::try_from_bootstrapper` or `CircuitBootstrapEvaluator::try_from_bootstrapper`. Both reject sparse server keys. The PBS borrow is always available, and `into_bootstrapper()` allocates nothing.

## Fixed-scale factorized MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)` returns `FourierFactorizedLookupTable`, bound to that context instance. Bind a `FactorizedEvaluator` once, or consume an existing ordinary evaluator. Keep the unsigned Scaled codec for decoding; the result is not automatically a Boolean gate input.

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

Native requires **odd h** and a stable Fourier inverse. Coefficient recovery and aggregate FFTs add numerical error.

Matching retries at most eight public maps with the fixed client; it never resamples the client. Every bucket, including encrypted zeros and dummies, contributes noise. Successful matching does not certify security or a complete failure bound. See [sparse rotation invariants](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation) and the [message/carry example](examples/ntru_fourier_sparse.rs).

## Optional circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Create `context.circuit_bootstrap_evaluator(&server)` or consume ordinary workspace as above. With a classic key generated using `None`, binding CBS returns `MissingCircuitBootstrapKey`. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/ntru_fourier_circuit_bootstrap.rs) shows their complete consumption chain.

The output is `FourierNgswCiphertext` under `f_acc`. The circuit key binds the complete output basis; `try_from_parts(context, server, circuit_key)` obtains parameters from that key. Budget native trace halving and FFT error against the smallest output gadget scale.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports.

## Further reading

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
