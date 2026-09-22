# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

The [basic example](examples/fourier_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=16` encoding for both input and output, and decodes with `decrypt`. `compile_lookup_table_fn(function)` defaults to the parameter codec. For a different output plaintext modulus, use `compile_lookup_table_with_codec_fn(&output_codec, function)`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public)`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `NativeModulus`.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example runs both orders with ternary input secrets.

## Reusing evaluators

Ordinary/interleaved calls reuse `Evaluator`; use `_to` with existing outputs. For PBS/MVB/CBS alternation, follow the [shared ownership workflow](../primus_tfhe/README.md#reusing-evaluators).

GLWE MVB consumes ordinary workspace with `FactorizedEvaluator::from_bootstrapper`. CBS uses `CircuitBootstrapEvaluator::try_from_bootstrapper` and requires bundled CBS material. Standalone BR→KS CBS omits return-KS buffers: `bootstrapper_mut()` returns `None`, and `into_bootstrapper()` explicitly allocates those missing buffers. KS→BR CBS and CBS converted from ordinary PBS retain them; their PBS borrow is `Some` and recovery allocates nothing.

## Fixed-scale factorized MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)` returns `FourierFactorizedLookupTable`, bound to that context instance. Bind a `FactorizedEvaluator` once, or consume an existing ordinary evaluator. Keep the unsigned Scaled codec for decoding; the result is not automatically a Boolean gate input.

The actual scale `round(2^BITS/t_out)` must be even (`t_out=10` works for u32/u64). Odd scales return `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling; budget their amplification and FFT error.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/fourier_mvb_thresholds.rs) with `--example fourier_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

Select a fixed-weight binary small-LWE distribution and choose sparse generation explicitly; a low-weight distribution alone still selects classic BR. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = ClientKey::generate(context.parameters(), &mut rng);
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Both orders support ordinary/interleaved PBS, MVB and CBS. Pass `Some(cbs_config)` to include sparse CBS material. `ServerKey::bootstrapping_key()` exposes `BootstrappingKey::{Classic,Sparse}`.

Matching retries at most eight public maps with the fixed client; it never resamples the client. Every bucket, including encrypted zeros and dummies, contributes noise. Successful matching does not certify security or a complete failure bound. See [sparse rotation invariants](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation).

## Circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Create `context.circuit_bootstrap_evaluator(&server)` or consume ordinary workspace as above. With a classic key generated using `None`, binding CBS returns `MissingCircuitBootstrapKey`. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/fourier_circuit_bootstrap.rs) shows their complete consumption chain.

The example uses classic keys in both orders and reuses the LWE input, GGSW control and GLWE selection buffers. For sparse CBS, use the explicit key generation workflow in [Experimental sparse PBS](#experimental-sparse-pbs), passing `Some(cbs_config)` instead of `None`, then create `context.circuit_bootstrap_evaluator(&server)`. The CBS and CMUX calls are the same.

The output is `FourierGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; advanced `try_from_parts` can use another output basis with the same level count. Budget native trace halving and FFT error against the smallest output gadget scale.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

## Further reading

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
