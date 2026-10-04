# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic --features rustfft
```

The [basic example](examples/fourier_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `parameters.lookup_table_compiler(&input_codec)?` creates a reusable compiler; `compiler.compile_fn(function)` uses the selected input codec for outputs. Select a different output encoding with `compiler.try_with_output_codec(&output_codec)?`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, &input_codec)`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples default to u32; change `type Word = u32` to `u64`; select TFHE-FFT by replacing the `RustFftTable as Table` import with `TfheFftTable as Table`. When changing engines, also update the example target’s `required-features` and use `--features tfhe-fft`. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/fourier_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/fourier_sparse.rs); `SPARSE=false` selects classic ManyLUT |
| Classic CBS → CMux | [circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| Sparse CBS → CMux | [sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/fourier_mvb_thresholds.rs); `SPARSE=true` selects sparse MVB |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.glwe_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

The Fourier ring supports only `NativeModulus`; `PowOf2Modulus` rings are unsupported.

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, RustFftTable>::from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `NativeModulus`.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; change its `ORDER` constant to use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and its return stage. CBS owns only LUT/projection state and borrows `pbs.bootstrap_resources_mut()` as the final execution argument. MVB uses `FactorizedEvaluator::new(&pbs)` and takes `&mut pbs` per request. Ordinary PBS resumes when the borrow ends, without evaluator conversion or recovery. The same FFT engine serves input/output KS, BR, trace, scheme switch and factor products; borrowing does not create another FFT workspace.

`ServerKey` remains the convenient complete PBS bundle. Advanced workflows can own `BootstrappingKey`, the ring KS key and `CircuitBootstrapKey` separately; `ServerKey::new` / `into_parts` move them without copying ciphertext arrays. `KeyGenerator::try_generate_bootstrapping_key` and the existing sparse entry generate only BR; `try_generate_glwe_key_switching_key` generates ring KS separately; `try_generate_circuit_bootstrap_key(accumulator_secret, parameters, rng)` needs only the accumulator secret. Separate generation may transform secrets again; paired generation retains its existing transform reuse.

For standalone CBS with an existing `ServerKey`, prepare only the required common resources:

```rust,ignore
let mut resources = context.bootstrap_resources_from_server_key(&server)?;
let circuit_key = server.circuit_bootstrap_key().unwrap(); // Generated with Some(cbs_config).
let mut cbs = CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)?;
```

The factory selects input KS for KS→BR and omits output-KS scratch for BR→KS. `try_new` uses the circuit key's parameters. If PBS is already prepared, pass `pbs.bootstrap_resources()` instead; subsequent CBS calls borrow `pbs.bootstrap_resources_mut()`.

For independently generated material, use `context.bootstrap_resources(br, input_ks)`: BR→KS accepts `None`, while KS→BR requires `Some(ks)`. Standalone CBS does not require an ordinary return key. `Evaluator::try_from_parts(context, br, ks)` binds complete PBS/ManyLUT. Both entries support classic/sparse. Layout, basis and modulus checks do not establish actual secret or transform identity.

`Evaluator::try_from_resources(resources, ks)` assembles ordinary PBS: only BR→KS allocates a missing output stage. `try_rebind_key_switching_key(ks)` reuses the active KS stage's buffers with compatible material; failure leaves its binding intact. CBS/MVB accept any resource instance from the same context, checked before writes. Callers must retain paired secrets, and mutable resource borrows must preserve the owning PBS binding and FFT table instance.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn(&input_codec, &output_codec, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. The input codec is Rounded and the output codec is Scaled, both at the context modulus. The program borrows that context; outputs use unsigned Scaled encoding.

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

## Circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Obtain `server.circuit_bootstrap_key()` and explicitly pass that material to the CBS constructor above. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`, lending common resources to each operation; the [CBS → CMUX example](examples/fourier_circuit_bootstrap.rs) shows independent BR/CBS generation and the complete consumption chain.

The [sparse CBS example](examples/fourier_sparse_circuit_bootstrap.rs) shows the fixed-weight secret, sparse key generation and CBS configuration together. Both PBS orders work; subsequent CBS and CMux calls are identical.

Input encoding and interleaved capacity are checked when binding the evaluator, so compatible programs can reuse the keys with another `t`.

The output is `FourierGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; `try_with_parameters(&resources, parameters, circuit_key, &input_codec)` explicitly selects another output basis with the same level count. Budget native trace halving and FFT error against the smallest output gadget scale.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

## Further reading

This crate enables `fourier` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in NTT. Default features are empty. Select an FFT engine explicitly with `rustfft` or `tfhe-fft`, or enable both; generic APIs do not force an engine. Examples use `rustfft`; tests and benchmarks comparing both engines require `rustfft,tfhe-fft`. Optional `simd` enables only nightly SIMD arithmetic in dependencies, without selecting an FFT engine.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../primus_tfhe/BENCHMARKS.md)
