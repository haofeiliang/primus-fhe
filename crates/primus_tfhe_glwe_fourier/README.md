# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

The basic, sparse, ManyLUT and MVB examples use `PbsMessageConfig`: `new(t)` defaults to equal message moduli, while `with_output_modulus(t_out)` changes only the output. Prepare with `parameters.pbs_codecs` for ordinary PBS/ManyLUT or `parameters.factorized_pbs_codecs` for MVB; the returned codecs distinguish input, LUT output and returned output. `context.decryptor(external_secret, codecs.output_codec())?` accepts Rounded or Scaled outputs; use `decrypt()` to obtain the message. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic --features rustfft
```

The [basic example](examples/fourier_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `parameters.lookup_table_compiler(&codecs)?` binds the prepared input/output encodings; `compiler.compile_fn(function)` creates the LUT. Choose a different output message modulus with `PbsMessageConfig::with_output_modulus`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, codecs.input_codec())`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples use `Word = u64` and Native64, with one explicit parameter set per workflow. The library and numerical diagnostics still support both u32 and u64. Select TFHE-FFT by replacing the `RustFftTable as Table` import with `TfheFftTable as Table`. When changing engines, also update the example target’s `required-features` and use `--features tfhe-fft`. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples start with `main`, followed by local parameters; comments identify client and server stages. Basic and sparse both compute `x % 4` with equal input/output message moduli. The separate ManyLUT example computes `x % 4` and `x / 4`, sets `t_in=16` and `t_out=8`, and decrypts with the output codec. Each example reuses the LUT, evaluator and output buffers for two requests. See [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/fourier_basic.rs) |
| Sparse PBS | [sparse](examples/fourier_sparse.rs) |
| Interleaved ManyLUT with a separate output message modulus | [many_lut](examples/fourier_many_lut.rs) |
| Classic CBS → CMux | [circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| Sparse CBS → CMux | [sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/fourier_mvb_thresholds.rs) |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.glwe_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

The Fourier ring supports only `NativeModulus`; `PowOf2Modulus` rings are unsupported.

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, RustFftTable>::from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `NativeModulus`.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; MVB examples use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and its return stage. CBS owns only LUT/projection state and borrows `pbs.bootstrap_resources_mut()` as the final execution argument. MVB uses `FactorizedEvaluator::new(&pbs)` and takes `&mut pbs` per request. Ordinary PBS resumes when the borrow ends, without evaluator conversion or recovery. The same FFT engine serves input/output KS, BR, trace, scheme switch and factor products; borrowing does not create another FFT workspace.

`Resources` groups borrowed context/evaluation material with owned reusable buffers; it does not own or copy the keys. `Workspace` denotes buffer storage and shape metadata, including lower-level BR/EP scratch. `Evaluator` executes a specific workflow using owned or briefly borrowed resources. Keep the context/key owners alive; serial operations can share one mutable resource instance, while concurrent requests need separate mutable resources. The resources own the FFT engine, which borrows the context’s table; switching resource owners must preserve that table identity.

`ServerKey` remains the convenient complete PBS bundle. Advanced workflows can own `BlindRotationKey`, the ring KS key and `CircuitBootstrapKey` separately; `ServerKey::new` / `into_parts` move them without copying ciphertext arrays. `KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)` uses `BlindRotationConfig` to select classic or sparse BR, without generating return or CBS material; `try_generate_glwe_key_switching_key` generates ring KS separately; `try_generate_circuit_bootstrap_key(accumulator_secret, parameters, rng)` needs only the accumulator secret. Separate generation may transform secrets again; paired generation retains its existing transform reuse.

For ring-output CBS, `context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)` returns `(ClientKey, CircuitBootstrapServerKey)`. This bundle always contains CBS material and generates input KS only for KS→BR. Use `server.bootstrap_resources(&context)` and `server.circuit_bootstrap_key()` to bind the evaluator; see [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

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

Compile through `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. Prepare `codecs` with `parameters.factorized_pbs_codecs(messages)`: Rounded input and Scaled output, both at the context modulus. The program borrows that context; outputs use unsigned Scaled encoding.

The actual scale `round(2^BITS/t_out)` must be even (`t_out=10` works for u32/u64). Odd scales return `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling; budget their amplification and FFT error.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/fourier_mvb_thresholds.rs) with `--example fourier_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

`KeyGenerator::try_generate_server_key(&client, blind_rotation, cbs, rng)` selects `BlindRotationConfig::Classic` or `Sparse { copy_count, bucket_count }` for an existing client. A fixed-weight binary secret supports both choices. `None` for CBS keeps ordinary BR/return material; `Some(config)` also generates CBS keys. The paired `context.try_generate_keys(blind_rotation, cbs, rng)` shortcut accepts the same choice and reuses transformed secrets; independent components do not require a complete bundle. See [algorithm and material choices](../primus_tfhe/README.md#selecting-blind-rotation).

Select a fixed-weight binary small-LWE distribution and choose sparse generation explicitly; the distribution alone does not select the algorithm. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let blind_rotation = BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 2 * h };
let (client, server) = context.try_generate_keys(blind_rotation, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Both orders support ordinary/interleaved PBS, MVB and CBS. Pass `Some(cbs_config)` to include sparse CBS material. `ServerKey::blind_rotation_key()` exposes `BlindRotationKey::{Classic,Sparse}`.

## Circuit bootstrapping

`parameters.circuit_bootstrap_codecs(t_in, t_ring)?` returns Rounded input and Scaled candidate ring codecs with the correct q/Q and independent plaintext domains. Pass the former to the input encryptor and CBS evaluator, and the latter to `accumulator_client`; it does not describe the CBS gadget output.

Compile a custom integer function with `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_lookup_table_slice`. Bind the resulting `CircuitBootstrapLookupTable` with `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?`; `try_new` keeps the identity default. Output lanes use `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other ring integers require the external-product noise contract. The ordinary CBS examples use t_in=8 and show both branches of this predicate.

Use `context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, &mut rng)` for ring outputs. Its `CircuitBootstrapServerKey` owns BR, required input preparation and CBS material; `circuit_bootstrap_key()` returns the required key directly. Mixed PBS/CBS workflows can still generate a complete `ServerKey` with `try_generate_keys(blind_rotation, Some(cbs_config), rng)`. Obtain `server.circuit_bootstrap_key()` and explicitly pass that material to the CBS constructor above. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`, lending common resources to each operation; the [CBS → CMUX example](examples/fourier_circuit_bootstrap.rs) shows grouped BR/CBS generation and the complete consumption chain.

The [sparse CBS example](examples/fourier_sparse_circuit_bootstrap.rs) shows the fixed-weight secret, sparse key generation and CBS configuration together. Both PBS orders work; subsequent CBS and CMux calls are identical.

Input encoding and interleaved capacity are checked at program compilation; binding checks its domain and basis, so compatible programs can reuse the keys with another `t`.

The output is `FourierGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; `try_with_parameters(&resources, parameters, circuit_key, &input_codec)` explicitly selects another output basis with the same level count. For a precompiled program at that basis, use `try_with_parameters_and_lookup_table(&resources, parameters, circuit_key, program)`. Budget native trace halving and FFT error against the smallest output gadget scale.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

The [shared coefficient key](../primus_tfhe_glwe/README.md#sparse-coefficient-keys) is re-exported as `SparseGlweBootstrappingKey<T, NativeModulus<T>>`. Raw sparse BR uses `workspace.blind_rotate_lookup_table_to(&key, input, lut, output, &mut fft)`; the workspace owns scratch and borrows the key only for the call.

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and sparse key generation/rotation in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

Benchmarks live in [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.md#targets). Select the operation target `pbs`, `sparse_pbs`, `mvb`, `cbs` or the explicit `setup` diagnostics. Select `--features glwe-fourier,rustfft` (or `tfhe-fft` instead of `rustfft`).

## Further reading

This crate enables `fourier` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in NTT. Default features are empty. Select an FFT engine explicitly with `rustfft` or `tfhe-fft`, or enable both; generic APIs do not force an engine. Examples use `rustfft`; tests that explicitly compare both engines still require `rustfft,tfhe-fft`. Benchmarks accept either engine independently; with both enabled, RustFFT is primary and `pbs` adds one TFHE-FFT shortint comparison. Optional `simd` enables only nightly SIMD arithmetic in dependencies, without selecting an FFT engine.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../../benchmarks/tfhe/BENCHMARKS.md)
