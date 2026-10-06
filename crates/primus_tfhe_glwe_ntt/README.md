# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

The [basic example](examples/ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `parameters.lookup_table_compiler(&input_codec)?` creates a reusable compiler; `compiler.compile_fn(function)` uses the selected input codec for outputs. Select a different output encoding with `compiler.try_with_output_codec(&output_codec)?`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, &input_codec)`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples default to u32; change `type Word = u32` to `u64` and the `Table` import from `U32NttTable` to `U64NttTable`. Rerun the same command after the edit. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/ntt_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/ntt_sparse.rs); `BLIND_ROTATION` selects classic/sparse |
| Classic CBS → CMux | [circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| Sparse CBS → CMux | [sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/mvb_thresholds.rs); `BLIND_ROTATION` selects classic/sparse |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.glwe_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `BarrettModulus`.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. All transformed keys/values must follow the supplied table's representation. Owning `NttGlweSecretKey` records q; ordinary and evaluation-key generation reject a different key modulus before sampling. Imports use `new(values, size, distribution, modulus)`. Equal q/N does not prove roots/order or secret identity; see the [GLWE key contracts](../primus_glwe/README.md).

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; change its `ORDER` constant to use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and its return stage. CBS owns only LUT/projection state and borrows `pbs.bootstrap_resources_mut()` as the final execution argument. MVB uses `FactorizedEvaluator::new(&pbs)` and takes `&mut pbs` per request. Ordinary PBS resumes when the borrow ends, without evaluator conversion or recovery.

`ServerKey` remains the convenient complete PBS bundle. Advanced workflows can own `BlindRotationKey`, the ring KS key and `CircuitBootstrapKey` separately; `ServerKey::new` / `into_parts` move them without copying ciphertext arrays. `KeyGenerator::try_generate_classic_blind_rotation_key` and the existing sparse entry generate only BR; `try_generate_glwe_key_switching_key` generates ring KS separately; `try_generate_circuit_bootstrap_key(accumulator_secret, parameters, rng)` needs only the accumulator secret. Separate generation may transform secrets again; paired generation retains its existing transform reuse.

For standalone CBS with an existing `ServerKey`, prepare only the required common resources:

```rust,ignore
let mut resources = context.bootstrap_resources_from_server_key(&server)?;
let circuit_key = server.circuit_bootstrap_key().unwrap(); // Generated with Some(cbs_config).
let mut cbs = CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)?;
```

The factory selects input KS for KS→BR and omits output-KS scratch for BR→KS. `try_new` uses the circuit key's parameters. If PBS is already prepared, pass `pbs.bootstrap_resources()` instead; subsequent CBS calls borrow `pbs.bootstrap_resources_mut()`.

For independently generated material, use `context.bootstrap_resources(br, input_ks)`: BR→KS accepts `None`, while KS→BR requires `Some(ks)`. Standalone CBS does not require an ordinary return key. `Evaluator::try_from_parts(context, br, ks)` binds complete PBS/ManyLUT. Both entries support classic/sparse. Layout, basis and modulus checks do not establish actual secret or transform identity.

`Evaluator::try_from_resources(resources, ks)` assembles ordinary PBS: only BR→KS allocates a missing output stage. `try_rebind_key_switching_key(ks)` reuses the active KS stage's buffers with compatible material; failure leaves its binding intact. CBS/MVB accept any resource instance from the same context, checked before writes. Callers must retain paired secrets, and mutable resource borrows must preserve the owning PBS binding.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn(&input_codec, &output_codec, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. The input codec is Rounded and the output codec is Scaled, both at the context modulus. The program borrows that context; outputs use unsigned Scaled encoding.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/mvb_thresholds.rs) with `--example mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

`KeyGenerator::try_generate_server_key(&client, blind_rotation, cbs, rng)` selects `BlindRotationConfig::Classic` or `Sparse { copy_count, bucket_count }` for an existing client. A fixed-weight binary secret supports both choices. `None` for CBS keeps ordinary BR/return material; `Some(config)` also generates CBS keys. The paired `try_generate_keys` shortcut selects classic and retains secret-transform reuse; independent components do not require a complete bundle. See [algorithm and material choices](../primus_tfhe/README.md#selecting-blind-rotation).

Select a fixed-weight binary small-LWE distribution and choose sparse generation explicitly; a low-weight distribution alone still selects classic BR. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = ClientKey::generate(context.parameters(), &mut rng);
let blind_rotation = BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 2 * h };
let server = generator.try_generate_server_key(&client, blind_rotation, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Both orders support ordinary/interleaved PBS, MVB and CBS. Pass `Some(cbs_config)` to include sparse CBS material. `ServerKey::blind_rotation_key()` exposes `BlindRotationKey::{Classic,Sparse}`.

The `sparse_pbs` benchmark includes separate `paper_2026_1730` NAND and padded-function comparisons alongside the existing fixed-weight diagnostics. `complete_ring_return` includes this backend's ring KS return; `blind_rotation` excludes it. Parameters, measurements and differences from the paper are recorded in the [comparison guide](../../guides/performance/sparse-paper-comparison.md); these are experimental benchmark profiles, not security presets.

The separate `sparse_candidate_r2` IDs use two copies, `2*h` buckets and fewer BR levels for the validated STD128 and three-bit function profiles. The [consumer measurements](../../guides/performance/sparse-consumer-measurements.md) cover PBS, ManyLUT, MVB and feedback. CBS needs its own output basis: a working PBS configuration alone does not ensure usable gadget controls or CMux results.

## Circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Obtain `server.circuit_bootstrap_key()` and explicitly pass that material to the CBS constructor above. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`, lending common resources to each operation; the [CBS → CMUX example](examples/ntt_circuit_bootstrap.rs) shows independent BR/CBS generation and the complete consumption chain.

The [sparse CBS example](examples/ntt_sparse_circuit_bootstrap.rs) shows the fixed-weight secret, sparse key generation and CBS configuration together. Both PBS orders work; subsequent CBS and CMux calls are identical.

Input encoding and interleaved capacity are checked when binding the evaluator, so compatible programs can reuse the keys with another `t`.

The output is `NttGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; `try_with_parameters(&resources, parameters, circuit_key, &input_codec)` explicitly selects another output basis with the same level count.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

## Further reading

This crate enables `ntt` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in Fourier/FFT. Default features are empty; optional `simd` enables nightly SIMD arithmetic in dependencies.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../primus_tfhe/BENCHMARKS.md)
