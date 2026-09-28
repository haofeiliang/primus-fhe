# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

The [basic example](examples/ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `compile_lookup_table_fn(function)` defaults to the parameter codec. For a different output plaintext modulus, use `compile_lookup_table_with_codec_fn(&output_codec, function)`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public)`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples default to u32; change `type Word = u32` to `u64` and the `Table` import from `U32NttTable` to `U64NttTable`. Rerun the same command after the edit. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/ntt_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/ntt_sparse.rs); `SPARSE=false` selects classic ManyLUT |
| Classic CBS → CMux | [circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| Sparse CBS → CMux | [sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/mvb_thresholds.rs); `SPARSE=true` selects sparse MVB |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `BarrettModulus`.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. All transformed keys/values must follow the supplied table's representation.

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; change its `ORDER` constant to use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` `_to` calls reuse workspace and caller outputs. See the [resource reuse guide](../primus_tfhe/README.md#reusing-evaluators) for PBS/MVB/CBS ownership conversions and the return-buffer limitation of standalone GLWE CBS.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn` and bind a `FactorizedEvaluator`. The program borrows that context; outputs use unsigned Scaled encoding.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/mvb_thresholds.rs) with `--example mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

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

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Create `context.circuit_bootstrap_evaluator(&server)` or consume ordinary workspace as above. With a classic key generated using `None`, binding CBS returns `MissingCircuitBootstrapKey`. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/ntt_circuit_bootstrap.rs) shows their complete consumption chain.

The [sparse CBS example](examples/ntt_sparse_circuit_bootstrap.rs) shows the fixed-weight secret, sparse key generation and CBS configuration together. Both PBS orders work; subsequent CBS and CMux calls are identical.

The output is `NttGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; advanced `try_from_parts` can use another output basis with the same level count.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

## Further reading

Default features are empty; optional `simd` enables nightly SIMD arithmetic in dependencies.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../primus_tfhe/BENCHMARKS.md)
