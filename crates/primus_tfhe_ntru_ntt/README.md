# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [NTRU parameter and key domains](../primus_tfhe_ntru/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

The basic, sparse and MVB examples use `PbsMessageConfig`: `new(t)` defaults to equal message moduli, while `with_output_modulus(t_out)` changes only the output. Prepare with `parameters.pbs_codecs` for ordinary PBS/ManyLUT or `parameters.factorized_pbs_codecs` for MVB; the returned codecs distinguish input, LUT output and returned output. `context.decryptor(external_secret, codecs.output_codec())?` accepts Rounded or Scaled outputs; use `decrypt()` to obtain the message. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

The [basic example](examples/ntru_ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `parameters.lookup_table_compiler(&codecs)?` binds the prepared input/output encodings; `compiler.compile_fn(function)` creates the LUT. Choose a different output message modulus with `PbsMessageConfig::with_output_modulus`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, codecs.input_codec())`; see the [family guide](../primus_tfhe_ntru/README.md#clients-and-luts). The example uses external `q=2^24`, distinct from ring `Q`: LUT compilation is at `Q` and the returned LWE is at `q`.

Examples use `Word = u64` and `U64NttTable`, with one explicit parameter set per workflow. The library and numerical diagnostics still support both u32 and u64. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. Message codecs are chosen separately in `main`; key generation does not depend on t. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. The [parameter and validation guide](../../guides/development/tfhe-parameters.md) records numerical choices; each example handles two requests with the same buffers.

Examples start with `main`, followed by local parameters. Each fixes one workflow: classic PBS/CBS/one-hot/MVB, or sparse ManyLUT in the dedicated sparse file. Basic `prepare_server` accepts public context, encoding and evaluation keys only; the two requests reuse the same LUT, evaluator and output buffer. Client encryption and decryption stay in `main`; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/ntru_ntt_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/ntru_ntt_sparse.rs) |
| CBS → CMux | [circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → CMux | [one_hot](examples/ntru_ntt_one_hot.rs) |
| High-precision lookup | [lookup](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs) |

ManyLUT interleaves outputs within one blind rotation, shares one Q→q conversion across multiple outputs, and batches their LWE key switches; factorized MVB uses public factors and a different evaluation interface. NTRU sparse supports ordinary/interleaved PBS, factorized MVB, CBS and one-hot. Sparse BR requires a fixed-weight binary external secret.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.accumulator_ntru_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `BarrettModulus`. `LM` in `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` selects the independent external modulus type, defaulting to the backend modulus type. `accumulator_modulus` supplies ring `Q`.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. The accumulator's `NttNtruSecretKey` records Q, and ordinary/gadget encryption checks it against the parameters/table before sampling. All transformed keys/values must follow the supplied table's roots and evaluation order; matching Q/N cannot prove representation or secret identity.

## Evaluation material

`ServerKey` bundles independently owned `BlindRotationKey`, `NtruLweKeySwitchingKey` and optional `CircuitBootstrapKey`. `into_parts()` moves them out without copying ciphertext buffers; `ServerKey::new(br, return_key, cbs)` combines owners. For independent generation, use `KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)`, `parameters.try_generate_lwe_return_key(&client, rng)` and `generator.try_generate_circuit_bootstrap_key(client.accumulator_ntru_secret_key(), cbs_parameters, rng)`. `BlindRotationConfig` selects classic or sparse BR without generating return or CBS material. Component generation may repeat accumulator conversion; paired generation reuses the transform.

`Evaluator::try_from_parts(context, br, return_key)` binds ordinary PBS. Standalone CBS/one-hot first prepares common BR/external-product resources with `context.bootstrap_resources(br)?`, then operation state with `try_new(&resources, circuit_key, &input_codec)`. No return key is needed; the CBS example demonstrates this workflow. Independent material must use the same actual secrets and transform representation. Shape and modulus checks do not prove identity.

`server_key.blind_rotation_key().classic_controls()` returns a borrowed `ClassicControls` view, or `None` for sparse material. Its `initializer()` lifts public polynomials; coordinate zero uses NLEV bits and later coordinates use NGSW bits, with positive/negative pairs for ternary secrets. CBS and one-hot use the selected classic or sparse BR with independent trace/scheme-switch material. MVB needs no additional lifting or CBS material. The optional `circuit_bootstrap_key()` remains available for inspecting or composing CBS material.

`KeyGenerator::try_generate_public_lift_key(accumulator_secret, &nlev_parameters, rng)` generates independent NLEV[1] for high-precision tables that need it. The parameters select its basis and row noise; keep the ciphertext and parameters together for lookup binding. Sparse PBS/CBS/one-hot and tables without a public lift require no such material.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and scalar/batch return buffers. CBS/one-hot retain only their LUT and projection buffers; pass `pbs.bootstrap_resources_mut()` as the final execution argument. Construct factorized MVB with `FactorizedEvaluator::new(&pbs)` and pass `&mut pbs` as its final execution argument. Ordinary PBS resumes as soon as the borrow ends, without converting or recovering evaluators. Online `_to` calls reuse all buffers. Operation state checks the same context before writes. Classic/sparse resource instances can share it when their actual input and accumulator secrets match; context identity does not establish secret identity.

For CBS/one-hot alone, keep standalone `BootstrapResources` without return buffers. To add PBS later, `Evaluator::try_from_resources(resources, return_key)` takes common resources and allocates return buffers. `try_rebind_return_key` changes compatible return material without reallocation; success discards pending samples, while failure preserves the old binding. Resource ownership does not establish actual secret identity.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. The program borrows that context; outputs use unsigned Scaled encoding. `factorized_pbs_codecs` prepares the Q LUT encoding and q return decoding from the same output message modulus; budget the difference between `(q/Q)*round(Q/t_out)` and `round(q/t_out)`, plus return noise.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Classic binary/ternary and sparse fixed-weight binary keys share the lift and blind rotation across outputs. Each factor product is independently converted from Q to q and extracted; small tiles reuse the PBS workspace for batched LWE key switching. The coefficient polynomial is reused after each extraction, without retaining every product. Factor norms amplify initialization and BR noise; return-KS noise is added afterward.

Run the [17-threshold example](examples/ntru_ntt_mvb_thresholds.rs) with `--example ntru_ntt_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

This backend re-exports the family's [shared coefficient key](../primus_tfhe_ntru/README.md#sparse-coefficient-keys), `SparseNtruBootstrappingKey<T>`. Generation, transforms and bucket aggregation remain backend-specific.

`KeyGenerator::try_generate_server_key(&client, blind_rotation, cbs, rng)` selects `BlindRotationConfig::Classic` or `Sparse { copy_count, bucket_count }` for an existing client. A fixed-weight binary secret supports both choices. `None` for CBS keeps ordinary BR/return material; `Some(config)` also generates CBS keys. The paired `context.try_generate_keys(blind_rotation, cbs, rng)` shortcut accepts the same choice and reuses transformed secrets; independent components do not require a complete bundle. See [algorithm and material choices](../primus_tfhe/README.md#selecting-blind-rotation).

Select a fixed-weight binary external-LWE distribution and choose sparse generation explicitly; the distribution alone does not select the algorithm. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let blind_rotation = BlindRotationConfig::Sparse { copy_count: 3, bucket_count: 2 * h };
let (client, server) = context.try_generate_keys(blind_rotation, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Ordinary/interleaved PBS use the same evaluator; factorized MVB borrows it per call. Pass `Some(cbs_config)` in place of `None` to include CBS/one-hot material, reusing the accumulator transform. For ring-only operations, generate sparse BR and CBS components independently without a return key. `server.blind_rotation_key().sparse_blind_rotation_key()` exposes selectors.

## Optional circuit bootstrapping

Generate paired material with `context.try_generate_keys(blind_rotation, Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Obtain `server.circuit_bootstrap_key()` and pass it with common resources to `CircuitBootstrapEvaluator::try_new`, which explicitly requires CBS material. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/ntru_ntt_circuit_bootstrap.rs) shows their complete consumption chain.

The output is `NttNgswCiphertext` under `f_acc`. The circuit key binds the complete output basis; `try_new(&resources, circuit_key, &input_codec)` obtains parameters from that key. NTT trace normalization requires odd Q below `2^(T::BITS-1)`.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples).

## One-hot CBS

The [one-hot example](examples/ntru_ntt_one_hot.rs) generates four selectors and uses δ₂, selected by `TARGET=2`, in a CMux. Change `TARGET` for another branch. Bind `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)`, allocate once and reuse `_to` calls.

See the [family one-hot contract](../primus_tfhe_ntru/README.md#one-hot-cbs) for full/nonzero output APIs, layout and input guards. NLEV output contains coefficients at Q; use `write_ntt_form` before a public-polynomial external product. NGSW is already in NTT representation. Inputs, keys and candidates must satisfy this page's transform contract.

`ngsw_selector_len()` returns the length of one transformed NGSW selector; `ngsw_batch_len()` returns the complete batch length, including branch zero. Both count NTT ring elements, not bytes.

For a consumer that immediately processes each result, `new_sparse_pair_workspace(&resources)` allocates one additional input state and `with_sparse_pair` blind-rotates two sparse inputs together. Its callback receives index 0 then 1 and a scoped `OneHotProjection`: `project_to` writes full NLEV and/or nonzero NGSW into reusable buffers. Complete consumption within each callback; the high-precision LUT evaluator uses this path automatically.

## High-precision lookup

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) composes one-hot CBS with table selection, aggregated negative rotations and the independent LWE return. It supports uniform input/output chunk widths and independently chosen counts. For lower-level composition, `server_key.blind_rotation_key().classic_controls().unwrap().initializer()` exposes the classic NLEV[1] under the context's BR basis; `key_switching_key()` exposes the Q→q, f→s return key.

A complete chunk-encryption and lookup workflow is in [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs).

For custom returns, bind `LweReturnEvaluator::new(server.key_switching_key(),
context.parameters().external_lwe().cipher_modulus())`, then prepare only the
needed scalar/batch workspace. Pass it explicitly to `return_at_to`,
`return_prefix_to`, or the stream operations; one-hot and transform scratch remain
independently usable. See the [family return contract](../primus_tfhe_ntru/README.md#ntrulwe-returns).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports.

Benchmarks live in [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.md#targets). Select the operation target `pbs`, `sparse_pbs`, `mvb`, `cbs` or the explicit `setup` diagnostics. Select `--features ntru-ntt`.

## Further reading

This crate enables `ntt` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in Fourier/FFT. Default features are empty; optional `simd` enables nightly SIMD arithmetic in dependencies.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../../benchmarks/tfhe/BENCHMARKS.md)
