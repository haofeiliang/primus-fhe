# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [NTRU parameter and key domains](../primus_tfhe_ntru/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Experimental paired parameters

```rust
use primus_tfhe_ntru_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table, _>::try_from_pbs_config(config)?;
let parameters = context.parameters();
let br = context.parameters();
// Optional: parameters.messages().with_output_modulus(8) changes only this program's output.
let codecs = br.pbs_codecs(parameters.messages())?;
```

`PbsConfig` is one complete numerical description, containing BR/KS choices and input/output messages. `CbsConfig` describes ring-output CBS; its gadget output has no ordinary message codec. `experimental` also exports `SPARSE_PBS_U64`, `CLASSIC_MANY_LUT_U64`, `CLASSIC_THRESHOLD_MVB_U64`, `CLASSIC_CBS_U64` and `CLASSIC_ONE_HOT_U64`. The context retains the selected algorithm, KS, messages and optional CBS state; default keygen does not receive them again. Configs are `Copy`, so field overrides and struct-update syntax work without preparing samplers first.

These u64 constants are arithmetic examples, with unassessed security and failure probability. See the [family configs](../primus_tfhe_ntru/README.md#experimental-paired-parameters) for composition, independent message overrides and numerical contracts. Every example starts from the matching operation config; advanced explicit composition remains available through the family constructors. Prepared `PbsParameters` remain reusable with compatible encodings; changing a workload still needs a new error budget.

## Quick start

The basic, sparse, ManyLUT and MVB examples use `PbsMessageConfig`: `new(t)` defaults to equal message moduli, while `with_output_modulus(t_out)` changes only the output. Prepare with `br.pbs_codecs` for ordinary PBS/ManyLUT or `br.factorized_pbs_codecs` for MVB; the returned codecs distinguish input, LUT output and returned output. `context.decryptor(external_secret, codecs.output_codec())?` accepts Rounded or Scaled outputs; use `decrypt()` to obtain the message. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

The [basic example](examples/ntru_ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `br.lookup_table_compiler(&codecs)?` binds the prepared input/output encodings; `compiler.compile_fn(function)` creates the LUT. Choose a different output message modulus with `PbsMessageConfig::with_output_modulus`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, codecs.input_codec())`; see the [family guide](../primus_tfhe_ntru/README.md#clients-and-luts). The example uses external `q=2^24`, distinct from ring `Q`: LUT compilation is at `Q` and the returned LWE is at `q`.

Examples use `Word = u64` and the operation config listed below. Dimensions, modulus representation, secret distributions, noise and decompositions live in `experimental`; each `main` shows only preparation, the public function, clients and evaluation. CBS uses the prepared `CbsParameters` and independently chooses the candidate ring-message domain. Explicit u32/u64 parameter composition remains available; see the [family configs](../primus_tfhe_ntru/README.md#experimental-paired-parameters) and [parameter guide](../../guides/development/tfhe-parameters.md).

Comments identify client and server stages. Basic and sparse both compute `x % 4` with equal input/output message moduli. The separate ManyLUT example computes `x % 4` and `x / 4`, sets `t_in=16` and `t_out=8`, and decrypts with the output codec. Each example reuses the LUT, evaluator and output buffers for two requests. See [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Config in `experimental` | Complete example |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/ntru_ntt_basic.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/ntru_ntt_sparse.rs) |
| Interleaved ManyLUT with a separate output message modulus | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/ntru_ntt_many_lut.rs) |
| CBS → CMux | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| Factorized MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → CMux | `CLASSIC_ONE_HOT_U64` | [one_hot](examples/ntru_ntt_one_hot.rs) |
| High-precision lookup | `primus_tfhe_ntru_lut::experimental::NTT_CLASSIC_LOOKUP_U64` | [lookup](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs) |

ManyLUT interleaves outputs within one blind rotation, shares one Q→q conversion across multiple outputs, and batches their LWE key switches; factorized MVB uses public factors and a different evaluation interface. NTRU sparse supports ordinary/interleaved PBS, factorized MVB, CBS and one-hot. Sparse BR requires a fixed-weight binary external secret.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.accumulator_ntru_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

`PbsParameters::try_from_config(pbs_config)` retains required KS, the algorithm and messages; `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` adds CBS gadgets and input encoding. Context construction retains one common parameter owner and transform table. `parameters()` always exposes the complete PBS domain; `cbs_parameters()` queries additional CBS capability. PBS and CBS share required KS, which downstream consumers can use to return ring/gadget computations to LWE.

Move prepared parameters into `TfheContext::try_from_parameters(parameters)` or `try_from_cbs_parameters(parameters)`; `try_new(parameters, table)` accepts an existing table. Default preparation does not copy the common sampler. CBS and PBS retain the ring sampler's existing Arc without a separate BR parameter owner. `PbsParameters::try_from_config(pbs)` prepares common state; `CbsParameters::try_from_config(pbs, gadget)` or `try_with_config(parameters, gadget)` adds CBS. The latter moves prepared state; selector messages come from the PBS parameters. `LM` selects the external-q modulus type; `PbsConfig.acc_modulus` specifies ring Q.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. The accumulator's `NttNtruSecretKey` records Q, and ordinary/gadget encryption checks it against the parameters/table before sampling. All transformed keys/values must follow the supplied table's roots and evaluation order; matching Q/N cannot prove representation or secret identity.

## Evaluation material

`ServerKey` bundles required `BlindRotationKey` and `NtruLweKeySwitchingKey`. `CircuitBootstrapServerKey::new(server_key, circuit_key)` adds required CBS material; both `into_parts()` methods move buffers without copying arrays. Independent BR, return-KS and CBS generation remain available, with `BlindRotationMethod` selecting classic/sparse. Component generation may repeat secret conversion; paired generation shares the accepted transform.

`context.try_generate_circuit_bootstrap_keys(rng)` returns `(ClientKey, CircuitBootstrapServerKey)`, sharing the accepted accumulator transform/inverse across BR/CBS and generating required return KS. Complete bundles must satisfy the return-q secret-magnitude bound. `server.bootstrap_resources(&context)` allocates only BR scratch; CBS/one-hot evaluation allocates no return buffers. Borrow `server.server_key()` for PBS and `server.circuit_bootstrap_key()` for CBS.

`Evaluator::try_from_parts(context, parameters.key_switching(), br, return_key)` binds ordinary PBS. Standalone CBS/one-hot first prepares common BR/external-product resources with `context.bootstrap_resources(br)?`, then operation state with `try_new(&resources, circuit_key, &input_codec)`. No return key is needed; the CBS example uses the grouped workflow above. Independent material must use the same actual secrets and transform representation. Shape and modulus checks do not prove identity.

`server_key.blind_rotation_key().classic_controls()` returns a borrowed `ClassicControls` view, or `None` for sparse material. Its `initializer()` lifts public polynomials; coordinate zero uses NLEV bits and later coordinates use NGSW bits, with positive/negative pairs for ternary secrets. CBS and one-hot use the selected classic or sparse BR with independent trace/scheme-switch material. MVB needs no additional lifting or CBS material. `CircuitBootstrapServerKey::circuit_bootstrap_key()` directly borrows required CBS material.

`KeyGenerator::try_generate_public_lift_key(accumulator_secret, &nlev_parameters, rng)` generates independent NLEV[1] for high-precision tables that need it. The parameters select its basis and row noise; keep the ciphertext and parameters together for lookup binding. Sparse PBS/CBS/one-hot and tables without a public lift require no such material.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and scalar/batch return buffers. CBS/one-hot retain only their LUT and projection buffers; pass `pbs.bootstrap_resources_mut()` as the final execution argument. Construct factorized MVB with `FactorizedEvaluator::new(&pbs)` and pass `&mut pbs` as its final execution argument. Ordinary PBS resumes as soon as the borrow ends, without converting or recovering evaluators. Online `_to` calls reuse all buffers. Operation state checks the same context before writes. Classic/sparse resource instances can share it when their actual input and accumulator secrets match; context identity does not establish secret identity.

`Resources` groups borrowed context/evaluation material with owned reusable buffers; it does not own or copy the keys. `Workspace` denotes buffer storage and shape metadata, including lower-level BR/EP scratch. `Evaluator` executes a specific workflow using owned or briefly borrowed resources. Keep the context/key owners alive; serial operations can share one mutable resource instance, while concurrent requests need separate mutable resources. The context owns the NTT table; key views and products must preserve its representation.

For CBS/one-hot alone, keep standalone `BootstrapResources` without return buffers. To add PBS later, `Evaluator::try_from_resources(resources, parameters.key_switching(), return_key)` takes common resources and allocates return buffers. `try_rebind_return_key` changes compatible return material without reallocation; success discards pending samples, while failure preserves the old binding. Resource ownership does not establish actual secret identity.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. The program borrows that context; outputs use unsigned Scaled encoding. `factorized_pbs_codecs` prepares the Q LUT encoding and q return decoding from the same output message modulus; budget the difference between `(q/Q)*round(Q/t_out)` and `round(q/t_out)`, plus return noise.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Classic binary/ternary and sparse fixed-weight binary keys share the lift and blind rotation across outputs. Each factor product is independently converted from Q to q and extracted; small tiles reuse the PBS workspace for batched LWE key switching. The coefficient polynomial is reused after each extraction, without retaining every product. Factor norms amplify initialization and BR noise; return-KS noise is added afterward.

Run the [17-threshold example](examples/ntru_ntt_mvb_thresholds.rs) with `--example ntru_ntt_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

This backend re-exports the family's [shared coefficient key](../primus_tfhe_ntru/README.md#sparse-coefficient-keys), `SparseNtruBootstrappingKey<T>`. Generation, transforms and bucket aggregation remain backend-specific.

Ordinary PBS uses `context.try_generate_keys(rng)` and `context.evaluator(&server)`; an existing client uses `context.try_generate_server_key(&client, rng)`. CBS uses `try_generate_circuit_bootstrap_keys` / `try_generate_circuit_bootstrap_server_key`, returning `CircuitBootstrapServerKey`. `try_with_circuit_bootstrap(gadget)` adds CBS capability to the context; ordinary factories still return a BR/KS `ServerKey`. Explicit advanced factories take KS and algorithm choices, plus the required gadgets for CBS factories.

Select a fixed-weight binary external-LWE distribution and choose sparse generation explicitly; the distribution alone does not select the algorithm. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let config = experimental::SPARSE_PBS_U64;
let context = TfheContext::<_, Table, _>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(&mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Ordinary/interleaved PBS use the same evaluator; factorized MVB borrows it per call. `try_generate_circuit_bootstrap_keys` generates CBS/one-hot material while sharing the accumulator transform with BR. For ring-only operations, construct the context from a sparse `CbsConfig` and call `try_generate_circuit_bootstrap_keys`. `server.server_key().blind_rotation_key().sparse_blind_rotation_key()` exposes selectors.

## Optional circuit bootstrapping

`br.circuit_bootstrap_codecs(t_in, t_ring)?` returns Rounded input and Scaled candidate ring codecs with the correct q/Q and independent plaintext domains. Pass the former to the input encryptor and CBS evaluator, and the latter to `accumulator_client`; it does not describe the CBS gadget output.

Compile a custom integer function with `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_lookup_table_slice`. Bind the resulting `CircuitBootstrapLookupTable` with `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?`; `try_new` keeps the identity default. Output lanes use `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other ring integers require the external-product noise contract. The ordinary CBS examples use t_in=8 and show both branches of this predicate.

Use `context.try_generate_circuit_bootstrap_keys(&mut rng)` to generate a BR/KS `ServerKey` plus required CBS key. Borrow `server.server_key()` for the PBS evaluator and `server.circuit_bootstrap_key()` for the CBS evaluator, sharing the same BR/KS. `allocate_output`, `circuit_bootstrap_to` and `cmux_to` lend common resources to each operation; the [CBS → CMUX example](examples/ntru_ntt_circuit_bootstrap.rs) shows the full consumption chain.

The output is `NttNgswCiphertext` under `f_acc`. The circuit key binds the complete output basis; `try_new(&resources, circuit_key, &input_codec)` obtains parameters from that key. NTT trace normalization requires odd Q below `2^(T::BITS-1)`.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples).

## One-hot CBS

The [one-hot example](examples/ntru_ntt_one_hot.rs) generates four selectors and uses δ₂, selected by `TARGET=2`, in a CMux. Change `TARGET` for another branch. Bind `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)`, allocate once and reuse `_to` calls.

See the [family one-hot contract](../primus_tfhe_ntru/README.md#one-hot-cbs) for full/nonzero output APIs, layout and input guards. NLEV output contains coefficients at Q; use `write_ntt_form` before a public-polynomial external product. NGSW is already in NTT representation. Inputs, keys and candidates must satisfy this page's transform contract.

`ngsw_selector_len()` returns the length of one transformed NGSW selector; `ngsw_batch_len()` returns the complete batch length, including branch zero. Both count NTT ring elements, not bytes.

For consumption, borrow a `NttNgswSelectors` with `cbs.ngsw_selectors(&output)` or
`cbs.nonzero_ngsw_selectors(&output)`. Use `selector(r)` to access δᵣ, and
`iter()` for `(r, control)` pairs. Full batches cover `0..M`; compact batches
cover `1..M` and return `None` for `selector(0)`. These views check the exact
batch length and borrow the existing buffer without copying or allocating.
`cbs.nlev_selectors(&output)` similarly borrows a complete coefficient NLEV batch.

After obtaining one control, call `cbs.cmux_to(&control, &lhs, &rhs, &mut selected, &mut resources)`: delta_r=0 selects lhs and delta_r=1 selects rhs. `cbs.external_product_to(&control, &input, &mut output, &mut resources)` multiplies the selector by a ring ciphertext. Both calls reuse the bound output basis, transform environment and shared scratch; candidates still require the CMux/product secret, modulus, encoding and noise contracts. Full and nonzero batches use the same consumption interface, with one selector per call.

For a consumer that immediately processes each result, `new_sparse_pair_workspace(&resources)` allocates one additional input state and `with_sparse_pair` blind-rotates two sparse inputs together. Its callback receives index 0 then 1 and a scoped `OneHotProjection`: `project_to` writes full NLEV and/or nonzero NGSW into reusable buffers. Complete consumption within each callback; the high-precision LUT evaluator uses this path automatically.

## High-precision lookup

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) composes one-hot CBS with table selection, aggregated negative rotations and the independent LWE return. It supports uniform input/output chunk widths and independently chosen counts. For lower-level composition, `server_key.blind_rotation_key().classic_controls().unwrap().initializer()` exposes the classic NLEV[1] under the context's BR basis; `key_switching_key()` exposes the Q→q, f→s return key.

A complete chunk-encryption and lookup workflow is in [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs).

For custom returns, bind `LweReturnEvaluator::new(server.key_switching_key().unwrap(),
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
