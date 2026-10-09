# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Experimental paired parameters

```rust
use primus_tfhe_glwe_ntt::{experimental, TfheContext};
use primus_ntt::U64NttTable as Table;

let config = experimental::CLASSIC_PBS_U64;
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
let parameters = context.parameters();
let br = context.parameters();
// Optional: parameters.messages().with_output_modulus(8) changes only this program's output.
let codecs = br.pbs_codecs(parameters.messages())?;
```

`PbsConfig` is one complete numerical description, containing BR/KS choices and input/output messages. `CbsConfig` describes ring-output CBS; its gadget output has no ordinary message codec. `experimental` also exports `SPARSE_PBS_U64`, `CLASSIC_MANY_LUT_U64`, `CLASSIC_THRESHOLD_MVB_U64`, `CLASSIC_CBS_U64` and `SPARSE_CBS_U64`. The context retains the selected algorithm, KS, messages and optional CBS state; default keygen does not receive them again. Configs are `Copy`, so field overrides and struct-update syntax work without preparing samplers first.

These u64 constants are arithmetic examples, with unassessed security and failure probability. See the [family configs](../primus_tfhe_glwe/README.md#experimental-paired-parameters) for composition, independent message overrides and numerical contracts. Every example starts from the matching operation config; advanced explicit composition remains available through the family constructors. Prepared `PbsParameters` remain reusable with compatible encodings; changing a workload still needs a new error budget.

## Quick start

The basic, sparse, ManyLUT and MVB examples use `PbsMessageConfig`: `new(t)` defaults to equal message moduli, while `with_output_modulus(t_out)` changes only the output. Prepare with `br.pbs_codecs` for ordinary PBS/ManyLUT or `br.factorized_pbs_codecs` for MVB; the returned codecs distinguish input, LUT output and returned output. `context.decryptor(external_secret, codecs.output_codec())?` accepts Rounded or Scaled outputs; use `decrypt()` to obtain the message. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
```

The [basic example](examples/ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `br.lookup_table_compiler(&codecs)?` binds the prepared input/output encodings; `compiler.compile_fn(function)` creates the LUT. Choose a different output message modulus with `PbsMessageConfig::with_output_modulus`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public, codecs.input_codec())`; see the [family guide](../primus_tfhe_glwe/README.md#clients-and-luts).

Examples use `Word = u64` and the operation config listed below. Dimensions, modulus representation, secret distributions, noise and decompositions live in `experimental`; each `main` shows only preparation, the public function, clients and evaluation. CBS uses the prepared `CbsParameters` and independently chooses the candidate ring-message domain. Explicit u32/u64 parameter composition remains available; see the [family configs](../primus_tfhe_glwe/README.md#experimental-paired-parameters) and [parameter guide](../../guides/development/tfhe-parameters.md).

Comments identify client and server stages. Basic and sparse both compute `x % 4` with equal input/output message moduli. The separate ManyLUT example computes `x % 4` and `x / 4`, sets `t_in=16` and `t_out=8`, and decrypts with the output codec. Each example reuses the LUT, evaluator and output buffers for two requests. See [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Config in `experimental` | Complete example |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/ntt_basic.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/ntt_sparse.rs) |
| Interleaved ManyLUT with a separate output message modulus | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/ntt_many_lut.rs) |
| Classic CBS → CMux | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/ntt_circuit_bootstrap.rs) |
| Sparse CBS → CMux | `SPARSE_CBS_U64` | [sparse_circuit_bootstrap](examples/ntt_sparse_circuit_bootstrap.rs) |
| Factorized MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/mvb_thresholds.rs) |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

Client factories take only the relevant secret: pass `client_key.external_lwe_secret_key()` to `encryptor` / `decryptor` and the Boolean variants, or `client_key.glwe_secret_key()` to `accumulator_client`. Complete `ClientKey` bundles are used for server-key generation; no secret buffers are copied to select a role.

## Parameters and representation

`PbsParameters::try_from_config(pbs_config)` retains required KS, the algorithm and messages; `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` adds CBS gadgets and input encoding. Context construction retains one common parameter owner and transform table. `parameters()` always exposes the complete PBS domain; `cbs_parameters()` queries additional CBS capability. PBS and CBS share required KS, which downstream consumers can use to return ring/gadget computations to LWE.

Move prepared parameters into `TfheContext::try_from_parameters(parameters)` or `try_from_cbs_parameters(parameters)`; `try_new(parameters, table)` accepts an existing table. Default preparation does not copy the common sampler. CBS and PBS retain the ring sampler's existing Arc without a separate BR parameter owner. `PbsParameters::try_from_config(pbs)` prepares common state; `CbsParameters::try_from_config(pbs, gadget)` or `try_with_config(parameters, gadget)` adds CBS. The latter moves prepared state; selector messages come from the PBS parameters.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. All transformed keys/values must follow the supplied table's representation. Owning `NttGlweSecretKey` records q; ordinary and evaluation-key generation reject a different key modulus before sampling. Imports use `new(values, size, distribution, modulus)`. Equal q/N does not prove roots/order or secret identity; see the [GLWE key contracts](../primus_glwe/README.md).

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; MVB examples use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and its return stage. CBS owns only LUT/projection state and borrows `pbs.bootstrap_resources_mut()` as the final execution argument. MVB uses `FactorizedEvaluator::new(&pbs)` and takes `&mut pbs` per request. Ordinary PBS resumes when the borrow ends, without evaluator conversion or recovery.

`Resources` groups borrowed context/evaluation material with owned reusable buffers; it does not own or copy the keys. `Workspace` denotes buffer storage and shape metadata, including lower-level BR/EP scratch. `Evaluator` executes a specific workflow using owned or briefly borrowed resources. Keep the context/key owners alive; serial operations can share one mutable resource instance, while concurrent requests need separate mutable resources. The context owns the NTT table; key views and products must preserve its representation.

`ServerKey` remains the convenient complete PBS bundle. Advanced workflows can own `BlindRotationKey`, the ring KS key and `CircuitBootstrapKey` separately; `ServerKey::new(br, ks)` / `into_parts` move BR/KS, while `CircuitBootstrapServerKey::new(server_key, circuit_key)` / `into_parts` move the CBS composition without copying ciphertext arrays. `KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)` uses `BlindRotationMethod` to select classic or sparse BR, without generating return or CBS material; `try_generate_glwe_key_switching_key` generates ring KS separately; `try_generate_circuit_bootstrap_key(accumulator_secret, cbs_parameters.gadget().clone(), rng)` needs only the accumulator secret. Separate generation may transform secrets again; paired generation retains its existing transform reuse.

`context.try_generate_circuit_bootstrap_keys(rng)` returns `(ClientKey, CircuitBootstrapServerKey)`, containing a required BR/KS `ServerKey` and CBS key. `server.bootstrap_resources(&context)` prepares only BR and any input-KS workspace; BR→KS CBS allocates no return scratch. Bind CBS with `server.circuit_bootstrap_key()`; downstream LWE returns reuse KS in `server.server_key()`. See [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

For CBS with an existing `CircuitBootstrapServerKey`, prepare only the required common resources:

```rust,ignore
let mut resources = server.bootstrap_resources(&context)?;
let circuit_key = server.circuit_bootstrap_key();
let mut cbs = context.circuit_bootstrap_evaluator(&resources, circuit_key)?;
```

The factory selects input KS for KS→BR and omits output-KS scratch for BR→KS. Default `context.circuit_bootstrap_evaluator(&resources, circuit_key)` uses the context's input encoding and gadgets; explicit `try_new` uses the circuit key's parameters. If PBS is already prepared, pass `pbs.bootstrap_resources()` instead; subsequent CBS calls borrow `pbs.bootstrap_resources_mut()`.

For independently generated material, use `context.bootstrap_resources(br, input_ks)`: BR→KS accepts `None`, while KS→BR requires `Some((ks_parameters, ks))`. Standalone CBS does not require an ordinary return key. `Evaluator::try_from_parts(context, parameters.glwe_key_switching(), br, ks)` binds complete PBS/ManyLUT. Both entries support classic/sparse. Layout, basis and modulus checks do not establish actual secret or transform identity.

`Evaluator::try_from_resources(resources, parameters.glwe_key_switching(), ks)` assembles ordinary PBS: only BR→KS allocates a missing output stage. `try_rebind_key_switching_key(ks)` reuses the active KS stage's buffers with compatible material; failure leaves its binding intact. CBS/MVB accept any resource instance from the same context, checked before writes. Callers must retain paired secrets, and mutable resource borrows must preserve the owning PBS binding.

## Fixed-scale factorized MVB

Compile through `context.compile_factorized_lookup_table_fn(&codecs, domain_len, output_count, function)` and bind a `FactorizedEvaluator`. Prepare `codecs` with `br.factorized_pbs_codecs(messages)`: Rounded input and Scaled output, both at the context modulus. The program borrows that context; outputs use unsigned Scaled encoding.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/mvb_thresholds.rs) with `--example mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

Ordinary PBS uses `context.try_generate_keys(rng)` and `context.evaluator(&server)`; an existing client uses `context.try_generate_server_key(&client, rng)`. CBS uses `try_generate_circuit_bootstrap_keys` / `try_generate_circuit_bootstrap_server_key`, returning `CircuitBootstrapServerKey`. `try_with_circuit_bootstrap(gadget)` adds CBS capability to the context; ordinary factories still return a BR/KS `ServerKey`. Explicit advanced factories take KS and algorithm choices, plus the required gadgets for CBS factories.

Select a fixed-weight binary small-LWE distribution and choose sparse generation explicitly; the distribution alone does not select the algorithm. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let config = experimental::SPARSE_PBS_U64;
let context = TfheContext::<_, Table>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(&mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Both orders support ordinary/interleaved PBS, MVB and CBS. `try_generate_circuit_bootstrap_keys` generates CBS material alongside one shared BR/KS bundle; `ServerKey::blind_rotation_key()` exposes the classic/sparse variant.

The separate `sparse_paper` benchmark provides the `paper_2026_1730` NAND and padded-function comparisons; ordinary `sparse_pbs` retains the fixed-weight comparison only. `complete_ring_return` includes this backend's ring KS return; `blind_rotation` excludes it. Parameters, measurements and differences from the paper are recorded in the [comparison guide](../../guides/performance/sparse-paper-comparison.md); these are experimental benchmark profiles, not security presets.

The separate `sparse_candidate_r2` IDs use two copies, `2*h` buckets and fewer BR levels for the validated STD128 and three-bit function profiles. The [consumer measurements](../../guides/performance/sparse-consumer-measurements.md) cover PBS, ManyLUT, MVB and feedback. CBS needs its own output basis: a working PBS configuration alone does not ensure usable gadget controls or CMux results.

## Circuit bootstrapping

`br.circuit_bootstrap_codecs(t_in, t_ring)?` returns Rounded input and Scaled candidate ring codecs with the correct q/Q and independent plaintext domains. Pass the former to the input encryptor and CBS evaluator, and the latter to `accumulator_client`; it does not describe the CBS gadget output.

Compile a custom integer function with `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_lookup_table_slice`. Bind the resulting `CircuitBootstrapLookupTable` with `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?`; `try_new` keeps the identity default. Output lanes use `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other ring integers require the external-product noise contract. The ordinary CBS examples use t_in=8 and show both branches of this predicate.

Use `context.try_generate_circuit_bootstrap_keys(&mut rng)` to generate a BR/KS `ServerKey` plus required CBS key. Borrow `server.server_key()` for the PBS evaluator and `server.circuit_bootstrap_key()` for the CBS evaluator, sharing the same BR/KS. `allocate_output`, `circuit_bootstrap_to` and `cmux_to` lend common resources to each operation; the [CBS → CMUX example](examples/ntt_circuit_bootstrap.rs) shows the full consumption chain.

The [sparse CBS example](examples/ntt_sparse_circuit_bootstrap.rs) shows the fixed-weight secret, sparse key generation and CBS configuration together. Both PBS orders work; subsequent CBS and CMux calls are identical.

Input encoding and interleaved capacity are checked at program compilation; binding checks its domain and basis, so compatible programs can reuse the keys with another `t`.

The output is `NttGgsw` under the accumulator secret. The key binds output layout and trace/scheme-switch bases; `try_with_parameters(&resources, parameters, circuit_key, &input_codec)` explicitly selects another output basis with the same level count. For a precompiled program at that basis, use `try_with_parameters_and_lookup_table(&resources, parameters, circuit_key, program)`.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_glwe/README.md#boolean-and-cbs).

## Lower-level composition

The [shared coefficient key](../primus_tfhe_glwe/README.md#sparse-coefficient-keys) is re-exported as `SparseGlweBootstrappingKey<T, BarrettModulus<T>>`. Raw sparse BR uses `workspace.blind_rotate_lookup_table_to(&key, input, lut, output, ntt)`; the workspace owns scratch and borrows the key only for the call.

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and sparse key generation/rotation in `sparse`. Common workflow types remain root imports. Raw GLWE controls and BR workspace are documented in `bootstrapping_key` and `blind_rotation`.

Benchmarks live in [`primus_tfhe_benchmarks`](../../benchmarks/tfhe/README.md#targets). Select the operation target `pbs`, `sparse_pbs`, `mvb`, `cbs` or the explicit `setup` diagnostics. Select `--features glwe-ntt`.

## Further reading

This crate enables `ntt` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in Fourier/FFT. Default features are empty; optional `simd` enables nightly SIMD arithmetic in dependencies.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../../benchmarks/tfhe/BENCHMARKS.md)
