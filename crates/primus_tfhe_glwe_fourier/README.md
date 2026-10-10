# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

GLWE-based TFHE with the native torus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [GLWE parameter and key domains](../primus_tfhe_glwe/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Experimental paired parameters

```rust
use primus_tfhe_glwe_fourier::{experimental, TfheContext};
use primus_fft::RustFftTable as Table;

let config = experimental::CLASSIC_PBS_U64;
// The context uses config.messages; change its output_modulus before construction to override the default.
let context = TfheContext::<u64, Table>::try_from_pbs_config(config)?;
```

`PbsConfig` is one complete numerical description, containing BR/KS choices and input/output messages. `CbsConfig` describes ring-output CBS; its gadget output has no ordinary message codec. `experimental` also exports `SPARSE_PBS_U64`, `CLASSIC_MANY_LUT_U64`, `CLASSIC_THRESHOLD_MVB_U64`, `CLASSIC_CBS_U64` and `SPARSE_CBS_U64`. The context retains the selected algorithm, KS, messages and optional CBS state; default keygen does not receive them again. Configs are `Copy`, so field overrides and struct-update syntax work without preparing samplers first.

These u64 constants are arithmetic examples, with unassessed security and failure probability. See the [family configs](../primus_tfhe_glwe/README.md#experimental-paired-parameters) for composition, independent message overrides and numerical contracts. Every example starts from the matching operation config; advanced explicit composition remains available through the family constructors. Prepared `PbsParameters` remain reusable with compatible encodings; changing a workload still needs a new error budget.

## Quick start

The examples take input/output plaintext moduli from `config.messages`: `PbsMessageConfig::new(t)` defaults to equal moduli, and `with_output_modulus(t_out)` changes only the output. Use `context.encryptor(external_secret)` for Rounded input, `pbs_decryptor` for ordinary PBS/ManyLUT, and `mvb_decryptor` for Scaled MVB output. Clients need no LUT or explicit codec. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
```

The [basic example](examples/fourier_basic.rs) shows config → context → paired keys → clients → LUT → reused evaluator and buffers. It forms `z=2*x+y`, computes `score=min(z,6)`, then feeds that ciphertext into a second PBS for `price=2*score+[score>=4]`. Input and output both use `t=32`. `context.pbs_lookup_table_compiler()?.compile_fn(function)` prepares the public LUT; public-key clients use `context.public_encryptor(&public)`. Input encryption uses the configured `messages.input_modulus`. Set `config.messages = PbsMessageConfig::new(t_in).with_output_modulus(t_out)` before context creation for distinct input and output domains. Advanced same-key programs reuse prepared codecs through the family parameter factories; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

Examples use `Word = u64` and the operation config listed below. Dimensions, modulus representation, secret distributions, noise and decompositions live in `experimental`; each `main` shows only preparation, the public function, clients and evaluation. CBS uses the prepared `CbsParameters` and independently chooses the candidate ring-message domain. The Fourier examples select RustFFT; switch the `Table` import and the example target’s `required-features` to use TFHE-FFT with `--no-default-features --features tfhe-fft`. Explicit u32/u64 parameter composition remains available; see the [family configs](../primus_tfhe_glwe/README.md#experimental-paired-parameters) and [parameter guide](../../guides/development/tfhe-parameters.md).

Comments identify client and server stages. Basic and sparse run the same two-PBS scoring pipeline for four `(x,y)` requests in `0..4`. Intermediate values stay in the padded `0..16` input range; feedback also needs a noise budget for this workload. ManyLUT computes `grade=x/2` and `flag=[x>=5]` in one blind rotation, then combines their ciphertexts as `code=2*grade+flag`. It uses `t_in=16`, `t_out=8` and returns only the final code; those outputs cannot be fed directly into the differently encoded input PBS. Keys, LUTs, evaluators and buffers are prepared once and reused. See [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

The [Boolean example](examples/fourier_boolean.rs) evaluates `admin OR (member AND NOT revoked)`, using `CLASSIC_PBS_U64` with `config.messages = PbsMessageConfig::new(4)`. It encrypts three client inputs and decrypts only the final decision. Run it with:

```sh
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_boolean
```

| Operation | Config in `experimental` | Complete example |
| --- | --- | --- |
| Classic PBS | `CLASSIC_PBS_U64` | [basic](examples/fourier_basic.rs) |
| Boolean access circuit | `CLASSIC_PBS_U64` with messages 4→4 | [boolean](examples/fourier_boolean.rs) |
| Sparse PBS | `SPARSE_PBS_U64` | [sparse](examples/fourier_sparse.rs) |
| Interleaved ManyLUT with a separate output message modulus | `CLASSIC_MANY_LUT_U64` | [many_lut](examples/fourier_many_lut.rs) |
| Classic CBS → CMux → ring addition | `CLASSIC_CBS_U64` | [circuit_bootstrap](examples/fourier_circuit_bootstrap.rs) |
| Sparse CBS → CMux → ring addition | `SPARSE_CBS_U64` | [sparse_circuit_bootstrap](examples/fourier_sparse_circuit_bootstrap.rs) |
| Factorized MVB | `CLASSIC_THRESHOLD_MVB_U64` | [thresholds](examples/fourier_mvb_thresholds.rs) |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface.

External LWE factories take `client_key.external_lwe_secret_key()`: `encryptor` / `pbs_decryptor` / `mvb_decryptor` and the Boolean variants derive their codecs from the configured messages. Boolean gates require both input/output t=4. Ring clients use `accumulator_client(client_key.glwe_secret_key(), t_ring)` with an independent candidate message modulus. Complete `ClientKey` bundles are used for server-key generation; selecting a role copies no secret buffers.

## Parameters and representation

`PbsParameters::try_from_config(pbs_config)` retains required KS, the algorithm and messages; `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` adds CBS gadgets and input encoding. Context construction retains one common parameter owner and transform table. `parameters()` always exposes the complete PBS domain; `cbs_parameters()` queries additional CBS capability. PBS and CBS share required KS, which downstream consumers can use to return ring/gadget computations to LWE.

The Fourier ring supports only `NativeModulus`; `PowOf2Modulus` rings are unsupported.

Move prepared parameters into `TfheContext::from_parameters(parameters)` or `from_cbs_parameters(parameters)`; `try_new(parameters, table)` accepts an existing table. Default preparation does not copy the common sampler. CBS and PBS retain the ring sampler's existing Arc without a separate BR parameter owner. `PbsParameters::try_from_config(pbs)` prepares common state; `CbsParameters::try_from_config(pbs, gadget)` or `try_with_config(parameters, gadget)` adds CBS. The latter moves prepared state; selector messages come from the PBS parameters.

Both `RustFftTable` and `TfheFftTable` support u32/u64. Keys, values and evaluators must use the same FFT table instance; equal length does not prove representation identity.

Choose `PbsOrder::BootstrapKeyswitch` for external dimension n or `KeyswitchBootstrap` for dimension dN. Use `context.allocate_lwe_ciphertext()` to allocate the selected layout. The basic example selects binary secrets and `BootstrapKeyswitch`; MVB examples use `KeyswitchBootstrap`.

## Reusing evaluators

Ordinary/interleaved `Evaluator` owns common `BootstrapResources` and its return stage. Default `CbsEvaluator` combines the CBS program, projection buffers and required input/BR resources. Independent `CircuitBootstrapEvaluator` briefly borrows `pbs.bootstrap_resources_mut()` per call. MVB uses `context.mvb_evaluator(&server_key)` and owns its PBS state; online calls need only the input, program and outputs. Advanced bindings can move a prepared PBS evaluator into `FactorizedEvaluator::new(pbs)` without copying keys or buffers.

`Resources` groups borrowed context/evaluation material with owned reusable buffers; it does not own or copy the keys. `Workspace` denotes buffer storage and shape metadata, including lower-level BR/EP scratch. `Evaluator` executes a specific workflow using owned or briefly borrowed resources. Keep the context/key owners alive; serial operations can share one mutable resource instance, while concurrent requests need separate mutable resources. The resources own the FFT engine, which borrows the context’s table; switching resource owners must preserve that table identity.

`ServerKey` remains the convenient complete PBS bundle. Advanced workflows can own `BlindRotationKey`, the ring KS key and `CircuitBootstrapKey` separately; `ServerKey::new(br, ks)` / `into_parts` move BR/KS, while `CircuitBootstrapServerKey::new(server_key, circuit_key)` / `into_parts` move the CBS composition without copying ciphertext arrays. `KeyGenerator::try_generate_blind_rotation_key(&client, config, rng)` uses `BlindRotationMethod` to select classic or sparse BR, without generating return or CBS material; `try_generate_glwe_key_switching_key` generates ring KS separately; `try_generate_circuit_bootstrap_key(accumulator_secret, cbs_parameters.gadget().clone(), rng)` needs only the accumulator secret. Separate generation may transform secrets again; paired generation retains its existing transform reuse.

`context.try_generate_circuit_bootstrap_keys(rng)` returns `(ClientKey, CircuitBootstrapServerKey)`, containing a required BR/KS `ServerKey` and CBS key. `server.bootstrap_resources(&context)` prepares only BR and any input-KS workspace; BR→KS CBS allocates no return scratch. Use `context.circuit_bootstrap_evaluator(&server)` for identity CBS; downstream LWE returns reuse KS in `server.server_key()`. See [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

The default CBS workflow takes the complete server key and prepares its resources:

```rust,ignore
let mut cbs = context.circuit_bootstrap_evaluator(&server)?;
```

The factory selects input KS for KS→BR; BR→KS allocates no return scratch. `cbs.into_parts()` moves out operation state and common resources for subsequent PBS reuse. With an existing PBS evaluator, use the low-level constructor below and borrow its resources per call. `operation` is the configured `context.cbs_parameters().unwrap()`; `try_new` instead uses the circuit key's output parameters and accepts an explicit input encoding.

```rust,ignore
let mut cbs = circuit_bootstrap::CircuitBootstrapEvaluator::try_with_parameters(
    pbs.bootstrap_resources(), operation.gadget(), circuit_key, operation.input_codec(),
)?;
```

For independently generated material, use `context.bootstrap_resources(br, input_ks)`: BR→KS accepts `None`, while KS→BR requires `Some((ks_parameters, ks))`. Standalone CBS does not require an ordinary return key. `Evaluator::try_from_parts(context, parameters.glwe_key_switching(), br, ks)` binds complete PBS/ManyLUT. Both entries support classic/sparse. Layout, basis and modulus checks do not establish actual secret or transform identity.

`Evaluator::try_from_resources(resources, parameters.glwe_key_switching(), ks)` assembles ordinary PBS: only BR→KS allocates a missing output stage. CBS accepts any resource instance from the same context, checked before writes. MVB retains the context and key binding of its owned PBS evaluator. Callers must retain paired secrets, and mutable resource borrows must preserve the owning PBS binding and FFT table instance.

## Fixed-scale factorized MVB

Compile with `context.compile_mvb_fn(domain_len, output_count, function)` and create `context.mvb_evaluator(&server_key)`. Call `mvb.apply_lookup_table_to(input.as_view(), &program, &mut outputs)` to reuse the owned workspace. The input uses the same `encryptor`; decode the unsigned Scaled output with `context.mvb_decryptor(external_secret)`. Both use the configured message domains. For another output domain with the same keys, reuse `parameters.factorized_pbs_codecs(messages)` for compilation and `parameters.decryptor_with_codec`; compiling a program does not change an existing decoder. The program remains bound to this context. LUT and returned LWE ciphertexts share the same modulus. Advanced composition uses `parameters.compile_factorized_lookup_table_fn(&codecs, ...)` followed by `FourierFactorizedLookupTable::new(&context, raw)`; same-key message overrides use `context.compile_mvb_fn_with_messages`.

The actual scale `round(2^BITS/t_out)` must be even (`t_out=10` works for u32/u64). Odd scales return `LookupTableError::OddFactorizationScale`. Factors are transformed as signed integers without torus scaling; budget their amplification and FFT error.

Both classic and sparse keys work in both PBS orders. BR→KS key-switches each factor product; KS→BR switches the input once. Extra workspace is independent of output count.

Run the [17-threshold example](examples/fourier_mvb_thresholds.rs) with `--example fourier_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

Ordinary PBS uses `context.try_generate_keys(rng)` and `context.evaluator(&server)`; an existing client uses `context.try_generate_server_key(&client, rng)`. CBS uses `try_generate_circuit_bootstrap_keys` / `try_generate_circuit_bootstrap_server_key`, returning `CircuitBootstrapServerKey`. `try_with_circuit_bootstrap(gadget)` adds CBS capability to the context; ordinary factories still return a BR/KS `ServerKey`. Complete factories use the retained config; independent BR/KS/CBS components are generated through `KeyGenerator`.

Select a fixed-weight binary small-LWE distribution and choose sparse generation explicitly; the distribution alone does not select the algorithm. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let config = experimental::SPARSE_PBS_U64;
let context = TfheContext::<_, Table>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(&mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Both orders support ordinary/interleaved PBS, MVB and CBS. `try_generate_circuit_bootstrap_keys` generates CBS material alongside one shared BR/KS bundle; `ServerKey::blind_rotation_key()` exposes the classic/sparse variant.

## Circuit bootstrapping

The Context retains Rounded input encoding and CBS gadgets. Encrypt with `context.encryptor(external_secret)?`; `context.accumulator_client(client.glwe_secret_key(), t_ring)?` independently prepares Scaled ring clients at Q. Candidate t_ring may differ from input or ordinary PBS output message moduli. CBS output uses gadget scales.

Compile an integer function with `context.compile_cbs_fn(|m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_cbs_slice`; `compile_cbs_identity()` supplies identity. `context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` moves in the program and combines reusable resources; `context.circuit_bootstrap_evaluator(&server)?` prepares identity CBS. Binding checks input message intervals, q/Q, basis and key layouts; equal input counts do not establish equal encodings. Output lanes contain `g_j * F(m) mod Q`; CMux requires bit-valued F throughout the domain, while other ring integers require the external-product noise contract.

`context.try_generate_circuit_bootstrap_keys(&mut rng)` generates a complete `CircuitBootstrapServerKey`. Default `CbsEvaluator` calls `circuit_bootstrap_to(input.as_view(), control.as_mut_view())` and `cmux_to(control.as_view(), lhs.as_view(), rhs.as_view(), selected.as_mut_view())` need no separate resources argument. Ordinary PBS borrows `server.server_key()`.

The [CBS → CMux → addition example](examples/fourier_circuit_bootstrap.rs) computes `[m>=2]` and selects encrypted fee plan A or B, then adds encrypted extra fees. The client repeats `A=[1,0,2,1]`, `B=[3,1,0,2]` and `extra=[0,1,1,0]` across all N coefficients, using Scaled `t_ring=8`. These are coefficient messages, not independent SIMD slots. Four requests cover m=0,1,2,3; the client checks every coefficient and prints only a short prefix.

Use low-level `CircuitBootstrapEvaluator` for per-call resource borrowing, other input encodings or GLWE output-basis overrides. Actual secret/transform identity, candidates' common encoding and noise margins remain caller contracts. See the [shared CBS contract](../primus_tfhe/README.md#cbs-output-and-consumption).

## Lower-level composition

Recommended workflow types remain root imports. Import advanced types by role: common resources through `bootstrap::BootstrapResources`, independent BR material through `key::BlindRotationKey`, CBS keys/gadget parameters and per-call borrowing evaluators through `circuit_bootstrap`, and sparse material/workspaces through `sparse`. Explicit codec bundles come from `primus_tfhe`. Raw classic BSKs and BR workspaces live in `bootstrapping_key` and `blind_rotation`.

The [shared coefficient key](../primus_tfhe_glwe/README.md#sparse-coefficient-keys) is re-exported as `sparse::SparseGlweBootstrappingKey<T, NativeModulus<T>>`. Raw sparse BR uses `workspace.blind_rotate_lookup_table_to(&key, input, lut, output, &mut fft)`; the workspace owns scratch and borrows the key only for the call.

## Benchmarks

```sh
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
```

Crate-local `benches/` provides `pbs`, `many_lut`, `mvb`, and `cbs`.

Each iteration measures one complete server request; setup and decryption checks are untimed. PBS covers u32/u64; other operations use u64. See the [benchmark guide](../../guides/development/testing.md#tfhe-benchmarks) for parameters, timing boundaries and a four-backend command. Fourier defaults to RustFFT; use `--no-default-features --features tfhe-fft` for TFHE-FFT alone, or `--features tfhe-fft` to measure both engines separately.

## Further reading

This crate enables `fourier` on its normal dependencies; no extra backend flag is needed, and standalone use does not pull in NTT. RustFFT is enabled by default, so examples and benchmarks run without extra feature flags. Use `--no-default-features --features tfhe-fft` for TFHE-FFT alone, or `--features tfhe-fft` to enable both engines. `--no-default-features` retains the generic API without a concrete engine. Optional `simd` enables nightly SIMD arithmetic in dependencies and does not change the engine selection.

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Performance notes](../../guides/performance/README.md)
