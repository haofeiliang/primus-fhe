# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over the native torus. Supports both PBS orders, ManyLUT,
Boolean gates, classic CBS and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

`Encryptor`, `Decryptor`, `TfheConfig` and `TfheParameters` specialize the shared types to
`NativeModulus`; `ClientKey`, `EncryptionKey` and `PbsOrder` are re-exported directly.

## Run the complete example

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

The [example source](examples/fourier_basic.rs) runs both orders with the same
workflow: parameters → context → paired keys → public-key encryptor/client decryptor
→ compiled LUT → reusable evaluator/output. It demonstrates single PBS, two-output
ManyLUT with `t_in=4 → t_out=8`, client `encrypt_padded_to`, Boolean gates, NOT and MUX.

For `BootstrapKeyswitch`, external ciphertexts have dimension `n`; for
`KeyswitchBootstrap`, they have dimension `kN`. Both inputs and outputs follow
the chosen external key. Example dimensions, noise and decomposition choices are
for functional demonstration, not production security or failure-probability recommendations.

## Context and reuse

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves FFT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext::try_new` checks the FFT length. Every transformed key, value and
evaluator must use the same FFT table instance; matching lengths do not establish
representation identity. The example uses `RustFftTable`; `TfheFftTable` is also
supported. Create FFT engines and evaluators from the same context.

Compile front-half LUTs through `context.parameters()` with
`compile_lookup_table_fn` / `compile_lookup_table_slice`,
or their `compile_interleaved_lookup_table_*` counterparts, passing an output
`RoundedCodec` first. Decode a different output scale using `decrypt_phase` and
that codec. Use unsigned padded input and
account for ManyLUT's coarser rotation resolution. The evaluator holds mutable
scratch; create it once and reuse `apply_lookup_table_to` / `apply_interleaved_lookup_table_to`.
These calls validate all output dimensions before writing.

For odd full domains, use the parameters' `compile_odd_full_domain_lookup_table_fn`
/ `_slice` with ordinary `encrypt` and the existing single-output evaluator.
See the [shared contract](../primus_tfhe/README.md#odd-full-domain-pbs).

Use `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` for `t=4`.
These APIs use ordinary `LweCiphertext` buffers with Boolean 0/1 encoding modulo 4.
The encryptor accepts secret or public keys and supports `encrypt_to`.
The evaluator handles the internal modulus-8 LUT scale. Use `evaluate_binary_to`,
`not_to` and `mux_to` for repeated Boolean evaluation.

## Binary and ternary small secrets

Select `SecretKeyDistr::UniformTernary` or another ternary family in `LweParameters`;
the key-generation and evaluator APIs are unchanged. The basic example uses this
configuration. Both PBS orders, ordinary/interleaved LUTs and public-key inputs work.
Ternary keys require more key and workspace storage than binary keys; see the
[ternary design and costs](../../docs/tfhe-ternary.md).

## Circuit bootstrapping

Classic CBS supports binary/ternary small secrets, both PBS orders and both FFT
engines. It produces Fourier GGSW under the accumulator secret. Sparse CBS is
not supported.

Choose a `CircuitBootstrapConfig` naming output/trace/scheme-switch decompositions and independent
trace/SS noise. The native modulus, ring layout and secret distribution come from the
accumulator; construction checks padded gadget-level capacity and binds the input
plaintext modulus. `CircuitBootstrapParameters::try_new` also accepts existing bases and GLev/GGSW parameters.
The scheme-switch key binds the output layout; another output basis with the same
level count can reuse the key.

Generate a paired client/server key with
`context.try_generate_keys(Some(config), &mut rng)`.
The `ServerKey` owns the CBS parameters and trace/scheme-switch keys, generated with
its ordinary PBS material from the same secrets and transform table. Use
`None` for PBS only: no CBS key material or CBS workspace is allocated.
Both `context.evaluator(&server)` and `context.circuit_bootstrap_evaluator(&server)`
use that server key; the latter returns `MissingCircuitBootstrapKey` when CBS is absent.
Only the selected evaluator allocates its workspace. Key generation returns `KeyGenerationError`.

For advanced composition, `try_generate_circuit_bootstrap_key` owns its prepared parameters,
and `CircuitBootstrapEvaluator::try_from_parts` accepts explicit parameters and material.
The caller must pair secrets and use the generating transform representation; layout checks
cannot verify identity. Bound parameters are available via
`server.circuit_bootstrap_key().unwrap().parameters()`.

`circuit_bootstrap_to` writes into an existing `FourierGgsw` containing
`parameters.output_size().fourier_ggsw_len()` complex values, without online allocations.
`circuit_bootstrap` allocates the output. The pipeline reuses the ordinary evaluator's
input KS/BR workspace, then projects each gadget level and performs scheme switching.
Input uses unsigned rounded LWE encoding in `0..ceil(t/2)`; its noise must fit the
coarser ManyLUT intervals. CMUX requires input 0 or 1. The result remains under the
accumulator secret with gadget scales; it does not pass through the ordinary PBS output KS.

Native reverse trace retains the low-level per-stage integer halving. Its rounding,
trace key switching, scheme-switch decomposition and FFT precision require a CBS
error budget; these parameter checks do not validate noise or security.

Run the [CBS→CMUX example](examples/circuit_bootstrap.rs) to select between two
encrypted GLWE messages using an LWE bit, with reusable outputs in both orders:

```sh
cargo run --release -p primus_tfhe_glwe_fourier --example circuit_bootstrap
```

See the [CBS error budget and costs](../../docs/tfhe-cbs.md) for parameter-selection
considerations. Example parameters are not production recommendations.

Use `evaluator.allocate_output()` to allocate the raw CBS control, then
`evaluator.cmux_to(control, lhs, rhs, output)` or `external_product_to(control, input, output)`.
`context.accumulator_client(&client)` binds ring encryption/decryption and conversion scratch.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/circuit_bootstrap.rs).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Further reading

[Implementation and developer validation](../../docs/tfhe.md) · [Benchmarks and measurements](../../docs/benchmarks/tfhe.md)
