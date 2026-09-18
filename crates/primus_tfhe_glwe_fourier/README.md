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
`KeyswitchBootstrap`, they have dimension `kN`. The example prints and checks these
dimensions (4 and 256). Both inputs and outputs follow the chosen external key.
All fixture dimensions, noise and decomposition choices are functional examples,
not production security or failure-probability recommendations.

## Context and reuse

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
returns the underlying FFT error. Use `try_new(parameters, table)` to inject an existing table.

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

Low-level `FourierGlweBootstrappingKey<T, LM>` retains the input modulus type `LM`, independently
of the accumulator modulus. Key generation prepares the ordinary-PBS
quantizer. ManyLUT prepares the conversion for the rotation step before coefficient
processing; the high-level context keeps its existing parameter restrictions.

## Binary and ternary small secrets

Select `SecretKeyDistr::UniformTernary` or another ternary family in `LweParameters`;
the key-generation and evaluator APIs are unchanged. The basic example uses this
configuration. Both PBS orders, ordinary/interleaved LUTs and public-key inputs work.
Binary keeps one GGSW per coordinate; ternary stores independently encrypted
`(positive, negative)` controls and combines them for one external product per coordinate.

At the low level, `FourierGlweBlindRotationContext::new(&key)` allocates scratch
for the key's control family; `resize` preserves that family. `iter_binary_controls` /
`iter_ternary_controls` expose single controls or pairs, returning `None` for the other
family. Server-key compatibility includes the small-secret distribution. Dispatch
occurs outside the rotation loop and online scratch is reused; fusion adds BSK and
temporary GGSW storage.

## Circuit bootstrapping

Classic CBS supports binary/ternary small secrets, both PBS orders and both FFT
engines. It produces Fourier GGSW under the accumulator secret. Sparse CBS is
not supported.

Use `CircuitBootstrapParameters::try_from_config(tfhe, config)` with a
`CircuitBootstrapConfig` naming output/trace/scheme-switch decompositions and independent
trace/SS noise. The native modulus, ring layout and secret distribution come from the
accumulator; construction checks padded gadget-level capacity and binds the input
plaintext modulus. `try_new` also accepts existing bases and GLev/GGSW parameters.
The scheme-switch key binds the output layout; another output basis with the same
level count can reuse the key.

Generate ordinary PBS and CBS keys from the same `ClientKey` using a reusable
`KeyGenerator`: `try_generate_server_key`, then `try_generate_circuit_bootstrap_key`.
`TfheContext::generate_circuit_bootstrap_key` is the convenience entry point.
Both keys must use the same client secrets and the generating context's FFT table;
layout/basis checks cannot establish identity. Ordinary `ServerKey` carries no CBS material.

Create the evaluator with `context.circuit_bootstrap_evaluator(&server, &parameters, &circuit_key)`.
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

The example and benchmark share an `n=728, N=1024`, three-level binary profile.
See the [CBS analysis](../../docs/tfhe-cbs.md) for error sources, observed margin at
the smallest gadget scale, key/workspace sizes and timings. This profile is not a
production parameter recommendation; sparse CBS remains unsupported.

## Validation and performance

```sh
cargo test -p primus_tfhe_glwe_fourier
cargo clippy -p primus_tfhe_glwe_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_fourier --features simd
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
cargo bench -p primus_tfhe_glwe_fourier --bench ternary_pbs
cargo bench -p primus_tfhe_glwe_fourier --bench circuit_bootstrap
```

`pbs` reuses output buffers and covers both orders, 3/4-output ManyLUT versus
separate PBS calls, and Boolean AND/MUX. BR and key-switch stages locate costs;
coefficient extraction is benchmarked in `primus_lattice`. Fourier PBS benchmarks cover both RustFFT and TfheFFT.

`ternary_pbs` compares complete binary, fused ternary and two-CMUX PBS at
`n=728, N=1024` with BR→KS, and separately times BSK+KSK generation. Timing and
key/workspace measurements are recorded in the [T3 profile and results](../../docs/tfhe-ternary.md#t3完整-glwe-接入与验收已完成).

`circuit_bootstrap` measures complete CBS in both orders and both FFT engines,
plus BR, three-level projection and scheme switching once per engine. Setup and
phase checks are outside timing; all online buffers are reused.
