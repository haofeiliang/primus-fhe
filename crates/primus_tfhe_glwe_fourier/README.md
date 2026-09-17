# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over the native torus. Supports both PBS orders, ManyLUT,
Boolean gates and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

`Encryptor`, `Decryptor` and `TfheParameters` specialize the shared types to
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

Fourier GLWE CBS is not implemented. The [NTT backend](../primus_tfhe_glwe_ntt/README.md)
provides the existing GLWE CBS path; its modular normalization guarantees must not
be applied to a future Fourier implementation.

## Validation and performance

```sh
cargo test -p primus_tfhe_glwe_fourier
cargo clippy -p primus_tfhe_glwe_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_fourier --features simd
cargo bench -p primus_tfhe_glwe_fourier --bench pbs
cargo bench -p primus_tfhe_glwe_fourier --bench ternary_pbs
```

`pbs` reuses output buffers and covers both orders, 3/4-output ManyLUT versus
separate PBS calls, and Boolean AND/MUX. BR and key-switch stages locate costs;
coefficient extraction is benchmarked in `primus_lattice`. Fourier PBS benchmarks cover both RustFFT and TfheFFT.

`ternary_pbs` compares complete binary, fused ternary and two-CMUX PBS at
`n=728, N=1024` with BR→KS, and separately times BSK+KSK generation. Timing and
key/workspace measurements are recorded in the [T3 profile and results](../../docs/tfhe-ternary.md#t3完整-glwe-接入与验收已完成).
