# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over the native torus. Supports both PBS orders, ManyLUT,
Boolean gates and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

## Run the complete example

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

The [example source](examples/fourier_basic.rs) runs both orders with the same
workflow: parameters → context → paired keys → public-key encryptor/client decryptor
→ compiled LUT → reusable evaluator/output. It demonstrates single PBS, two-output
ManyLUT, client `encrypt_padded_to`, Boolean gates, NOT and MUX.

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

Compile ordinary LUTs with `compile_lookup_table_fn` / `compile_lookup_table_slice`,
or their `compile_interleaved_lookup_table_*` counterparts. Use unsigned padded input and
account for ManyLUT's coarser rotation resolution. The evaluator holds mutable
scratch; create it once and reuse `apply_lookup_table_to` / `apply_interleaved_lookup_table_to`.
These calls validate all output dimensions before writing.

Use `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` for `t=4`.
The adapter handles the internal modulus-8 LUT scale. Use `evaluate_binary_to`,
`not_to` and `mux_to` for repeated Boolean evaluation.

Low-level `FourierGlweBootstrappingKey<T, LM>` retains the input modulus type `LM`, independently
of the accumulator modulus. Key generation prepares the ordinary-PBS
quantizer. ManyLUT prepares the stride-dependent conversion before coefficient
processing; the high-level context keeps its existing parameter restrictions.

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
```

`pbs` reuses output buffers and covers both orders, 3/4-output ManyLUT versus
separate PBS calls, and Boolean AND/MUX. BR and key-switch stages locate costs;
coefficient extraction is benchmarked in `primus_lattice`. Fourier PBS benchmarks cover both RustFFT and TfheFFT.
