# Primus FHE

English | [简体中文](README.zh_CN.md)

Primus FHE is an experimental Rust workspace for fully homomorphic encryption. It provides arithmetic and lattice primitives, LWE/GLWE/NTRU encryption and evaluation operations, and TFHE backends over GLWE and NTRU with NTT and Fourier representations.

> [!WARNING]
> APIs, data representations, algorithms, and crate boundaries are unstable and may change incompatibly without a deprecation period. Example and benchmark parameters are functional fixtures, not certified security or failure-probability recommendations. The project does not claim production readiness.

## Start here

- **Evaluate encrypted functions:** read the [TFHE operation and encoding guide](crates/primus_tfhe/README.md), then run a backend example below.
- **Use encryption and evaluation primitives:** start with [LWE](crates/primus_lwe/README.md), [GLWE](crates/primus_glwe/README.md), or [NTRU](crates/primus_ntru/README.md). These crates provide keys and operations beneath the TFHE workflows.
- **Build arithmetic or scheme components:** use the workspace map below and the corresponding crate's README and rustdoc.

Examples separate client key generation/encryption, server evaluation, and client decryption. They demonstrate reusable contexts, evaluators, and output buffers. Ordinary LUT compilation defaults to the input plaintext codec; explicit codec variants support a different output plaintext modulus.

## TFHE backends

| Family | NTT: explicit field modulus | Fourier: native word modulus |
| --- | --- | --- |
| [GLWE parameters and clients](crates/primus_tfhe_glwe/README.md) | [primus_tfhe_glwe_ntt](crates/primus_tfhe_glwe_ntt/README.md) | [primus_tfhe_glwe_fourier](crates/primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](crates/primus_tfhe_ntru/README.md) | [primus_tfhe_ntru_ntt](crates/primus_tfhe_ntru_ntt/README.md) | [primus_tfhe_ntru_fourier](crates/primus_tfhe_ntru_fourier/README.md) |

All four backends support LWE private/public-key clients, classic binary/ternary secrets, programmable bootstrapping (PBS), interleaved ManyLUT, bounded bivariate LUTs, odd-plaintext-modulus full-domain unary LUTs, Boolean gates, circuit bootstrapping (CBS) with CMUX consumption, and fixed-scale factorized multi-value bootstrapping (MVB). ManyLUT and MVB compute several functions of one encrypted input. Fourier supports both RustFFT and TfheFFT, with backend-specific precision requirements.

Sparse fixed-weight binary PBS is experimental. Both GLWE backends support sparse PBS, CBS, and MVB; both NTRU backends support sparse ordinary/interleaved PBS but reject sparse CBS/MVB. NTRU requires an invertible secret; its Fourier backend also checks numerical stability and requires odd weight for fixed-weight binary secrets. See the [shared capability guide](crates/primus_tfhe/README.md#crate-map-and-capabilities) for encoding and composition boundaries.

Run a basic end-to-end example from the repository root:

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example ntt_basic
cargo run -p primus_tfhe_glwe_fourier --release --example fourier_basic
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_basic
```

Each backend README also links its CBS → CMUX, MVB threshold, and sparse PBS examples. Parameter choices, output encodings, and supported combinations remain explicit; these APIs do not infer them from raw ciphertexts.

## Workspace map

| Layer | Crates and responsibility |
| --- | --- |
| Storage and integers | [primus_data](crates/primus_data/README.md): contiguous storage; [primus_integer](crates/primus_integer/README.md): integer traits and multi-limb arithmetic; [primus_gcd](crates/primus_gcd/README.md): GCD and modular inverses |
| Modular arithmetic | [primus_reduce](crates/primus_reduce/README.md): modulus-side traits; [primus_modulus](crates/primus_modulus/README.md): modulus implementations; [primus_factor](crates/primus_factor/README.md): prepared multiplication; [primus_barrett_derive](crates/primus_barrett_derive/README.md): constant Barrett moduli |
| Polynomials and transforms | [primus_poly](crates/primus_poly/README.md): polynomial representations and arithmetic; [primus_ntt](crates/primus_ntt/README.md): exact transforms; [primus_fft](crates/primus_fft/README.md): Fourier tables and reusable scratch |
| Decomposition and RNS | [primus_decompose](crates/primus_decompose/README.md): signed gadget decomposition; [primus_rns](crates/primus_rns/README.md): residue bases, conversion, and hybrid RNS |
| Sampling and encoding | [primus_distr](crates/primus_distr/README.md): secret/noise distributions; [primus_encoding](crates/primus_encoding/README.md): Rounded, Scaled, and BFV RNS coefficient codecs |
| Ciphertext representations | [primus_lattice](crates/primus_lattice/README.md): storage, arithmetic, extraction, gadget products, CMUX, and reusable workspaces |
| Encryption and evaluation | [primus_lwe](crates/primus_lwe/README.md), [primus_glwe](crates/primus_glwe/README.md), [primus_ntru](crates/primus_ntru/README.md): keys and scheme primitives; [primus_glwe_rns](crates/primus_glwe_rns/src/lib.rs): CRT/DCRT GLWE and hybrid-RNS key switching |
| TFHE | [primus_tfhe](crates/primus_tfhe/README.md): shared external LWE clients, LUTs, PBS traits, and Boolean evaluation; the two family crates and four backends above bind parameters, keys, and execution |

The RNS and encoding components provide building blocks rather than complete BFV, BGV, or CKKS application backends. `test-support/` contains development-only shared test fixtures and allocation counters. Mathematical contracts live in rustdoc; cross-layer TFHE rationale and retained performance tradeoffs are in the [implementation notes](crates/primus_tfhe/IMPLEMENTATION.md).

## Building and testing

Default features build on stable Rust. Run these commands from the workspace root:

```sh
cargo check --workspace --all-targets
cargo test --workspace
cargo doc --workspace --no-deps
```

Portable SIMD requires nightly. To check and test the whole workspace with all features, including SIMD and optional RNS paths:

```sh
cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
cargo +nightly test --workspace --all-features
```

The [justfile](justfile) offers focused workflows:

| Command | Coverage |
| --- | --- |
| `just tfhe` | Seven TFHE crates and test support: default checks, Clippy, tests/doctests, and docs |
| `just tfhe-simd` | The same packages with nightly SIMD: checks, Clippy, and tests/doctests |
| `just simd` | Selected arithmetic crates with nightly SIMD: checks, Clippy, and nextest |

`just` is optional; workflows that invoke nextest also require `cargo-nextest`. The [CI workflow](.github/workflows/ci.yml) is the full workspace validation reference: formatting, stable/default and nightly/all-feature all-target Clippy, tests and doctests, and strict nightly rustdoc including private items. Local `just ci` combines the workspace default and focused SIMD workflows; it is not identical to CI's all-feature matrix.

The repository configures `target-cpu=native`, so local artifacts may use instructions unavailable on other CPUs. CI clears that setting. Benchmark commands and workload parameters are documented with each crate's benchmarks; measure performance separately from compilation and tests.

## License

Primus FHE is licensed under either of the following, at your option:

- [Apache License, Version 2.0](LICENSE-APACHE-2.0)
- [MIT License](LICENSE-MIT)
