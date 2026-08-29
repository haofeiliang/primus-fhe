# Primus FHE

English | [简体中文](README.zh_CN.md)

Primus FHE is an experimental Rust workspace for exploring fully homomorphic
encryption implementations and the arithmetic infrastructure they require.

> [!WARNING]
> Primus FHE is in an early experimental stage. Its APIs, data representations,
> algorithms, and crate boundaries are unstable and may receive breaking
> changes at any time, without a deprecation period. No claim of production
> readiness or security review is made.

## Overview

The workspace currently includes:

- low-level storage, integer, modular-arithmetic, decomposition, RNS, NTT, and
  Fourier building blocks;
- lattice ciphertext abstractions for LWE-, GLWE-, and NTRU-based schemes;
- TFHE experiments over GLWE and NTRU, with NTT and Fourier backends.

Documentation will be expanded as the crates and their public contracts are
reviewed. The following foundational crates already have focused READMEs:

- [`primus_data`](crates/primus_data/README.md): contiguous-storage traits;
- [`primus_gcd`](crates/primus_gcd/README.md): fixed-width GCD and modular
  inverse operations;
- [`primus_integer`](crates/primus_integer/README.md): integer traits,
  fixed-width multi-limb arithmetic, and optional SIMD abstractions.

## Building and testing

The default workspace builds on stable Rust:

```text
cargo check --workspace --all-targets
cargo test --workspace
```

Portable SIMD support currently requires nightly Rust. The repository's
`justfile` provides the complete SIMD check, lint, and test sequence:

```text
just simd
```

The repository configures `target-cpu=native`, so locally built artifacts may
use instructions unavailable on older or different CPUs.

## License

Primus FHE is licensed under either of the following, at your option:

- [Apache License, Version 2.0](LICENSE-APACHE-2.0)
- [MIT License](LICENSE-MIT)
