# primus_barrett_derive

English | [简体中文](README.zh_CN.md)

`primus_barrett_derive` implements the `Barrett` derive macro used by [`primus_modulus`](../primus_modulus/README.md) to create zero-sized modulus contexts for compile-time constants.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its generated API and numerical contracts are unstable and may change incompatibly at any time.

Workspace crates should normally enable the `derive` feature of `primus_modulus` instead of depending on this procedural-macro crate directly:

```toml
[dependencies]
primus_modulus = { path = "../primus_modulus", features = ["derive"] }
```

## Example

```rust
use primus_modulus::{Barrett, reduce::prelude::*};

#[derive(Barrett)]
#[modulus(ty = u32, value = 536813569)]
struct Modulus;

assert_eq!(Modulus::value(), 536_813_569);
assert_eq!(Modulus.reduce_mul(12_345, 67_890), 301_288_481);
```

The visibility of the generated `value()` and `ratio()` functions follows the visibility of the unit struct.

## Input contract

The macro accepts only a unit struct with one `modulus` attribute:

```rust,ignore
#[derive(Barrett)]
#[modulus(ty = u64, value = 1125899906826241)]
pub struct CiphertextModulus;
```

- `ty` must be the bare identifier `u16`, `u32`, or `u64`.
- `value` must satisfy `1 < value < 2^(BITS - 2)` for that type.
- Invalid structures, types, literals, and modulus ranges produce compile-time errors.

## Generated implementation

For each modulus, the macro computes the two-limb reciprocal `floor(B² / modulus)` during macro expansion, where `B = 2^BITS`. The resulting unit struct stores no runtime context.

The expansion provides:

- associated `value()` and `ratio()` functions;
- `primus_reduce` scalar, slice, lazy-reduction, inverse, exponentiation, fused-operation, and dot-product implementations;
- `Copy`, `Clone`, `PartialEq`, `Eq`, `Debug`, and `Hash` implementations.

Do not derive those standard traits separately on the same struct, because the generated implementations would conflict.

## SIMD

The crate's `simd` feature selects SIMD slice implementations in generated code. It is normally enabled transitively by using the `derive` and `simd` features of `primus_modulus`; that path requires a nightly Rust toolchain.

The scalar and SIMD expansions follow the same caller contracts as `BarrettModulus`. In particular, slice dimensions remain caller-maintained invariants in low-level kernels, lazy results lie in `[0, 2 * modulus)`, and inverse operations still require an invertible input. A compile-time modulus does not imply that the modulus is prime.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
