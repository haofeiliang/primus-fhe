# primus_modulus

English | [简体中文](README.zh_CN.md)

`primus_modulus` provides the concrete modulus contexts and arithmetic kernels that implement the contracts defined by [`primus_reduce`](../primus_reduce/README.md).

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Modulus types

| Type | Modulus | Intended use |
| --- | --- | --- |
| `NativeModulus<T>` | implicit `2^T::BITS` | wrapping arithmetic in the native word ring |
| `PowOf2Modulus<T>` | representable power of two greater than one | mask-based arithmetic for an explicit power-of-two modulus |
| `BarrettModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | repeated multiplication, wide reduction, fused slice operations, and dot products |
| `CompactModulus<T>` | `1 < modulus < 2^(T::BITS - 2)` | basic add, subtract, negate, and inverse operations without precomputed data |
| `UintModulus<T>` | any representable `modulus > 1` | basic arithmetic when the compact range restriction is unsuitable |

`BarrettModulus` stores the little-endian limbs `[low, high]` of `floor(B² / modulus)`, where `B = 2^T::BITS`. The two spare modulus bits permit its dot-product kernels to accumulate 16 products before reduction. `CompactModulus` and `UintModulus` store only the modulus.

## Example

```rust
use primus_modulus::{BarrettModulus, reduce::prelude::*};

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let lhs = [12, 20, 31];
let rhs = [9, 10, 11];
let mut output = [0; 3];
modulus.reduce_mul_slice_to(&lhs, &rhs, &mut output);
assert_eq!(output, [11, 6, 50]);
```

## Choosing and constructing a modulus

- Use `NativeModulus::new()` when overflow itself represents reduction modulo the full word range.
- Use `PowOf2Modulus::new(value)` for a representable power-of-two modulus.
- Use `BarrettModulus::new(value)` when multiplication and repeated reduction are required for a modulus in the supported Barrett range.
- Use `CompactModulus::new(value)` or `UintModulus::new(value)` for their smaller basic-operation sets.

Checked constructors validate their documented range. `CompactModulus(value)` and `UintModulus(value)` remain available when an already-validated caller intentionally avoids a repeated check. Likewise, `BarrettModulus::new_unchecked`, `BarrettModulus::from_parts`, and `SimdBarrettModulus::from_parts` require the caller to uphold their documented reciprocal and range invariants.

## Features

- `derive` re-exports the `Barrett` derive macro for compile-time constant moduli. See [`primus_barrett_derive`](../primus_barrett_derive/README.md).
- `simd` enables nightly portable-SIMD kernels and slice dispatch. When `derive` is also enabled, generated Barrett contexts use the corresponding SIMD paths.

Both features are disabled by default. The `simd` feature requires a nightly Rust toolchain.

## Arithmetic contracts

The operation traits, input ranges, output ranges, and slice-length requirements come from `primus_reduce`.

- Canonical operations generally require canonical residues unless their trait documents a wider input domain.
- Lazy operations return representatives in `[0, 2 * modulus)` and require a final once-reduction before canonical use.
- Low-level slice kernels may use `debug_assert*!` for shape diagnostics; release callers must uphold the documented length contracts.
- `FieldContext` is a capability marker. It does not prove primality or guarantee that every nonzero value is invertible.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
