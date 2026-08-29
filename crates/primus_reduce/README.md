# primus_reduce

English | [简体中文](README.zh_CN.md)

`primus_reduce` defines the modular-arithmetic contracts shared by modulus implementations and higher-level algorithms in Primus FHE.

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

## Overview

The traits in this crate put the modulus or reduction context in the receiver position:

```text
modulus.reduce_add(a, b)
modulus.reduce_mul_slice_to(a, b, output)
```

Operations are split into fine-grained traits so a modulus type implements only the scalar, slice, lazy, inverse, or fused operations it actually supports. Concrete modulus types and kernels live in [`primus_modulus`](../primus_modulus).

The main API groups are:

- scalar `Reduce*` traits for canonical arithmetic, inversion, division, and exponentiation;
- `Reduce*Slice` traits for bulk operations and SIMD dispatch;
- `LazyReduce*` traits whose results lie in `[0, 2 * modulus)`;
- `Modulus` and `ExplicitModulus` for modulus metadata;
- `RingContext` and `FieldContext` capability markers.

## Example

```rust
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;

let modulus = BarrettModulus::new(97u64);

assert_eq!(modulus.reduce_add(80, 30), 13);
assert_eq!(modulus.reduce_mul(12, 9), 11);

let mut values = [80, 30];
let rhs = [30, 80];
modulus.reduce_add_slice_assign(&mut values, &rhs);
assert_eq!(values, [13, 13]);
```

## Caller contracts

This crate defines interfaces, not validation boundaries. Each public method documents its input range, representation, output state, and length requirements.

- Higher-level constructors and batch APIs should validate dimensions and layouts once.
- Low-level numerical kernels may diagnose shape mismatches only with `debug_assert*!`; release callers must uphold the documented contracts.
- Dot products explicitly check equal slice lengths in every build profile.
- Lazy results require a final once-reduction before they are treated as canonical residues.
- Fallible inverse traits report `ReduceError`; infallible inverse and division traits may panic when the required inverse does not exist.

`FieldContext` means that a modulus type implements the listed operation set. It does not prove that the modulus is prime or that every nonzero residue is invertible. Callers remain responsible for validating the algebraic assumptions required by their algorithms.

## Value-side mirror

[`primus_modulo`](../primus_modulo/README.md) provides an optional value-receiver mirror such as `a.add_modulo(b, modulus)`. The modulus-side traits in this crate remain the primary implementation and workspace integration boundary.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
