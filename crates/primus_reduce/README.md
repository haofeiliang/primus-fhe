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

## Signed coefficients

`EncodeSigned<T>` converts bounded signed coefficients to canonical residues, without plaintext scaling or general modular reduction. It is implemented for the concrete modulus types in `primus_modulus` and exported from both the crate root and `prelude`. It does not require `Reduce` or `ReduceNeg`. Custom modulus types implement `encode_signed`; the default slice method checks equal lengths once and statically calls that scalar implementation.

`ReduceDotProductSigned<T>` computes the dot product of canonical residues and bounded signed coefficients, returning a canonical residue without an encoded copy. It checks equal slice lengths; empty inputs return zero. Its signed input bounds match `EncodeSigned`. Native, PowOf2, Barrett and derived Barrett moduli implement this trait, including backend-specific SIMD dispatch.

`RingContext<T>` includes both signed operation traits; `FieldContext<T>` inherits them through `RingContext<T>`. Both contexts require `T: FheUint`. Code needing only one operation can use its individual trait without the full context.

```rust
use primus_modulus::{NativeModulus, UintModulus};
use primus_reduce::prelude::*;

assert_eq!(UintModulus::new(97u64).encode_signed(-1), 96);
assert_eq!(NativeModulus::<u64>::new().encode_signed(-1), u64::MAX);
let mut output = [0u64; 3];
UintModulus::new(97).encode_signed_slice_to(&[-1, 0, 1], &mut output);
assert_eq!(output, [96, 0, 1]);
```

For an explicit modulus `q`, every coefficient must satisfy `value.unsigned_abs() < q`. This is a correctness precondition, not a release validation pass. Every signed value is representable under the native modulus. Both methods handle the signed minimum without signed negation. See [`primus_modulus`](../primus_modulus/README.md#arithmetic-contracts) for the concrete encoding strategies.

LWE, GLWE and NTRU use this bounded conversion. NTRU parameters validate the sampler's support against their modulus; callers importing keys or converting them to a different modulus must ensure the coefficients fit that target. When an already validated raw modulus is all that is available, `UintModulus(q)` provides the operation without building a reduction context.

## Prepared modulus switching

`source.prepare_switch_to(target)` prepares a fixed modulus pair through `PrepareModulusSwitch`. Its associated `PreparedModulusSwitch` converts canonical source residues with `switch(value)`, returning `round(value*target/source) mod target` with ties upward. Native moduli are valid on either side. This is integer ratio rounding, independent of modular division.

`RingContext` includes `PrepareModulusSwitch`; `FieldContext` inherits it. The preparation trait also works independently, so codecs need only preparation and modular addition. `PreparedModulusSwitch` describes the returned conversion, not the source ring context. Custom ring contexts must implement preparation.

`switch_map` carries a payload beside each coefficient, allowing fused sign handling, output conversion and accumulation without a temporary buffer. Concrete implementations can select their arithmetic kernel before the iterator; the default uses `switch`. The iterator and callback may have partial effects if they panic.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
