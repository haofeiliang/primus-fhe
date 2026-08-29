# primus_modulo

English | [简体中文](README.zh_CN.md)

`primus_modulo` provides value-side extension traits that mirror the modulus-side operations in [`primus_reduce`](../primus_reduce/README.md).

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API is unstable and may change incompatibly at any time.

## Overview

Each blanket implementation only reverses the call order:

| Value side | Modulus side |
| --- | --- |
| `a.add_modulo(b, modulus)` | `modulus.reduce_add(a, b)` |
| `a.mul_modulo(b, modulus)` | `modulus.reduce_mul(a, b)` |
| `values.add_modulo_slice_assign(rhs, modulus)` | `modulus.reduce_add_slice_assign(values, rhs)` |

The wrappers add no allocation, buffering, validation, or arithmetic. Output ranges, panic behavior, length requirements, and lazy-reduction guarantees are inherited from the corresponding `primus_reduce` operation.

## Example

The operations are extension-trait methods, so callers should normally import the prelude:

```rust
use primus_modulo::prelude::*;
use primus_modulus::BarrettModulus;

let modulus = BarrettModulus::new(97u64);

assert_eq!(80u64.add_modulo(30, modulus), 13);
assert_eq!(12u64.mul_modulo(9, modulus), 11);

let mut values = [80, 30];
let rhs = [30, 80];
values
    .as_mut_slice()
    .add_modulo_slice_assign(rhs.as_slice(), modulus);
assert_eq!(values, [13, 13]);
```

Importing individual traits is also supported when a wildcard prelude is undesirable.

## Maintenance status

`primus_modulo` is maintained as a thin mirror, but no other Primus FHE crate currently depends on it. Workspace implementations and generic arithmetic use `primus_reduce` directly.

Rust can only offer extension methods after the providing trait is in scope, and diagnostics for many fine-grained blanket traits can be less direct than modulus-side calls. New workspace code should therefore normally prefer `primus_reduce`; this crate remains available when value-receiver syntax is useful to an external caller.

The mirror intentionally does not introduce a residue wrapper, a new modulus context, compatibility aliases, or a second validation layer.

## Caller contracts

Callers must uphold the same contracts documented by the matching `primus_reduce` trait. In particular, slice lengths and residue ranges are generally caller-maintained invariants, and lazy results remain in `[0, 2 * modulus)` until reduced once. Importing this crate does not add release-mode checks to the underlying numerical kernels.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
