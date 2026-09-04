# primus_ntt

English | [简体中文](README.zh_CN.md)

`primus_ntt` provides in-place negacyclic number-theoretic transforms for
polynomials in `Z_q[X] / (X^N + 1)`. It includes generic unsigned-integer
tables, optimized `u32` and `u64` tables, direct monomial transforms, and
modulus-major DCRT transforms for [Primus FHE](../../README.md).

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, NTT
> representation, numerical contracts, and backend selection are unstable and
> may change incompatibly at any time.

## Core types

| Type | Role |
| --- | --- |
| `NttTable` | Common construction and forward/inverse transform contract |
| `MonomialNttTable` | Directly transforms `coeff * X^degree` without building a coefficient polynomial |
| `UintNttTable<T>` | Generic unsigned-integer implementation using Shoup multiplication |
| `U32NttTable` | Optimized table for `u32` moduli below `2^30` |
| `U64NttTable` | Optimized table for `u64` moduli below `2^62` |
| `DcrtTable<Ntt>` | One same-length NTT table per CRT modulus |
| `U32DcrtTable`, `U64DcrtTable`, `UintDcrtTable<T>` | Common DCRT aliases |

The specialized tables own their root powers and precomputed backend layouts.
Transforms dispatch to a valid scalar or instruction-set-specific kernel, run
in place, and require no per-call scratch allocation.

## Example

```rust
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};

let modulus = BarrettModulus::new(97_u32);
let table = U32NttTable::new(3, modulus).unwrap(); // N = 8; 2N divides 97 - 1
let expected = vec![3, 1, 4, 1, 5, 9, 2, 6];
let mut values = expected.clone();

table.transform_slice(&mut values);
// `values` now holds NTT evaluations in bit-reversed order.
table.inverse_transform_slice(&mut values);

assert_eq!(values, expected);
```

Construct and reuse a table outside repeated transform paths. The table is
immutable and implements `Send + Sync`, so it may be shared across threads.

## Representation and ranges

For `N = 2^log_n`, the forward transform consumes coefficients in
ascending-power order and produces evaluations in bit-reversed order. The
inverse transform consumes that bit-reversed representation and restores
ascending-power coefficient order.

Every single-modulus input or output slice must contain exactly
`table.poly_length()` values. `NttTable` implementations enforce this before
entering their unchecked kernels.

| Operation | Input range | Output range |
| --- | --- | --- |
| `transform_slice` | `[0, q)` | `[0, q)` |
| `inverse_transform_slice` | `[0, q)` | `[0, q)` |
| `lazy_transform_slice` | `[0, 4q)` | `[0, 4q)` |
| `lazy_inverse_transform_slice` | `[0, 2q)` | `[0, 2q)` |

Lazy values represent residues modulo `q`, but their wider integer ranges are
part of the calling contract. In particular, a lazy forward result is not
automatically a valid lazy-inverse input; normalize it to the inverse method's
accepted range first.

The consuming `transform_inplace` and `inverse_transform_inplace` methods use
the canonical operations while changing the storage wrapper between
[`Polynomial`](../primus_poly/README.md) and `NttPolynomial`.

## Construction constraints

- The supported contract uses `log_n >= 1`, so `N >= 2`. `N = 1` is not a
  supported transform size.
- The modulus must admit a primitive `2N`-th root of unity. For a prime
  modulus, this requires `2N` to divide `q - 1`.
- `U32NttTable` and `UintNttTable<u32>` require `q < 2^30`;
  `U64NttTable` and `UintNttTable<u64>` require `q < 2^62`. The two spare high
  bits make every lazy value below `4q` representable.
- The generic table additionally requires `N < q` and reports a construction
  error if `N` cannot be represented by its coefficient type.

`NttTable::new` searches for a primitive root and precomputes its powers,
preconditioners, and selected backend layout. A modulus context satisfying
`FieldContext` supplies arithmetic operations but does not itself prove that
the modulus is prime or that the required root exists.

## Monomial transforms

`MonomialNttTable` writes the NTT representation of `coeff * X^degree`
directly into an exact-length output slice. The degree is interpreted modulo
`2N`, matching `X^N = -1` in the negacyclic ring.

`transform_monomial` requires `coeff` to be canonical, meaning
`0 <= coeff < q`; it does not reduce or validate the coefficient. Use
`transform_coeff_one_monomial` and `transform_coeff_minus_one_monomial` for
the common `X^degree` and `-X^degree` cases.

## DCRT layout

`DcrtTable` stores one NTT table for each modulus, all with the same `N`.
Coefficient and transform slices are modulus-major and have length
`moduli_count * N`:

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

This matches the `CrtPolynomial` and `DcrtPolynomial` layout from
[`primus_poly`](../primus_poly/README.md). Shape checks in repeated DCRT paths
are debug diagnostics; release callers must preserve the exact total length
and modulus-major ordering.

For `DcrtTable::transform_monomial`, the single supplied `coeff` must be
canonical for every component modulus. The method does not reduce it
separately for each limb.

## SIMD backends and build target

On `x86_64`, the specialized tables detect CPU features at runtime and select
among scalar, AVX2, AVX-512 DQ, and AVX-512 IFMA kernels as applicable. Other
architectures use scalar implementations. These x86 kernels do not require
the crate's optional `simd` feature; that feature enables the matching
portable-SIMD support in dependencies and currently requires nightly Rust.

The repository-level [`.cargo/config.toml`](../../.cargo/config.toml) sets
`target-cpu=native`. This is separate from runtime dispatch: the compiler may
use host-specific instructions in ordinary Rust code as well as in a selected
backend. Override the build rustflags when producing portable binaries or
performing controlled ISA benchmarks.

## Testing and benchmarks

```text
cargo test -p primus_ntt
cargo bench -p primus_ntt --bench bench_ntt
cargo +nightly test -p primus_ntt --features simd
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
or the [MIT License](../../LICENSE-MIT), at your option.
