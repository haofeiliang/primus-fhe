# primus_poly

English | [简体中文](README.zh_CN.md)

`primus_poly` provides storage wrappers and arithmetic operations for the polynomial representations used throughout [Primus FHE](../../README.md). The wrappers separate coefficient, NTT, CRT/DCRT, multi-limb, and Fourier data so callers can make each representation explicit without storing per-polynomial context.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, data representations, and numerical contracts are unstable and may change incompatibly at any time.

## Representations

| Type | Representation and layout | Main operations |
| --- | --- | --- |
| `ArrayBase<S>` | Flat unsigned-integer array | Element-wise modular arithmetic and butterfly helpers |
| `Polynomial<S>` | `N` coefficients in ascending-power order under one modulus | Add, subtract, negate, scalar/factor multiplication, negacyclic monomials, naive multiplication, evaluation, and sampling |
| `NttPolynomial<S>` | `N` point values under one modulus; ordering is defined by the NTT context | Point-wise arithmetic, fused multiply-add, inverse, and uniform sampling |
| `CrtPolynomial<S>` | Modulus-major coefficient data: one contiguous `N`-coefficient polynomial per modulus | Component-wise arithmetic, scalar/factor operations, negacyclic monomials, and shared uniform-binary/sparse-ternary/Gaussian sampling |
| `DcrtPolynomial<S>` | Modulus-major NTT data: one contiguous `N`-value transform per modulus | Point-wise arithmetic, fused multiply-add, inverse, uniform sampling, and butterfly kernels |
| `BigUintPolynomial<S>` | Coefficient-major data: each coefficient is a fixed-width little-endian limb chunk | Multi-limb modular add, subtract, and negate |
| `FourierPolynomial<S>` | Independent complex evaluations; ordering is defined by the Fourier backend | Point-wise add, subtract, negate, multiply, fused multiply-add, and scalar multiplication |

`primus_poly` stores values and implements arithmetic; it does not own transform tables or perform representation selection. [`primus_ntt`](../primus_ntt) converts between coefficient and NTT/CRT and DCRT representations, while [`primus_fft`](../primus_fft) supplies Fourier transforms.

## Example

```rust
use primus_modulus::CompactModulus;
use primus_poly::PolynomialOwned;

let modulus = CompactModulus::new(97_u64);
let mut lhs = PolynomialOwned::from_slice(&[80, 12, 5, 40]);
let rhs = PolynomialOwned::from_slice(&[30, 9, 96, 70]);

lhs.add_assign(&rhs, modulus);
assert_eq!(lhs.as_slice(), &[13, 21, 4, 13]);

// Multiplication by X in Z_97[X]/(X^4 + 1).
lhs.mul_monomial_assign(1, modulus);
assert_eq!(lhs.as_slice(), &[84, 13, 21, 4]);
```

## Storage and ownership

Most polynomial types are generic over a backing store `S` implementing the contiguous-storage traits from [`primus_data`](../primus_data/README.md). Owned `Vec` aliases and borrowed slice aliases are available for the common coefficient, NTT, Fourier, and array forms. CRT, DCRT, and multi-limb wrappers can likewise be constructed over owned or borrowed storage through their generic types.

Operation names describe where results are written:

- `operation` consumes a mutable-capable wrapper, updates its storage, and returns the wrapper;
- `operation_assign` updates `self` in place;
- `operation_to` writes to a separate output wrapper;
- `operation_rev_assign` writes a reversed non-commutative operation into its mutable operand.

Consuming a wrapper backed by `&mut [T]` still updates the caller's slice.

## Layout and arithmetic contracts

The wrappers deliberately do not store polynomial length, modulus values, transform tables, normalization state, or limb width. Callers must establish these invariants at the owning FHE/RNS/transform boundary and preserve them across low-level operations:

- all operands and outputs participating in one operation have the same representation and layout;
- backing storage is exactly divisible by the supplied polynomial length or multi-limb coefficient width;
- CRT/DCRT storage has length `moduli.len() * poly_length`; component-wise scalar, factor, distribution, and modulus slices contain one entry per component, while per-point factor polynomials such as butterfly `w` have the same modulus-major layout and length as the backing storage;
- values satisfy the canonical or lazy range required by the selected `primus_reduce` or `primus_factor` operation;
- monomial exponents belong to the documented `[0, 2N)` range, and methods requiring a power-of-two `N` receive one;
- NTT and Fourier operands were produced for compatible transform contexts.

Many shape checks in repeated arithmetic paths are `debug_assert*!` diagnostics. Release callers must uphold the documented contracts; iterator `zip` and `chunks_exact` operations are not substitutes for boundary validation.

## Random sampling

Direct NTT and DCRT sampling is uniform. To sample a non-uniform coefficient distribution, construct a coefficient-domain `Polynomial` or `CrtPolynomial` and then transform it. CRT uniform-binary, sparse-ternary, and Gaussian sampling draw one logical coefficient and encode that same value under every component modulus. The sparse ternary distribution has `P(0) = 1/2` and `P(1) = P(-1) = 1/4`. Random APIs require an RNG implementing both `rand::Rng` and `rand::CryptoRng`.

## SIMD feature

The optional `simd` feature enables the portable-SIMD DCRT butterfly path and the matching SIMD support in arithmetic dependencies. It is disabled by default and requires a nightly Rust toolchain.

```text
cargo +nightly test -p primus_poly --features simd
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
