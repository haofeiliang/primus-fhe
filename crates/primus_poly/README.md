# primus_poly

English | [简体中文](README.zh_CN.md)

`primus_poly` provides storage wrappers and arithmetic operations for the polynomial representations used throughout [Primus FHE](../../README.md). The wrappers separate coefficient, NTT, CRT/DCRT, multi-limb, and Fourier data so callers can make each representation explicit without storing per-polynomial context.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, data representations, and numerical contracts are unstable and may change incompatibly at any time.

## Representations

| Type | Representation and layout | Main operations |
| --- | --- | --- |
| `Polynomial<S>` | `N` coefficients in ascending-power order under one modulus | Add, subtract, negate, scalar/factor multiplication, negacyclic monomials, naive multiplication, evaluation, and sampling |
| `NttPolynomial<S>` | `N` point values under one modulus; ordering is defined by the NTT context | Point-wise arithmetic, fused multiply-add, inverse, and uniform sampling |
| `CrtPolynomial<S>` | Modulus-major coefficient data: one contiguous `N`-coefficient polynomial per modulus | Component-wise arithmetic, scalar/factor operations, negacyclic monomials, and shared uniform-binary/sparse-ternary/Gaussian sampling |
| `DcrtPolynomial<S>` | Modulus-major NTT data: one contiguous `N`-value transform per modulus | Point-wise arithmetic, fused multiply-add, inverse, uniform sampling, and butterfly kernels |
| `BigUintPolynomial<S>` | Coefficient-major data: each coefficient is a fixed-width little-endian limb chunk | Multi-limb modular add, subtract, and negate |
| `FourierPolynomial<S>` | Independent complex evaluations; ordering is defined by the Fourier backend | Point-wise add, subtract, negate, multiply, fused multiply-add, and scalar multiplication |

`primus_poly` stores values and implements arithmetic; it does not own transform tables or perform representation selection. [`primus_ntt`](../primus_ntt) converts between coefficient and NTT/CRT and DCRT representations, while [`primus_fft`](../primus_fft) supplies Fourier transforms.

For flat scalar buffers, use slices and the `Reduce*Slice` traits from
[`primus_reduce`](../primus_reduce/README.md), such as
`modulus.reduce_add_slice_assign(lhs, rhs)`. Polynomial and ciphertext wrappers
retain their representation-specific operations. DCRT inverse butterflies remain
available through `DcrtPolynomial::butterfly_mul_to` and `butterfly_mul_factor_to`.

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

## Ring polynomial length

`PolyLength` is a checked coefficient count `N`: a power of two in `MIN_POLY_LENGTH..=MAX_POLY_LENGTH` (currently `32..=2^17`). FHE layouts and transform libraries share this supported range, checked once by the type's constructor. Use `PolyLength::try_new(N)` or `PolyLength::new(N)`; `PolyLengthError` retains the rejected length.

`get()`, `log_n()` and `fourier_poly_len()` return `N`, `log2(N)` and `N/2` complex elements. GLWE/NTRU layouts, NTT/FFT tables and workspaces pass this type directly without repeating the upper-bound check. The range guarantees that `2N` fits in `usize`; combined storage lengths and transform numerical conditions remain checked at their owning boundaries. Raw polynomial wrappers and batch storage do not carry a separate ring length; their actual element counts remain `usize`.

The raw wrappers use `len()` / `is_empty()` to inspect their complete storage:

| Wrapper | What `len()` counts | One complete polynomial |
| --- | --- | --- |
| `Polynomial` | Coefficients | `N` |
| `NttPolynomial` | NTT evaluations | `N` |
| `FourierPolynomial` | Complex values | `N/2` |
| `CrtPolynomial`, `DcrtPolynomial` | Residues across all moduli | `moduli_count * N` |

These accessors do not validate geometry or layout. Empty, arbitrary-length and packed storage remain representable; an operation's contract determines which layouts it accepts. Checked table and size `poly_length()` accessors return the ring's `PolyLength`, while `DcrtTable::rns_poly_len()` returns the complete RNS polynomial's storage count.

## Storage and ownership

Most polynomial types are generic over a backing store `S` implementing the contiguous-storage traits from [`primus_data`](../primus_data/README.md). Owned `Vec` aliases and borrowed slice aliases are available for the common coefficient, NTT, and Fourier forms. CRT, DCRT, and multi-limb wrappers can likewise be constructed over owned or borrowed storage through their generic types.

`as_view()` and `as_mut_view()` borrow the complete storage while preserving the polynomial representation. Equivalent `From<&Wrapper<S>>` / `From<&mut Wrapper<S>>` conversions return slice-backed wrappers without copying. `into_inner()` consumes a wrapper and returns its original storage, including borrowed or aligned storage; it does not allocate or turn a borrow into an owner.

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

`Polynomial::add_mul_monomial_pair_assign` accumulates two rotated inputs in one output traversal without allocation. `add_mul_monomial_pair_assign` also accepts a flat batch of complete polynomials, computing rotation offsets once and dispatching each interval outside the polynomial loop for 64-bit words. Each contribution is reduced in order; both APIs require equally sized power-of-two polynomials, canonical residues, and exponents in `[0, 2N)`.

`CoeffAutomorphismPermutation` caches the coefficient substitution `X -> X^d` modulo `X^N + 1`. Construct it for a power-of-two `N >= 32` and odd `d` in `[1, 2N)`, then reuse `apply_to` on canonical residues. `apply_signed_to` is for small signed coefficients whose required negations are representable. The map does not perform cryptographic key switching. Its NTT counterpart lives in `primus_ntt`. Identity copies the coefficients; `d=N+1` negates only odd positions. These two cases allocate no index table. General degrees store a packed source index and sign in one `u32` per coefficient, shared by single-modulus and RNS consumers.

## Random sampling

Direct NTT and DCRT sampling is uniform. To sample a non-uniform coefficient distribution, construct a coefficient-domain `Polynomial` or `CrtPolynomial` and then transform it. CRT uniform-binary, sparse-ternary, and Gaussian sampling draw one logical coefficient and encode that same value under every component modulus. The sparse ternary distribution has `P(0) = 1/2` and `P(1) = P(-1) = 1/4`. Random APIs require an RNG implementing both `rand::Rng` and `rand::CryptoRng`.

`Polynomial::random_gaussian` collects samples directly into the chosen `FromIterator` storage. `random_gaussian_assign` overwrites existing storage through `DiscreteGaussian::sample_to`, selecting the CDT/Ziggurat backend once per batch. `add_random_gaussian_assign` preserves the existing coefficients and adds one sample per coefficient under the supplied modulus; the sampler must encode residues for that same modulus. Both in-place methods allocate no scratch. All three consume samples in coefficient order, with the same RNG consumption as scalar sampling; an empty polynomial consumes none.

## Monomial arithmetic benchmark

[monomial.rs](benches/monomial.rs) compares two single-term accumulations with one paired accumulation for `acc += first * X^r + second * X^s` modulo `X^N + 1`. All cases use `N=1024/2048`, batches of `1/8` polynomials and the same exponents. The u32/u64 Barrett cases share `q=132120577`; native cases wrap at their respective word widths. Inputs are seeded, buffers are reused, and timing excludes allocation and initialization. Equal coefficient counts do not imply equal byte counts across word widths. These are arithmetic measurements, not PBS/CBS timings.

```text
cargo bench -p primus_poly --bench monomial
```

## SIMD feature

The optional `simd` feature enables the portable-SIMD DCRT butterfly path and the matching SIMD support in arithmetic dependencies. It is disabled by default and requires a nightly Rust toolchain.

```text
cargo +nightly test -p primus_poly --features simd
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
