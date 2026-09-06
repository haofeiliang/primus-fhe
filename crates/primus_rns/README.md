# primus_rns

English | [简体中文](README.zh_CN.md)

`primus_rns` provides residue-number-system bases, CRT composition and
decomposition, base conversion, and the hybrid `Q`/`P` operations used by
[Primus FHE](../../README.md). Its allocation-free polynomial paths operate on
flat slices with caller-owned reusable workspace.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, data
> layouts, and numerical contracts are unstable and may change incompatibly at
> any time.

## Main types

| Type | Role |
| --- | --- |
| `Residues<S>` | One value represented under an ordered RNS basis |
| `ResidueFactors<S>` | Precomputed multiplication factors for one value under an ordered RNS basis |
| `RNSBase<T, M>` | A non-empty, pairwise-coprime modulus basis and its CRT precomputations |
| `BaseConverter<T, M>` | Precomputed fast or corrected conversion between two RNS bases |
| `ExactConversionContext<T>` | Reusable workspace for corrected batched conversion |
| `HybridRNSPartitioning` | Fixed full-`Q` partition rule shared across modulus-chain levels |
| `HybridRNS<T, M>` | Bases and precomputations for one active hybrid-RNS level |
| `HybridRNSPartition<T, M>` | One contiguous `Q` partition and its approximate ModUp converter |

`T` is an unsigned FHE integer type. `M` is a `primus_reduce::FieldContext<T>`;
[`BarrettModulus`](../primus_modulus/README.md) is the normal context for
repeated polynomial operations.

## Example

`Residues<S>` stores one value as canonical residues in an ordered RNS basis,
with owned or borrowed storage. It does not store or validate the basis.
Single-value decomposition, composition, and fast conversion use this type;
batched layouts and scratch buffers remain slices.

`ResidueFactors<S>` stores one precomputed factor per modulus in basis order.
`decompose_factors` returns this type, and scaled-decomposition APIs accept it.
Each factor must be prepared for its corresponding modulus; the wrapper does not
validate precomputations. Polynomial factor tables and CRT reconstruction weights
remain separate representations.

```rust
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, Residues};

let moduli = [3_u64, 5, 7].map(BarrettModulus::new);
let base = RNSBase::new(&moduli).unwrap();

let value = base.compose(&Residues([2, 4, 6]));
assert_eq!(value.digits(), &[104]);
assert_eq!(base.decompose(value.view()).as_ref(), [2, 4, 6]);
```

`compose` returns the canonical representative in `[0, Q)`, where `Q` is the
product of the basis moduli.

## Layout

Batched residues are always modulus-major. For `k` values and moduli
`q_0, ..., q_(n-1)`, a slice of length `n * k` is arranged as

```text
[a_0 mod q_0, ..., a_(k-1) mod q_0,
 a_0 mod q_1, ..., a_(k-1) mod q_1,
 ...]
```

Batched big integers use the opposite grouping: each value occupies one
contiguous, fixed-width, little-endian limb chunk. The chunk width is
`RNSBase::big_uint_value_len()`.

[`CrtPolynomial`](../primus_poly/README.md) uses the same modulus-major
coefficient layout, so the polynomial wrappers forward directly to the slice
operations without rearranging data.

## RNS bases

`RNSBase::new` clones a non-empty slice of pairwise-coprime moduli;
`from_owned_moduli` avoids that clone. The base precomputes `Q`, every
punctured product `Q / q_i`, and `(Q / q_i)^-1 mod q_i`.

The main operation families are:

- `compose*` and `decompose*` for scalar, batched, and polynomial CRT
  conversion;
- `wrapping_decompose*` for centered lifting from a smaller modulus;
- fused `add_*_decompose_*_scaled_assign` operations for polynomial hot paths;
- `extend` and `extend_with` for appending one modulus or another basis while
  reusing existing CRT precomputations.

Centered small-value decomposition interprets values below `ceil(t / 2)` as
nonnegative and the remaining values as negative representatives modulo `t`.
Modulus `t = 2` is intentionally special: `0` and `1` are preserved directly,
so `1` is not lifted as `-1`.

## Base conversion

`BaseConverter` owns its input and output bases. Use `new` to clone existing
bases or `from_owned_bases` to transfer ownership.

The two conversion families have different mathematical contracts:

- `fast_convert` and `fast_convert_array` compute a SEAL-style approximate CRT
  lift. With a multi-modulus input basis, the result represents `x + kQ` for
  some integer `k`; it is not generally the canonical `x mod p_j`. This is
  suitable only when the surrounding algorithm cancels or accepts the
  multiple-of-`Q` term. A single-modulus input uses exact direct reduction.
- `exact_convert_array` applies a quotient correction, interprets the input
  through its centered representative in `[-Q/2, Q/2)`, and requires exactly
  one output modulus. The name "exact" follows SEAL terminology. The correction
  uses `f64`, so values close to the `-Q/2`/`Q/2` boundary may still be off by
  one multiple of `Q` modulo the output modulus.

Create an `ExactConversionContext` with `exact_conversion_context` and reuse it
with the same converter and polynomial length. Fast conversion instead accepts
a raw scratch slice sized by `fast_convert_scratch_len` or
`fast_convert_array_scratch_len`.

## Hybrid RNS

`HybridRNS` combines a ciphertext basis `Q` with an auxiliary basis `P` and
stores the complete basis in `Q || P` order. `HybridRNSPartitioning` derives a
fixed maximum partition size `alpha` from the full `Q` basis and requested
digit count `dnum`:

```text
alpha = ceil(full_q_moduli_count / dnum)
```

The fixed size must produce exactly `dnum` non-empty partitions. For example,
five `Q` moduli with `dnum = 3` produce ranges `[0..2, 2..4, 4..5]`; requesting
`dnum = 4` is rejected because the same fixed size would produce only three
partitions.

Use `HybridRNS::from_partitioning` at shorter, ordered-prefix levels of the
same modulus chain so key-compatible partition boundaries remain fixed. The
constructor validates the active modulus count; the owning modulus-chain
context is responsible for preserving the prefix relationship.

Each partition supports approximate ModUp into the complete `Q || P` basis.
The streaming variant emits only converted complement limbs so higher-level
key switching can reuse partition limbs in another representation. ModDown
converts the `P` correction into `Q`, subtracts it, and multiplies by
`P^-1 mod q_i`.

## Caller contracts and workspace

- Input residues supplied to arithmetic and base-conversion kernels must be
  canonical for their corresponding moduli unless the method documents a
  wider range.
- Moduli combined in one basis, including `Q || P`, must be pairwise coprime.
- Slice lengths and modulus-major ordering must match the selected base and
  polynomial length exactly.
- Reuse converter contexts and scratch buffers outside hot loops. The batched
  APIs perform no internal allocation once their output and workspace are
  provided.
- Some low-level repeated paths use `debug_assert*!` for shape diagnostics.
  Release callers must establish those invariants at the owning public or
  scheme boundary.

## SIMD feature

The optional `simd` feature enables portable-SIMD small-value and modular
arithmetic paths. It is disabled by default and requires a nightly Rust
toolchain.

```text
cargo +nightly test -p primus_rns --features simd
```

## Testing and benchmarks

```text
cargo test -p primus_rns
cargo bench -p primus_rns --bench decompose
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
or the [MIT License](../../LICENSE-MIT), at your option.
