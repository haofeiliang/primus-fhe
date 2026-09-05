# primus_decompose

English | [简体中文](README.zh_CN.md)

`primus_decompose` provides approximate signed radix decomposition for
[Primus FHE](../../README.md). It separates reusable basis precomputation from
single-value and batched digit extraction, for gadget products and key switching.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API,
> representations, and numerical contracts may change incompatibly.

## Core types

| Type | Role |
| --- | --- |
| `primitive::ApproxSignedBasis<T>` | Single-limb inputs with an explicit modulus or the implicit native modulus `2^T::BITS` |
| `big_integer::BigUintApproxSignedBasis<T>` | Fixed-width, multi-limb inputs with an explicit integer modulus |
| `OnceSignedDecomposer`, `OnceBigUintSignedDecomposer` | Extract one retained level; obtained from the corresponding basis's `decomposer_iter()` |
| `ApproxSignedBasisError` | Invalid construction parameters, returned by `try_new` |

`T: FheUint` is the unsigned coefficient type for the primitive basis and the
limb type for the BigUint basis. `BigUint` comes from
[`primus_integer`](../primus_integer/README.md), not a dynamically sized integer
library. Construct a basis once and reuse its weights and extraction windows.

## Mathematical contract

For `B = 2^log_basis`, `L = decompose_length()` and `d = drop_bits()`, decomposition
produces signed digits with weights:

```text
-B/2 <= digit_i < B/2
weight_i = 2^d * B^i                  (0 <= i < L)
reconstructed = sum(digit_i * weight_i) mod modulus
```

Both `decomposer_iter()` and `scalar_iter()` visit levels from the lowest
retained level to the highest. The circular distance between the input and its
reconstruction is at most `approximate_error_bound()`: zero when `d == 0`,
otherwise `2^(d - 1)`.

Initialization selects the internal representative and initial rounding carry.
Discarded bits are rounded to nearest, with half-way cases rounded up in that
representative. In particular, native inputs recompose to
`round_half_up(input / 2^d) * 2^d` modulo `2^T::BITS`. For other moduli, do not
replace initialization with rounding the canonical input: the representative
adjustment is part of correctness.

The output encoding depends on the operation:

| Operation | Encoding of a mathematical digit `z` |
| --- | --- |
| Primitive `decompose*` | One canonical residue modulo `q`; negative `z` becomes `q + z`, or its native wrapping representation |
| BigUint `decompose*` | A full-width canonical residue modulo `Q`; negative `z` becomes `Q + z` |
| BigUint `unsigned_decompose*` | One limb in `[0, B)` encoding `z mod B`; decode `u >= B/2` as `u - B` |

Despite its name, `unsigned_decompose*` still represents a **signed** digit.
For example, with `B = 256`, output `255` means `-1`, not positive `255`.

## Construction and retained levels

Both bases require `2 <= log_basis < T::BITS` and a modulus at least `B`.
`new` panics on invalid parameters; `try_new` returns `ApproxSignedBasisError`.

The decomposition width `m` differs between representations:

| Basis and modulus | Width `m` |
| --- | --- |
| Primitive, `None` | `T::BITS`, with implicit modulus `2^T::BITS` |
| Primitive, explicit power of two `q` | `log2(q)` |
| Primitive, other explicit `q` | `bit_width(q)` |
| BigUint, any explicit `Q` | `bit_width(Q)`, **including powers of two** |

The full level count is `floor(m / log_basis)`. The constructor argument named
`reverse_length` is an optional **retained level count**, not an iteration
direction: `Some(L)` requires `1 <= L <= full_length`, while `None` uses all
full levels. In both cases, `drop_bits = m - L * log_basis`, so even `None` can
discard low bits when `m` is not divisible by `log_basis`.

A BigUint modulus must have a nonempty little-endian limb slice with a nonzero
most-significant limb. The basis owns a copy. Inputs use exactly that same limb
count, including leading zero limbs when the input value is small.

## Primitive workflow

Initialize a batch once, then pass the same adjusted values and advancing carry
buffer through every level. Consume each level before overwriting its output:

```rust
use primus_decompose::primitive::ApproxSignedBasis;

let basis = ApproxSignedBasis::new(Some(97_u32), 2, None);
let values = [42_u32, 96];
let mut adjusted = [0_u32; 2];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // These small example parameters make the intermediate products fit in u32.
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = (*sum + digit * weight) % 97;
    }
}

assert_eq!(basis.drop_bits(), 1);
assert_eq!(reconstructed, [42, 0]); // Circular errors modulo 97: 0 and 1.
```

Power-of-two inputs need no adjusted-value buffer. Use `init_carry_slice` and
pass the original input to each operator; this is the native Fourier path:

```rust
use primus_decompose::primitive::ApproxSignedBasis;

let basis = ApproxSignedBasis::<u32>::new(None, 8, Some(3));
let values = [0x1234_5678_u32, u32::MAX];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_u32; 2];

basis.init_carry_slice(&values, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.decompose_slice_to(&values, &mut digits, &mut carries);
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        *sum = sum.wrapping_add(digit.wrapping_mul(weight));
    }
}

assert_eq!(reconstructed, [0x1234_5600, 0]);
```

`init_carry_slice` also accepts explicit power-of-two moduli, but panics for
non-power-of-two moduli. Scalar processing uses `init_value_carry` followed by
`decompose` or `decompose_to`, forwarding the carry in the same way.

## BigUint workflow and layout

For `N` values and `W = big_uint_value_len()` limbs per value, full-width buffers
contain `N * W` limbs in **value-major**, little-endian order:

```text
[value_0_low, ..., value_0_high, value_1_low, ..., value_1_high, ...]
```

Carry buffers contain `N` booleans. Full-width digit outputs contain `N * W`
limbs; compact `unsigned_decompose_slice_to` outputs contain only `N` limbs.
BigUint initialization is required even when `Q` is a power of two.

```rust
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::BigUint;

let modulus = [1_u32, 1]; // Q = 2^32 + 1, little-endian limbs.
let basis = BigUintApproxSignedBasis::new(BigUint(&modulus[..]), 8, None);
let values = [42_u32, 0, u32::MAX, 0]; // Two values: 42 and Q - 2.
let mut adjusted = [0_u32; 4];
let mut carries = [false; 2];
let mut digits = [0_u32; 2];
let mut reconstructed = [0_i64; 2];

basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
for (decomposer, weight) in basis.decomposer_iter().zip(basis.scalar_iter()) {
    decomposer.unsigned_decompose_slice_to(&adjusted, &mut digits, &mut carries);
    // Convert the full-width weight and compact digits for this small example.
    let weight = i64::from(weight[0]) + (i64::from(weight[1]) << 32);
    for (sum, &digit) in reconstructed.iter_mut().zip(&digits) {
        let signed = if digit < 128 {
            i64::from(digit)
        } else {
            i64::from(digit) - 256
        };
        *sum += signed * weight;
    }
}

assert_eq!(reconstructed, [42, -2]); // -2 represents Q - 2 modulo Q.
```

This crate does not depend on `primus_rns`. RNS/CRT conversion belongs to
[`primus_rns`](../primus_rns/README.md); its residue batches are modulus-major,
not the value-major layout above. `CrtGlevParameters` in `primus_glwe_rns`
precomputes reconstruction weights modulo each RNS modulus and exposes them
through `scalar_residue_iter()`. They are separate from this basis's full-width
integer weights.

## Caller contracts and allocation

- Original inputs must be canonical: `[0, q)` or `[0, Q)`. Every bit pattern is
  valid for the primitive native modulus. These methods do not reduce inputs.
- Adjusted inputs are internal bit representations, not necessarily canonical
  residues. Keep them unchanged throughout decomposition; do not reduce them.
- Apply every operator in ascending level order, without skipping levels or
  resetting carry. A zero digit can still produce a carry. Start each new input
  batch with initialization, not with the previous batch's final carries.
- Primitive value, output and carry slices must have equal lengths. BigUint
  buffers must follow the exact shapes above. Shape checks in these repeated
  paths are debug diagnostics, not release-mode input validation.
- Slice methods overwrite outputs and update carries; they do not accumulate
  digits. `init_value_carry_slice_assign` also overwrites the original values.
- Constructors allocate precomputation storage. Slice and caller-output methods
  do not allocate internally. BigUint `init_value_carry`, `decompose`, and
  `approximate_error_bound` return newly allocated vectors or big integers;
  prefer reusable buffers and the `_to`/slice methods in repeated paths.

## Features and validation

The default feature set is empty. The optional `simd` feature forwards to
`primus_integer/simd` and requires nightly Rust. It does not select a separate
decomposition backend; the loops can also benefit from compiler auto-vectorization.

```text
cargo test -p primus_decompose
cargo bench -p primus_decompose --bench decompose
cargo +nightly test -p primus_decompose --features simd
```

The benchmarks separate basis construction from online scalar and batch
decomposition, including primitive no-copy/adjusted paths and full-width/compact
BigUint outputs. Workspace builds already use `target-cpu=native` via
[`.cargo/config.toml`](../../.cargo/config.toml).

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
or the [MIT License](../../LICENSE-MIT), at your option.
