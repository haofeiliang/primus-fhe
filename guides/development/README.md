# Library usage guide

English | [简体中文](README.zh_CN.md)

Use this guide when composing or extending workspace libraries. It points to existing APIs and their boundaries; detailed contracts belong in rustdoc. Start with the [workspace map](../../README.md#workspace-map) for crate responsibilities and the [testing guide](testing.md) for validation commands.

## Choose the arithmetic domain

Choose the modulus before choosing a transform or decomposition basis. The implementations are in [primus_modulus](../../crates/primus_modulus/src/lib.rs); arithmetic capability traits are in [primus_reduce](../../crates/primus_reduce/src/lib.rs).

| Domain | Modulus type | Constraint |
| --- | --- | --- |
| Implicit `2^BITS` | `NativeModulus<T>` | Word wrapping, no representable modulus value |
| Explicit `2^b` | `PowOf2Modulus<T>` | `1 <= b < T::BITS`; for example `PowOf2Modulus::new(1u64 << 24)` |
| Repeated multiplication under an explicit modulus | `BarrettModulus<T>` | `1 < q < 2^(BITS-2)`; NTT also requires its own prime/root conditions |
| Bounded basic arithmetic | `CompactModulus<T>` | The same two spare high bits; without Barrett precomputation |
| General representable modulus | `UintModulus<T>` | `q > 1`; not a substitute for a transform's stronger contract |

`RingContext` / `FieldContext` express available arithmetic, not a proof of primality or invertibility. For NTT, read the [root and range requirements](../../crates/primus_ntt/README.md#construction-constraints). For gadget operations, use [primus_decompose](../../crates/primus_decompose/README.md) and the caller's basis order. Decomposition, normalization and lazy ranges are numerical contracts, not properties inferred from a buffer's type.

## Select storage and establish the layout

[primus_data](../../crates/primus_data/src/traits.rs) separates element type (`RawData`), read access (`Data`), mutation (`DataMut`) and owned construction (`DataOwned`). `Polynomial<S>` and ciphertext wrappers use these traits so the same operation can work with owned buffers or borrowed slices.

`Polynomial::new(storage.as_slice())` borrows; `Polynomial::new(storage.as_mut_slice())` borrows mutably. These wrappers do not clone or transform the elements. `Polynomial::new(storage)` moves the container. A consuming arithmetic method on a mutable view can still modify the caller's storage; choose `*_assign` when that effect should be explicit, and `*_to` for reusable output storage.

Raw polynomial/ciphertext constructors do not establish modulus, key identity, representation or full layout. `Polynomial<S>` does not carry an independent ring length: wrapping `batch_count*N` elements does not automatically turn single-polynomial operations into batch operations. Only pass such storage to an API whose contract explicitly accepts a batch; otherwise iterate over complete objects.

Use the existing [size descriptors](../../crates/primus_lattice/src/size.rs) for GLWE layouts:

| Descriptor | Describes |
| --- | --- |
| `GlweSize` | `k` mask polynomials and one body; `glwe_len() = (k+1)*N` |
| `GadgetSize` | L levels per GLev, k+1 GLev rows per GGSW |
| `RnsGlweSize` | GLWE with an explicit RNS modulus count |
| `RnsGadgetSize` | Gadget levels and rows over that RNS layout |

Descriptors check supported dimensions and flattened-length overflow. They do not inspect storage or validate basis, tables or noise. Compare the complete buffer length with the derived length at the owning public boundary. For NTRU, one Ntru occupies N values and one Nlev/Ngsw occupies L*N; use the operation's parameters/basis and checked batch lengths. Nlev and Ngsw have the same flat shape but different encrypted phases and valid products.

## Traverse mathematical objects

Use semantic iterators when a chunk is one complete polynomial or ciphertext. Their `new(data, object_len)` arguments are **stored element counts**, not dimensions, levels or bytes. Mutable variants end in `IterMut`; child methods have an `_mut` variant. Scalar weights, indices and batches without a matching object type still use ordinary slice iteration or `chunks_exact(_mut)`.

| Objects | Batch iterator / child traversal | Length of one child |
| --- | --- | --- |
| Coefficient polynomials | `PolynomialIter`, `PolynomialIterMut` | N coefficients |
| NTT polynomials | `NttPolynomialIter`, `NttPolynomialIterMut` | N ring values |
| Fourier polynomials | `FourierPolynomialIter`, `FourierPolynomialIterMut` | N/2 complex values |
| CRT/DCRT polynomials | `CrtPolynomialIter`, `DcrtPolynomialIter` and mutable variants | modulus_count*N values |
| NTRU family | `NtruIter`, `NlevIter`, `NgswIter` and mutable variants; `Nlev::iter_ntru(N)`, `Ngsw::iter_ntru(N)` | N per Ntru; L*N per Nlev/Ngsw |
| GLWE family | `GlweIter`, `GlevIter`, `GgswIter` and mutable variants | `GlweSize` / `GadgetSize` lengths |
| GGSW → GLev → GLWE → polynomial | `iter_glev(glev_len)`, `iter_glwe(glwe_len)`, `iter_poly(N)` | row → level → component |
| GLWE mask/body | `a_b(N)`, `a_b_mut(N)` | mask polynomial iterator plus one body polynomial |

The [polynomial exports](../../crates/primus_poly/src/lib.rs), [ciphertext modules](../../crates/primus_lattice/src/lib.rs) and [iterator generation](../../crates/primus_lattice/src/macros/iter.rs) locate these interfaces. NTT ciphertexts use prefixed types such as `NttNgswIter`, with `iter_ntt_ntru`, `iter_ntt_glev`, `iter_ntt_glwe` and `iter_ntt_poly`. Fourier types use `FourierNgswIter` and similar names, but their child methods are `iter_ntru`, `iter_glev`, `iter_glwe` and `iter_fourier_poly`; each child length counts complex values. Use `fourier_*_len()` from GLWE size descriptors where available.

These iterators omit incomplete trailing chunks; `zip` stops at the shorter input. Validate full lengths and paired counts once before constructing them. Iterator count or absence of a panic does not prove layout validity.

### Batch polynomial operation

This complete fragment multiplies two polynomials by X in `Z_256[X]/(X^4+1)`. It needs `primus_modulus` and `primus_poly`. The small ring is an arithmetic example, not an encryption parameter set.

```rust
use primus_modulus::PowOf2Modulus;
use primus_poly::{PolynomialIter, PolynomialIterMut};

let n = 4;
let modulus = PowOf2Modulus::new(256u32);
let input = [1u32, 2, 3, 4, 5, 6, 7, 8];
let mut output = [0u32; 8];

assert_eq!(input.len() % n, 0);
assert_eq!(output.len(), input.len());
for (input, mut output) in PolynomialIter::new(&input, n)
    .zip(PolynomialIterMut::new(&mut output, n))
{
    input.mul_monomial_to(1, &mut output, modulus);
}
assert_eq!(output, [252, 1, 2, 3, 248, 5, 6, 7]);
```

### Gadget layout and borrowed views

This fragment needs `primus_lattice`. It walks the rows and levels of one GGSW and separates each GLWE's mask/body. The zero buffer demonstrates layout access; it does not sample an encryption. Each child is a borrowed view, with no allocation in the traversal.

```rust
use primus_lattice::{GadgetSize, GlweSize, ggsw::Ggsw};

let glwe_size = GlweSize::new(2, 8);
let gadget_size = GadgetSize::new(glwe_size, 3);
let storage = vec![0u32; gadget_size.ggsw_len()];

assert_eq!(storage.len(), gadget_size.ggsw_len());
let ggsw = Ggsw::new(storage.as_slice());
let mut level_count = 0;
for row in ggsw.iter_glev(gadget_size.glev_len()) {
    for level in row.iter_glwe(glwe_size.glwe_len()) {
        let (mask, body) = level.a_b(glwe_size.poly_length());
        assert_eq!(mask.len(), glwe_size.dimension());
        assert_eq!(body.poly_length(), glwe_size.poly_length());
        level_count += 1;
    }
}
assert_eq!(level_count, 9); // (k+1) rows * L levels
```

## Keep transform representations explicit

| Representation | Entry point | Reuse and compatibility |
| --- | --- | --- |
| Coefficients ↔ NTT | [NttTable](../../crates/primus_ntt/README.md#representation-and-ranges), `transform_inplace` / `inverse_transform_inplace`; ciphertext `into_ntt_form` / `write_ntt_form` | Reuse a table for the same N, modulus and transform convention. Check canonical/lazy ranges independently of storage length. |
| Coefficients ↔ Fourier | [FftTable / FftEngine](../../crates/primus_fft/README.md#transform-variants) | Reuse the originating table instance and its workspace. Ciphertexts use normalized torus scale; small integer factors use integer scale. |
| CRT ↔ DCRT | [DcrtTable](../../crates/primus_ntt/README.md#dcrt-layout), [RNS operations](../../crates/primus_rns/README.md) | Preserve modulus order and modulus-major N-value blocks. |

Constructing a different wrapper or iterator does not perform a transform. Fourier values occupy N/2 complex slots and are approximate; arbitrary FFT tables with the same N are not interchangeable. Parallel workers may share an immutable table but each needs its own mutable workspace.

## Compose an encrypted workflow

The [TFHE parameter and boundary guide](tfhe-parameters-and-boundaries.md) maps q/Q, secret domains, PBS/CBS/MVB/one-hot/lookup paths and construction error ownership.

Choose the lowest layer that owns the operation. [LWE](../../crates/primus_lwe/README.md), [GLWE](../../crates/primus_glwe/README.md), [NTRU](../../crates/primus_ntru/README.md) and [RNS GLWE](../../crates/primus_glwe_rns/src/lib.rs) provide encryption, keys and evaluation primitives. [Shared TFHE](../../crates/primus_tfhe/README.md) provides LWE clients, encodings, LUT geometry and common evaluation interfaces; the [GLWE](../../crates/primus_tfhe_glwe/README.md) and [NTRU](../../crates/primus_tfhe_ntru/README.md) families define their own parameter and key contracts.

Follow a backend example in order: parameters → validated context/table → client/server keys → public LUT → evaluator and output allocation → repeated `*_to` evaluation → client decryption. The four concrete starting points are [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_basic.rs), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs) and [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_basic.rs). Parameters are functional fixtures; choose and validate them for the intended operation.

NTRU separates the external LWE secret/modulus/dimension from the accumulator's NTRU secret/modulus/length. GLWE's PBS order has its own input/output domain contract. Matching buffer dimensions alone does not make keys interchangeable. Keep the backend's parameter checks and caller-maintained secret/table identity requirements visible.

For high-precision functions over encrypted chunks, use [primus_tfhe_ntru_lut](../../crates/primus_tfhe_ntru_lut/README.md). One-hot CBS belongs to the NTRU backends; table partitioning, selection and rotation belong to the lookup crate. Its evaluator borrows context, server key and compiled LUT and owns reusable buffers. Allocate outputs once and reuse `evaluate_to`; do not reconstruct keys or tables inside the online loop.

## Preserve error roles and causes

Define error types around public operations and their contracts. Retain distinct causes that help callers diagnose or handle a failure; split or merge types only when real consumers benefit. Share identical lower-level checks while preserving each scheme's geometry and representation requirements.

Context-bearing wrappers describe their own role in `Display` and expose the underlying cause through `std::error::Error::source()`. Error reporters should follow that chain; formatting the source in every wrapper duplicates messages. Transparent wrappers delegate both methods. Use `From` only when the source has one destination role; otherwise map it explicitly. For parameter construction, `SecretKeySamplerError` covers secret preparation, weights and modulus fit, while `GaussianError` is shared by Gaussian implementations. Trait derives follow the stored data; floating-point causes do not implement `Eq`.

## Distinguish environment from workspace

The naming rule follows responsibility. Existing APIs have not all adopted it; the current names below locate the implementation without introducing compatibility aliases.

| Responsibility | Naming rule | Current entry point |
| --- | --- | --- |
| A group of reusable temporary buffers with shape invariants | `*Workspace` | [Ntt/FourierNtruExternalProductContext](../../crates/primus_lattice/src/context/ntru_external_product.rs), [NtruLweKeySwitchingContext](../../crates/primus_ntru/src/key_switch/lwe.rs) currently retain `Context` names |
| Owned FFT temporary buffers | `*Workspace` as well | [FftTable::Scratch / new_scratch and FftEngine](../../crates/primus_fft/src/table.rs) use the current `Scratch` vocabulary |
| Validated parameters, modulus and transform environment | `*Context` | [TfheContext](../../crates/primus_tfhe_ntru_ntt/src/context.rs); arithmetic `RingContext` / `FieldContext` remain capability traits |
| Bound execution with keys/tables and mutable workspace | `*Evaluator` / `*Engine` | TFHE evaluators and `FftEngine`; classify mixed state by its actual responsibility |
| One borrowed temporary slice or region | Local `scratch` / `buffer` | No extra wrapper required; third-party `PodBuffer` / `PodStack` retain their names |

A workspace with the right length does not prove basis, modulus, table or key compatibility. Construct reusable buffers before the repeated operation, preserve the API's overwrite/accumulate rules, and document when a borrowed workspace or caller-owned accumulator must be restored. Secret-key erasure and workspace erasure may have different postconditions; read each type's `zeroize` contract before reuse.

## Choose owned containers by their consumers

Reuse, fixed length and extra alignment are separate decisions. Apply this matrix to actual coefficient arrays, including key data, rather than mechanically changing every `Vec`.

| Data and lifetime | Candidate storage |
| --- | --- |
| Fixed length, hot numeric data with required or measured alignment benefit | `ABox<[T]>`; elements remain mutable |
| Growth is required and extra alignment is useful | `AVec<T>`; inspect copying/reallocation when converting to fixed storage |
| Fixed length, no extra alignment requirement | `Box<[T]>`, or `Vec<T>` for a concrete construction/reuse need |
| Dynamic metadata, indices, small controls or object descriptors | Ordinary `Vec`, arrays or boxes |
| Backend-specific temporary memory | Preserve the backend's allocation, capacity and borrowing contract |

With `primus_data/aligned-vec`, [AVec and ABox implement RawData/Data/DataMut](../../crates/primus_data/src/impls.rs), **not DataOwned**. That trait also requires iterator construction/consumption, and aligned allocation has its own alignment choice. Allocate the container explicitly, wrap it with `new`, and use `DataMut` operations where supported; do not assume a `DataOwned` constructor such as `Polynomial::zero` accepts an aligned destination.

An aligned allocation does not guarantee aligned sub-blocks: check the actual stride, especially LWE rows of n+1 values. Aligning `Vec<Key>` does not align each key's internal coefficients. Before changing storage, inspect the consuming kernel and measure the affected workload, construction/conversion costs and memory use; preserve secret erasure and ownership contracts. Alignment alone is not evidence of a speedup.

## Validate the relevant contract

Follow [AGENTS.md](../../AGENTS.md) and the [testing guide](testing.md). Ordinary tests, including encrypted end-to-end cases, favor small parameters that preserve the intended contract; keep larger cases only where their path or regression requires them. Compile/lint all targets, execute lib/tests separately from doctests, and run selected Criterion smoke fixtures separately from both ordinary tests and performance sampling.
