# Library usage guide

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

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

`Polynomial::new(storage)` moves the container. For an existing polynomial or ciphertext, `as_view()` / `as_mut_view()` borrow its storage while preserving its representation; the corresponding `From` conversions do the same. `into_inner()` returns the original container or borrow without copying. These operations do not transform or validate elements. A consuming arithmetic method on a mutable view can still modify the caller's storage; choose `*_assign` when that effect should be explicit, and `*_to` for reusable output storage.

When implementing a long algorithm, keep container flexibility at the public boundary through `Data` / `DataMut`, then pass borrowed views such as `Glwe<&[T]>` and `Glwe<&mut [T]>` into the internal kernel. Convert a storage-generic key receiver through `as_view()` as well. This keeps the algorithm independent of the owning container while retaining the numeric type, modulus and transform generics needed for specialization. Code that owns or swaps reusable buffers continues to operate on those owners.

Each public boundary checks the contract it owns: parameters and tables establish numerical domains, resource binding checks compatibility, and single/batch entry points validate complete layouts. Private kernels rely on those invariants rather than repeating validation at every layer. Views remove storage ownership generics, not checks; validate owners before taking views that erase modulus or other metadata. Each operation’s rustdoc specifies actual panics, unchecked preconditions and possible partial writes.

Public `try_from_parts` constructors validate the pairing of independently supplied components. Internal construction and derivation reuse pairings established by the same source owner, without rechecking unchanged state; new bases, composed lengths and codec/noise recovery conditions remain checked. A `ServerKey` does not prove compatibility with a separately supplied context: resource binding must still validate that combination.

Raw polynomial/ciphertext constructors do not establish modulus, key identity, representation or full layout. `Polynomial<S>` does not carry an independent ring length: wrapping `batch_count*N` elements does not automatically turn single-polynomial operations into batch operations. Only pass such storage to an API whose contract explicitly accepts a batch; otherwise iterate over complete objects.

Raw coefficient, NTT, Fourier and CRT/DCRT polynomials expose `len()` / `is_empty()` for their storage elements. Those counts are distinct from a checked table or size's `poly_length()` (`N`), Fourier table `fourier_length()` (`N/2`), and DCRT table `rns_poly_len()` (`moduli_count*N`). DCRT table construction rejects empty modulus lists. Transform callers must supply the complete layout in the table's modulus order; existing debug diagnostics do not establish a release rejection guarantee. Raw wrappers still allow empty and packed storage.

[PolyLength](../../crates/primus_poly/src/poly_length.rs) belongs to `primus_poly` and centrally checks the shared FHE power-of-two range `32..=2^17`. `get()`, `log_n()` and `fourier_poly_len()` return `N`, `log2(N)` and `N/2` complex elements. GLWE/NTRU parameters, checked sizes, workspaces, shared TFHE LUTs and NTT/FFT tables pass the same type directly without repeating the upper-bound check.

This range guarantees that `2N` fits in `usize`; combined storage lengths remain checked by the boundary owning the layout. FFT construction directly accepts the supported range; NTT retains its modulus, root and degree conditions. Both TFHE families' `BlindRotationConfig::acc_poly_length` take `PolyLength`; raw buffers, batch counts and numerical kernels use integers and rely on their caller layout contracts.

`LweDimension` and `GlweDimension` from lattice check positive mask counts and representable body-inclusive counts; `ciphertext_len()` gives `n+1` and `component_count()` gives `k+1`. `GlweSize` stores GLWE geometry and flattened lengths; `LweDimension::from(glwe_size)` explicitly derives checked `kN`. NTRU extraction uses `LweDimension::from(poly_length)`. Raw slices keep integer dimensions and may have dimension zero.

`DecompositionBaseLog` and `DecompositionLevelCount` from decompose establish `log_basis >= 2` and `L >= 1`. Basis construction checks word/modulus limits and their pairing, without preset caps. Checked parameters, layouts and workspaces pass these units directly; unwrap once at numerical or storage boundaries. Composed lengths still require checks at the boundary owning the layout.

Bit widths and bit counts use `u32`, matching `T::BITS` and `leading_zeros` / `trailing_zeros`. Element/byte counts, dimensions, decomposition levels, limb counts, chunk counts, array indices and ring monomial exponents keep `usize` or their existing semantic types. Index-derived offsets and loop counters may remain `usize` when used in shifts; do not cast them solely to change the shift operand type. Convert where mixed-type arithmetic or an API requires it. SIMD shift operands and third-party intrinsic immediates retain the representations required by their APIs.

Use the existing [size descriptors](../../crates/primus_lattice/src/size.rs) for GLWE layouts:

| Descriptor | Describes |
| --- | --- |
| `GlweSize` | `k` mask polynomials and one body; `glwe_len() = (k+1)*N` |
| `GadgetSize` | L levels per GLev, k+1 GLev rows per GGSW |
| `RnsGlweSize` | GLWE with an explicit RNS modulus count |
| `RnsGadgetSize` | Gadget levels and rows over that RNS layout |

Descriptors check composed lengths and flattened-length overflow. They do not inspect storage or validate basis, tables or noise. Establish each resource's layout at its owning construction or binding boundary; numerical kernels rely on caller geometry and representation. For NTRU, one Ntru occupies N values and one Nlev/Ngsw occupies L*N; use the operation's parameters/basis and establish batch lengths where storage is prepared. Nlev and Ngsw have the same flat shape but different encrypted phases and valid products.

Owning LWE secrets record the coefficient domain as `q - 1`, including Native. Import with `LweSecretKey::new(coefficients, distribution, modulus)`; coefficient canonicality and the declared distribution remain import preconditions. Validate an owner's domain before converting it with `as_view()`: raw encoded/signed views have no modulus metadata. TFHE family binding, LWE key-switch output-key generation and GLWE bootstrapping input-key generation perform this check before sampling. Metadata does not identify a particular secret. Explicitly zeroized keys must be discarded even though their public metadata remains.

Owning `NttGlweSecretKey` records explicit q on import/conversion and checks it with the parameter modulus and table at ordinary, coefficient, truncated and gadget boundaries. Key-switch, automorphism, trace, scheme-switch and TFHE bootstrapping generation inherit the gadget check; inner kernels do not repeat it. `cipher_modulus()` exposes q for consumers that still hold the owner. Raw polynomial iterators carry no domain metadata; equal q/N cannot prove NTT roots/order or secret identity. Import and erased-key contracts are in the [GLWE README](../../crates/primus_glwe/README.md).

Owning `NttNtruSecretKey` likewise records explicit q for both `NTT(f)` and its inverse. Conversion/generation uses one validated modulus/table; ordinary, phase and gadget boundaries check the owner domain, and evaluation-key generation inherits those checks. NTRU imports a signed coefficient key and computes the inverse rather than accepting a raw NTT pair. Unlike raw LWE/NTT GLWE imports, conversion checks invertibility; the signed-magnitude bound remains the caller’s responsibility. All three owning secret types must be discarded after explicit erasure; public domain metadata is not a live-key marker. See the [NTRU README](../../crates/primus_ntru/README.md).

LWE key generation takes `LweEncryptionParameters`, which owns dimension, modulus and prepared samplers without encoding. Ordinary `LweParameters` adds a Rounded codec and exposes `encryption_parameters()` / `into_encryption_parameters()`. GLWE TFHE builds from the core and GGSW parameters, then binds codecs at clients/program compilers; see the [parameter ownership map](tfhe-parameters-and-boundaries.md).

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
use primus_lattice::{GadgetSize, GlweDimension, GlweSize, ggsw::Ggsw};
use primus_poly::PolyLength;
use primus_decompose::DecompositionLevelCount;

let poly_length = PolyLength::new(32);
let glwe_size = GlweSize::new(GlweDimension::new(2), poly_length);
let gadget_size = GadgetSize::new(glwe_size, DecompositionLevelCount::new(3));
let storage = vec![0u32; gadget_size.ggsw_len()];

assert_eq!(storage.len(), gadget_size.ggsw_len());
let ggsw = Ggsw::new(storage.as_slice());
let mut level_count = 0;
for row in ggsw.iter_glev(gadget_size.glev_len()) {
    for level in row.iter_glwe(glwe_size.glwe_len()) {
        let (mask, body) = level.a_b(glwe_size.poly_length().get());
        assert_eq!(mask.len(), glwe_size.dimension().get());
        assert_eq!(body.len(), glwe_size.poly_length().get());
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

### Lattice implementation boundaries

Within each ciphertext family, `coeff.rs` owns coefficient storage and arithmetic.
The `ntt.rs`, `fourier.rs`, and `dcrt.rs` modules own their representations and
both conversion directions, including inherent methods on coefficient types.
External products, CMux, and fused lifting live in the corresponding representation's
subdirectory. Public type paths and inherent methods are exported by the family module;
callers do not need extension traits.

| Implementation | Source entry |
| --- | --- |
| GGSW products and CMux | [NTT](../../crates/primus_lattice/src/ggsw/ntt.rs), [Fourier](../../crates/primus_lattice/src/ggsw/fourier.rs), [DCRT products](../../crates/primus_lattice/src/ggsw/dcrt/external_product.rs) |
| Shared NLev/NGSW gadget kernels | [NTT](../../crates/primus_lattice/src/ntru/ntt/gadget_product.rs), [Fourier](../../crates/primus_lattice/src/ntru/fourier/gadget_product.rs) |
| Workspace owners and internal views | [NTT](../../crates/primus_lattice/src/workspace/ntt.rs), [Fourier](../../crates/primus_lattice/src/workspace/fourier.rs), [DCRT](../../crates/primus_lattice/src/workspace/dcrt_glev_mul.rs) |

Keep backend-specific code within these modules. Lattice and GLWE/NTRU default to coefficient capabilities; `ntt` / `fourier` explicitly enable representations, operations and dependencies. `rustfft` / `tfhe-fft` also enable Fourier and the selected engine, as described in the [FFT guide](../../crates/primus_fft/README.md#features). `rns` includes the NTT capability required by DCRT; `simd` only propagates to active dependencies.

Pure LWE and both TFHE families need no transform. Concrete TFHE backends select their capability on normal dependencies. RNS GLWE selects lattice’s `rns` and reuses only the coefficient secret from single-modulus GLWE. Each direct consumer declares the features its APIs need, without relying on incidental workspace or test-dependency unification.
Current feature availability is documented in the [lattice README](../../crates/primus_lattice/README.md#features).

## Compose an encrypted workflow

Keep messages, encoded plaintexts and extracted coefficient phases distinct.
Encoding chooses the codec and embedding; encryption adds noise to encoded
data; phase extraction does not decode. For diagnostics, compare the extracted
phase to the encoded **expected message** with
[`phase_error_magnitude` / `phase_error_magnitude_slice_to`](../../crates/primus_encoding/README.md#phase-error-diagnostics).
Do not substitute a re-encoded decoded value or analyze NTT/Fourier storage
as coefficient phases. Message recovery and phase-error magnitude answer
different questions. LWE, single-modulus GLWE and NTRU expose these roles as
`encrypt_message*` / `decrypt_message*`, `encrypt_encoded*`, and `decrypt_phase*`;
message encryption always selects `PlaintextEmbedding` explicitly. LWE independent `*_batch` samples
and shared-mask `*_packed` samples have distinct layouts; see the
[LWE workflow](../../crates/primus_lwe/README.md#independent-batches-and-packed-messages).

The [TFHE parameter and boundary guide](tfhe-parameters-and-boundaries.md) maps q/Q, secret domains, PBS/CBS/MVB/one-hot/lookup paths and construction error ownership. The [parameter matrix](tfhe-parameters.md) records actual key/message profiles, operation conditions, key reuse, evidence gaps and the opt-in numerical validator. These are arithmetic fixtures with unassessed security and failure probability; ordinary tests keep small parameters.

Choose the lowest layer that owns the operation. The quick starts below cover message encryption/decryption and encoded/phase primitives without requiring gadget or TFHE setup.

| Task | Shortest entry point | Further use |
| --- | --- | --- |
| Standalone LWE | [Quick start](../../crates/primus_lwe/README.md#quick-start) | [Public-key/batch/key-switch example](../../crates/primus_lwe/examples/basic.rs), [packed layout](../../crates/primus_lwe/README.md#independent-batches-and-packed-messages) |
| Single-modulus GLWE | [Quick start](../../crates/primus_glwe/README.md#quick-start) | [NTT/Fourier workspaces and coefficient paths](../../crates/primus_glwe/README.md#encryption-and-decryption) |
| NTRU | [Quick start](../../crates/primus_ntru/README.md#quick-start) | [Automorphism example](../../crates/primus_ntru/examples/automorphism.rs), [independent LWE return](../../crates/primus_ntru/README.md#independent-lwe-return) |
| TFHE PBS/ManyLUT | [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_basic.rs), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs), [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_basic.rs) | [sparse/CBS/one-hot/MVB support and examples](../../crates/primus_tfhe/README.md#crate-map-and-capabilities) |
| High-precision chunk lookup | [NTT](../../crates/primus_tfhe_ntru_lut/examples/ntt_lookup.rs), [Fourier](../../crates/primus_tfhe_ntru_lut/examples/fourier_lookup.rs) | [sparse/public-lift and evaluator binding](../../crates/primus_tfhe_ntru_lut/README.md#evaluation-and-workspace) |

TFHE examples fix u64 and follow parameters → context/table → client/server keys → public LUT → evaluator and output allocation → repeated `*_to` evaluation → client decryption. Parameters are functional fixtures; choose and validate them for the intended operation. Both parties may hold public contexts/codecs/LUTs; the client supplies evaluation keys, request ciphertexts and any required public lift, while the server constructs and reuses evaluators and outputs without the client secret.

NTRU separates the external LWE secret/modulus/dimension from the accumulator's NTRU secret/modulus/length. GLWE's PBS order has its own input/output domain contract. Matching buffer dimensions alone does not make keys interchangeable. Keep the backend's parameter checks and caller-maintained secret/table identity requirements visible.

For high-precision functions over encrypted chunks, use [primus_tfhe_ntru_lut](../../crates/primus_tfhe_ntru_lut/README.md). One-hot CBS belongs to the NTRU backends; table partitioning, selection and rotation belong to the lookup crate. Its evaluator borrows context, server key and compiled LUT and owns reusable buffers. Allocate outputs once and reuse `evaluate_to`; do not reconstruct keys or tables inside the online loop. Public compilation takes PolyLength, accumulator Q, an input codec and chunk configuration, without encryption parameters, keys or transform dependencies. `stats()` and partial workspace estimates help compare partitions; `ntt` / `fourier` select an evaluator, and `rustfft` / `tfhe-fft` also select Fourier and a concrete engine.

For RNS GLWE, ordinary secret/public keys use `try_bind(parameters, table)` and gadget encryption uses `try_bind_gadget(domain)`. These contexts borrow checked resources. Key-switch, automorphism, trace and expansion evaluators borrow a key/domain and own workspace, checking ordered bases and decomposition/partition compatibility once before online calls. Parallel expansion owns its preallocated pool and requires an exclusive evaluator borrow. See the [RNS GLWE workflow](../../crates/primus_glwe_rns/README.md#evaluation-resources).

GLWE parameters separate [shared modulus/sampling state](../../crates/primus_glwe/src/parameter/core.rs), [ordinary layout/encoding](../../crates/primus_glwe/src/parameter/ordinary.rs), [gadget basis](../../crates/primus_glwe/src/parameter/gadget.rs) and [key-switch layouts](../../crates/primus_glwe/src/parameter/key_switch.rs). [RNS parameters](../../crates/primus_glwe_rns/src/parameter/mod.rs) use the same roles while retaining RNS-specific contracts. The [DCRT secret modules](../../crates/primus_glwe_rns/src/secret_key/dcrt/mod.rs) separate ownership/binding, signed conversion, ordinary encryption, gadget encryption, decryption and erasing scratch. Private numerical helpers live with their bound operation; public types remain exported at the crate root.

## Preserve error roles and causes

Define error types around public operations and their contracts. Retain distinct causes that help callers diagnose or handle a failure; split or merge types only when real consumers benefit. Share identical lower-level checks while preserving each scheme's geometry and representation requirements.

Context-bearing wrappers describe their own role in `Display` and expose the underlying cause through `std::error::Error::source()`. Error reporters should follow that chain; formatting the source in every wrapper duplicates messages. Transparent wrappers delegate both methods. Use `From` only when the source has one destination role; otherwise map it explicitly. For parameter construction, `SecretKeySamplerError` covers secret preparation, weights and modulus fit, while `GaussianError` is shared by Gaussian implementations. Trait derives follow the stored data; floating-point causes do not implement `Eq`.

## Distinguish environment from workspace

Names distinguish reusable storage (`Workspace`), validated environments (`Context`), bound common resources (`Resources`) and specific execution workflows (`Evaluator` / `Engine`).

| Responsibility | Naming rule | Current entry point |
| --- | --- | --- |
| A group of reusable temporary buffers with shape invariants | `*Workspace` | [Ntt/FourierNtruExternalProductWorkspace](../../crates/primus_lattice/src/workspace/mod.rs), [NtruLweKeySwitchingWorkspace](../../crates/primus_ntru/src/key_switch/lwe.rs) |
| Owned FFT temporary buffers | `*Workspace` as well | [FftTable::Workspace / new_workspace and FftEngine](../../crates/primus_fft/src/table.rs) |
| Validated parameters, modulus and transform environment | `*Context` | [TfheContext](../../crates/primus_tfhe_ntru_ntt/src/context.rs); arithmetic `RingContext` / `FieldContext` remain capability traits |
| Borrowed environment/evaluation material paired with owned reusable buffers | `*Resources` | Four TFHE backends’ `BootstrapResources`; internal KS/BR resource sets |
| A specific execution workflow using owned or briefly borrowed resources | `*Evaluator` / `*Engine` | PBS, CBS, one-hot and MVB evaluators; `FftEngine` |
| One borrowed temporary slice or region | Local `scratch` / `buffer` | No extra wrapper required; third-party `PodBuffer` / `PodStack` retain their names |

Resources borrow context/key owners; they own only their prepared buffers and, in Fourier backends, the FFT engine borrowing the context’s table. Serial PBS/MVB/CBS/one-hot operations can lend common resources to each other; concurrent workers normally need separate mutable instances. GLWE `KeySwitchingResources` binds a ring KS key to its lower-level workspace and switched output. NTRU `BlindRotationResources` binds classic controls or a sparse key to the selected BR buffers; their external-product workspaces remain pure storage. These internal combinations use `Resources` without introducing another public wrapper. A buffer helper does not itself require an `Evaluator` name. See [TFHE resource composition](tfhe-parameters-and-boundaries.md#输入盲旋转与返回组合).

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

With `primus_data/aligned-vec`, [AVec and ABox implement RawData/Data/DataMut](../../crates/primus_data/src/impls.rs), **not DataOwned**. Construction of aligned storage needs an explicit alignment choice; `DataOwned` does not provide one. Iterator construction/consumption are separate `FromIterator` / `IntoIterator` capabilities. Allocate the container explicitly, wrap it with `new`, and use `DataMut` operations where supported; do not assume a `DataOwned` constructor such as `Polynomial::zero` accepts an aligned destination.

An aligned allocation does not guarantee aligned sub-blocks: check the actual stride, especially LWE rows of n+1 values. Aligning `Vec<Key>` does not align each key's internal coefficients. Before changing storage, inspect the consuming kernel and measure the affected workload, construction/conversion costs and memory use; preserve secret erasure and ownership contracts. Alignment alone is not evidence of a speedup.

Concrete storage choices, serial reuse and measured memory/latency tradeoffs are recorded in [workspaces and storage](workspaces-and-storage.md).

## Validate the relevant contract

Follow [AGENTS.md](../../AGENTS.md) and the [testing guide](testing.md). Ordinary tests, including encrypted end-to-end cases, favor small parameters that preserve the intended contract; keep larger cases only where their path or regression requires them. Compile/lint all targets, execute lib/tests separately from doctests, and run selected Criterion smoke fixtures separately from both ordinary tests and performance sampling.

## Performance decisions

For measured tradeoffs and their limits, use the [performance guide](../performance/README.md). Current API and workspace contracts remain here; historical measurements and rejected candidates have their own evidence reports.
