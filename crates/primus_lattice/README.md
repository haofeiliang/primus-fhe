# primus_lattice

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

`primus_lattice` provides ciphertext storage, representation conversions, and low-level lattice operations for [Primus FHE](../../README.md). It is shared by the GLWE/NTRU × Fourier/NTT TFHE paths and by RNS GLWE implementations.

Key generation, encryption parameters, encoding policy, noise management, and complete homomorphic evaluation belong to higher layers such as [`primus_glwe`](../primus_glwe), [`primus_ntru`](../primus_ntru), and [`primus_glwe_rns`](../primus_glwe_rns).

## Ciphertext families

Let `N` be the polynomial length, `k` the GLWE mask dimension, `L` the gadget level count, and `m` the RNS modulus count. Polynomial arithmetic uses the negacyclic ring modulo `X^N + 1`.

| Family | Coefficient-domain layout | Available representations |
| --- | --- | --- |
| `Lwe` | Scalar mask followed by one body scalar | Coefficients |
| `MultiMsgLwe` | One length-`N` mask in constant-term extraction order, followed by retained body coefficients | Packed RLWE samples |
| `Glwe` | `k` mask polynomials followed by one body polynomial | Coefficient, NTT, Fourier, CRT/DCRT |
| `Glev` | `L` GLWE ciphertexts in decomposition order | Coefficient, NTT, Fourier, CRT/DCRT |
| `Ggsw` | `k+1` GLev rows | Coefficient, NTT, Fourier, CRT/DCRT |
| `Ntru` | One polynomial `h`, with phase `f*h` under secret `f` | Coefficient, NTT, Fourier |
| `Nlev` / `Ngsw` | `L` NTRU polynomials in decomposition order | Coefficient, NTT, Fourier |
| `TruncatedGlwe` | Full mask polynomials followed by a prefix of the body | Coefficients |
| `BigUintGlwe` | GLWE polynomials with fixed-width little-endian limbs per coefficient | Multi-limb coefficients |

RLWE, RLev and RGSW use `Glwe`, `Glev` and `Ggsw` with `GlweSize::new(GlweDimension::new(1), PolyLength::new(N))`; their NTT and CRT/DCRT representations follow the same dimension-one layout.

Types are exported through their modules, for example `glwe::Glwe`, `ggsw::NttGgsw`, and `ngsw::FourierNgsw`. Prefixes identify the representation. `Torus*` aliases name native-torus uses of coefficient wrappers; they do not enforce a modulus or perform encoding.

NLev and NGSW share a storage shape but have different semantics: an NLev of `beta` contains phases `v_i*beta`; an NGSW of `beta` contains phases `v_i*f*beta`. Their valid gadget products differ, so the types are intentionally distinct.

NLev/NGSW scalar external products can write coefficients or keep the result in NTT/Fourier form with `external_product_ntt_to` / `external_product_fourier_to`. Transform outputs accumulate directly into the destination. NTT coefficient outputs also reuse the destination, then inverse-transform in place. Fourier coefficient outputs retain separate complex scratch for torus conversion; Fourier outputs skip that conversion and its rounding. For `NGSW.external_product_nlev_to`, input/output NLev levels match each other but are independent of the control's decomposition basis; their gadget scales are preserved.

NLev `external_product_sum_to` and NGSW `cmux_k_to` accept exact-size iterators of paired inputs. They sum products in the transform domain and inverse-transform once, without allocating a batch of wrapper objects. Empty NLev sums write zero; empty CMux copies its default. Fourier conversion rounds the total, so it need not match the bits from summing separately converted products.

These batch operations check counts and fixed-buffer lengths before writes,
then validate each pair's complete lengths as it is consumed. A later invalid
pair may leave partial state: NTT sums use output for the transform accumulator,
Fourier sums keep it in scratch, and k-CMux uses output for candidate differences.
After a rejected call, discard the result; a valid call reuses the workspace
without a reset. Key, basis, modulus and transform compatibility remain caller
obligations as specified in rustdoc.

## Storage and layout

Wrappers are generic over storage `S` using [`primus_data`](../primus_data/README.md). Operations require the appropriate read, mutable, or owned-storage capability. Borrowed wrappers operate directly on the caller's slices.

`as_view()` / `as_mut_view()` and the corresponding `From` conversions borrow the complete storage without copying or changing representation. `into_inner()` returns the original storage. Integer, NTT, and Fourier ciphertext iterators support exact-size, fused, bidirectional iteration; shared iterators can also be cloned.

For NLev sums and NGSW multi-way CMux, pass `output.as_mut_view()` as output, and `default.as_view()` as the CMux default. Polynomial/candidate items accept borrowed wrappers through `Into` or views yielded by semantic iterators. Gadgets/controls use `Borrow<Self>` to accept objects or references to the same wrapper type. No wrapper array is required for packed storage.

`LweIter` / `LweIterMut` and `MultiMsgLweIter` / `MultiMsgLweIterMut` borrow complete chunks, like other ciphertext iterators. Their chunk lengths include the body; `Lwe::lwe_len()` returns this length. An incomplete tail is omitted, so batch operations must validate the complete buffer length before iteration. `MultiMsgLweIter` traverses packed containers, not the samples extracted from one shared mask.

- Ordinary GLWE uses `(k+1)*N` elements; GLev uses `L*(k+1)*N`; GGSW uses `(k+1)*L*(k+1)*N`.
- CRT stores each polynomial as `m` consecutive coefficient blocks of length `N`. DCRT has the same block structure in NTT form. Nested gadget order is `[row][level][component][modulus][coefficient/evaluation]`.
- Fourier polynomials contain `N/2` complex entries in the selected backend's evaluation order. Ciphertexts use normalized torus transforms; polynomial multipliers must use the scale required by the multiplication API.
- BigUint storage is coefficient-major within each polynomial, with one fixed-width little-endian limb sequence per coefficient.

`LweDimension` and `GlweDimension` represent positive mask counts with a representable body-inclusive count. `LweDimension::ciphertext_len()` gives `n+1`; `GlweDimension::component_count()` gives `k+1`. They impose no parameter-preset or security cap. Raw ciphertext and secret-key slices retain integer lengths and can represent dimension zero.

`GlweSize`, `GadgetSize`, `RnsGlweSize`, and `RnsGadgetSize` compute checked lengths from `GlweDimension`, `PolyLength` and the `primus_decompose::DecompositionLevelCount` for gadgets. They check RNS modulus counts and flattened-length overflow. `GlweSize` stores GLWE geometry and flattened lengths. `LweDimension::from(glwe_size)` explicitly derives the extracted dimension `kN`, including the guarantee that `kN+1` fits. They do not validate backing buffers, transform availability, modulus suitability, or security. Use their length accessors when allocating rather than repeating layout formulas.

`PolyLength` checks that `N` is a power of two in `MIN_POLY_LENGTH..=MAX_POLY_LENGTH`
(currently `2..=2^17`). Its `get()`, `log_n()`
and `fourier_poly_len()` return `N`, `log2(N)` and `N/2` complex elements.
This range also ensures `2N` fits in `usize`. Use `new`, `try_new`
or `TryFrom<usize>` to construct it. `PolyLengthError` retains the rejected length.
`GlweSize` stores it, and gadget/RNS layouts
compose the same invariant through their nested GLWE size. Layout constructors consume `PolyLength`, and `poly_length()` accessors
return it directly; extract `usize` with `.get()` at raw storage/kernel boundaries. Transform constructors
retain their own supported ranges and numerical requirements.

## Operations and ownership

| Operation family | Main interfaces |
| --- | --- |
| Basic arithmetic | `add_assign`, `sub_assign`, `neg_assign` and corresponding output forms |
| Scalar/factor arithmetic | `mul_scalar_*`, `mul_factor_*`, and supported fused accumulations |
| Polynomial operations | Monomials in coefficient/NTT form; polynomial multiplication/accumulation in NTT, Fourier, or DCRT form |
| Plaintext and gadget updates | `add_plaintext_assign`, `set_trivial`, `add_gadget_diagonal_assign` |
| Conversions | `into_ntt_form`, `write_ntt_form`, inverse coefficient conversions, `write_fourier_form`, `write_torus_form` |
| Extraction | `extract_lwe_at_to`, compact extraction, packed RLWE extraction, `inverse_extract_glwe_to` |
| External products | Fourier/NTT GGSW and NTRU gadget products; DCRT GLev polynomial products and GGSW products |
| CMUX | GGSW/NGSW `cmux_to`, `cmux_k_to`, `cmux_monomial_to` |
| Ternary rotation | NTT/Fourier GGSW and NGSW `cmux_ternary_monomial_to`, using a positive/negative control pair and one external product |

Availability depends on the type and representation; this is a family overview, not a promise that every type has every method. RNS scalar/factor inputs use `primus_rns::Residues` and `ResidueFactors` in modulus order.

`*_assign` mutates its receiver; `*_to` writes a separate output. `add_*_assign` accumulates into initialized storage. Consuming arithmetic and conversions can reuse mutable storage, while allocation-returning extraction methods allocate their result; consult the method contract rather than assuming an unsuffixed method is allocation-free.

Coefficient-domain `Glwe`, `Glev`, `Ggsw`, `Nlev` and `Ngsw` share `add_mul_monomial_pair_assign` for `self += first * X^ra + second * X^rb`. Pass both input/exponent pairs, the polynomial length and modulus. Matching layouts and canonical initialized storage are required; each contribution is reduced in order. The batch kernel computes rotation offsets once for all components and dispatches each interval outside the polynomial loop for 64-bit words, without allocation.

Single-modulus NTT ciphertexts provide `mul_monomial_assign`, `mul_monomial_to`, and `add_mul_monomial_assign`, plus `sub_mul_monomial_to` for `self - rhs * X^exponent`. Pass the modulus, monomial NTT table, and a length-`N` scratch slice after the operands. The operations overwrite scratch with one monomial transform shared by all ciphertext polynomials, without allocation or conversion to coefficients.

`FourierGgsw` and `FourierNgsw` provide `sub_mul_monomial_to` using an FFT engine and scratch slices of `N` torus words and `N/2` complex values. It transforms the monomial at integer scale using the ciphertexts' exact table instance, preserving their torus scale and evaluation order.

Full GLWE extraction flattens all mask polynomials into an LWE mask. Compact extraction requires the omitted secret-key suffix to be zero. Packed `MultiMsgLwe` represents one RLWE mask; conversion from truncated GLWE requires `k == 1`. Inverse extraction embeds the constant-term LWE sample and zero-fills unused storage; it does not reconstruct all coefficients of the original GLWE plaintext.

## Correctness and workspace contracts

Raw constructors and mutable access do not establish ciphertext validity. Callers must supply compatible keys, encodings, dimensions, exact buffer lengths, modulus order, decomposition basis, and transform conventions. Unless explicitly documented otherwise, modular inputs must be canonical residues; every word value is canonical for the native modulus.

Checks belong at the highest layer that owns these parameters. This crate deliberately omits many checks: debug assertions are diagnostics, and malformed slices may panic or silently process only a common prefix or complete chunks. A call returning without panic does not establish correctness. Method rustdoc describes specific `Correctness` and `Panics` contracts.

| Workspace | What it binds |
| --- | --- |
| `FourierGlweExternalProductWorkspace` / `NttGlweExternalProductWorkspace` | GLWE layout and decomposition level count through `GadgetSize` |
| `NttGlweTernaryCmuxWorkspace` / `FourierGlweTernaryCmuxWorkspace` | Fixed `GadgetSize`; combined GGSW, transformed monomial, and external-product scratch |
| `FourierNtruExternalProductWorkspace` / `NttNtruExternalProductWorkspace` | Polynomial length for scalar NTRU gadget products |
| `NttNtruCmuxWorkspace` / `FourierNtruCmuxWorkspace` | Fixed polynomial length and level count; combined NLEV/NGSW and reusable external-product scratch for first lifting and ternary CMUX |
| `DcrtGlevMulWorkspace` | RNS gadget layout and BigUint limb-width requirements |

Workspaces provide reusable scratch, not a validated basis/table/modulus domain. GLWE external-product workspaces support `rebind` for unchanged GLWE shape and `resize` when buffer sizes change. DCRT compatibility includes the RNS product's limb width. Owning callers must establish compatibility before entering the kernels.

Overwriting external products initialize their accumulator, and other scratch is written before use: no manual reset is needed between valid calls. Accumulating APIs preserve the existing output and require it to be initialized. CMUX selection additionally requires bit controls; `cmux_k_to` requires at most one active control. Noise growth and decryptability remain higher-layer obligations.

`positive.cmux_ternary_monomial_to(&negative, ...)` uses mutually exclusive encrypted bits `s⁺, s⁻` to rotate by `X^(exponent * (s⁺-s⁻))`. Both controls use the same key, basis, and NTT table or exact FFT table instance. Fourier controls use native-torus scale and a matching native basis. The exponent is already quantized into `0..2N`; zero copies the input exactly. Evaluation reuses its workspace without allocation. This is a lattice primitive; complete GLWE TFHE ternary key generation and evaluation are described in the [family API](../primus_tfhe_glwe/README.md). The NGSW form supports NTT and Fourier; complete NTRU integration is described in the [family API](../primus_tfhe_ntru/README.md).

## Example

Borrow storage, add an already encoded polynomial to the body, then extract its second coefficient under an explicit modulus:

```rust
use primus_lattice::{GlweDimension, GlweSize, PolyLength, glwe::Glwe, lwe::Lwe};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;

let size = GlweSize::new(GlweDimension::new(2), PolyLength::new(4));
let modulus = BarrettModulus::new(97u32);
let mut storage = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
assert_eq!(storage.len(), size.glwe_len());
let mut ciphertext = Glwe::new(storage.as_mut_slice());
let plaintext = Polynomial::new([10, 20, 30, 40]);
ciphertext.add_plaintext_assign(&plaintext, modulus);

let mut sample: Lwe<Vec<u32>> = Lwe::zero(size.mask_len());
ciphertext.extract_lwe_at_to(1, &mut sample, size.poly_length().get(), modulus);
assert_eq!(sample.a(), &[2, 1, 93, 94, 6, 5, 89, 90]);
assert_eq!(sample.b(), 30);
```

This illustrates layout and arithmetic, not randomized encryption or secure parameter selection.

## Features

Default features are empty.

- `rns` enables CRT/DCRT ciphertexts, their product workspace, and CRT conversions on `BigUintGlwe`.
- `simd` enables nightly SIMD support in arithmetic dependencies. It does not enable `rns`; use both for SIMD RNS operations.
- `BigUintGlwe`, `RnsGlweSize`, and `RnsGadgetSize` are available without `rns`.

## Tests and benchmarks

Run from the workspace root:

```sh
cargo test -p primus_lattice
cargo test -p primus_lattice --features rns
cargo clippy -p primus_lattice --all-targets --features rns -- -D warnings
cargo +nightly test -p primus_lattice --features rns,simd
cargo doc -p primus_lattice --no-deps --features rns
```

The [test guide](tests/README.md) maps independent contracts to test files. The [benchmark guide](benches/README.md) describes independently runnable GLWE/NTRU × Fourier/NTT, extraction, and RNS targets. Benchmarks isolate warmed lattice operations; full PBS and key-streaming costs must be measured in the upper layers. Basic modular and factor arithmetic are benchmarked in their owning crates.
