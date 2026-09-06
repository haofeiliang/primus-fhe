# primus_lattice

English | [简体中文](README.zh_CN.md)

`primus_lattice` provides ciphertext storage, representation conversions, and low-level lattice operations for [Primus FHE](../../README.md). It is shared by the GLWE/NTRU × Fourier/NTT TFHE paths and by RNS GLWE implementations.

The crate is under active development and does not promise a stable API. Key generation, encryption parameters, encoding policy, noise management, and complete homomorphic evaluation belong to higher layers such as [`primus_glwe`](../primus_glwe), [`primus_ntru`](../primus_ntru), and [`primus_glwe_rns`](../primus_glwe_rns).

## Ciphertext families

Let `N` be the polynomial length, `k` the GLWE mask dimension, `L` the gadget level count, and `m` the RNS modulus count. Polynomial arithmetic uses the negacyclic ring modulo `X^N + 1`.

| Family | Coefficient-domain layout | Available representations |
| --- | --- | --- |
| `Lwe` | Scalar mask followed by one body scalar | Coefficients |
| `MultiMsgLwe` | One length-`N` mask in constant-term extraction order, followed by retained body coefficients | Packed RLWE samples |
| `Glwe` | `k` mask polynomials followed by one body polynomial | Coefficient, NTT, Fourier, CRT/DCRT |
| `Rlwe` | One mask polynomial followed by one body polynomial | Coefficient, NTT, CRT/DCRT |
| `Glev` / `Rlev` | `L` GLWE/RLWE ciphertexts in decomposition order | Coefficient, NTT, CRT/DCRT; Fourier for GLev |
| `Ggsw` / `Rgsw` | `k+1` GLev rows / two RLev rows | Coefficient, NTT, CRT/DCRT; Fourier for GGSW |
| `Ntru` | One polynomial `h`, with phase `f*h` under secret `f` | Coefficient, NTT, Fourier |
| `Nlev` / `Ngsw` | `L` NTRU polynomials in decomposition order | Coefficient, NTT, Fourier |
| `TruncatedGlwe` | Full mask polynomials followed by a prefix of the body | Coefficients |
| `BigUintGlwe` | GLWE polynomials with fixed-width little-endian limbs per coefficient | Multi-limb coefficients |

Types are exported through their modules, for example `glwe::Glwe`, `ggsw::NttGgsw`, and `ngsw::FourierNgsw`. Prefixes identify the representation. `Torus*` aliases name native-torus uses of coefficient wrappers; they do not enforce a modulus or perform encoding.

NLev and NGSW share a storage shape but have different semantics: an NLev of `beta` contains phases `v_i*beta`; an NGSW of `beta` contains phases `v_i*f*beta`. Their valid gadget products differ, so the types are intentionally distinct.

## Storage and layout

Wrappers are generic over storage `S` using [`primus_data`](../primus_data/README.md). Operations require the appropriate read, mutable, or owned-storage capability. Borrowed wrappers operate directly on the caller's slices.

- Ordinary GLWE uses `(k+1)*N` elements; GLev uses `L*(k+1)*N`; GGSW uses `(k+1)*L*(k+1)*N`.
- CRT stores each polynomial as `m` consecutive coefficient blocks of length `N`. DCRT has the same block structure in NTT form. Nested gadget order is `[row][level][component][modulus][coefficient/evaluation]`.
- Fourier polynomials contain `N/2` complex entries in the selected backend's evaluation order. Ciphertexts use normalized torus transforms; polynomial multipliers must use the scale required by the multiplication API.
- BigUint storage is coefficient-major within each polynomial, with one fixed-width little-endian limb sequence per coefficient.

`GlweSize`, `GadgetSize`, `RnsGlweSize`, and `RnsGadgetSize` compute checked lengths. They reject invalid counts, unsupported polynomial sizes, and flattened-length overflow. They do not validate backing buffers, transform availability, modulus suitability, or security. Use their length accessors when allocating rather than repeating layout formulas.

## Operations and ownership

| Operation family | Main interfaces |
| --- | --- |
| Basic arithmetic | `add_assign`, `sub_assign`, `neg_assign` and corresponding output forms |
| Scalar/factor arithmetic | `mul_scalar_*`, `mul_factor_*`, and supported fused accumulations |
| Polynomial operations | Monomials in coefficient form; polynomial multiplication/accumulation in NTT, Fourier, or DCRT form |
| Plaintext and gadget updates | `add_plaintext_assign`, `set_trivial`, `add_gadget_diagonal_assign` |
| Conversions | `into_ntt_form`, `write_ntt_form`, inverse coefficient conversions, `write_fourier_form`, `write_torus_form` |
| Extraction | `extract_lwe_at_to`, compact extraction, packed RLWE extraction, `inverse_extract_glwe_to` |
| External products | Fourier/NTT GGSW and NTRU gadget products; DCRT GLev polynomial products and GGSW products |
| CMUX | GGSW/NGSW `cmux_to`, `cmux_k_to`, `cmux_monomial_to` |

Availability depends on the type and representation; this is a family overview, not a promise that every type has every method. RNS scalar/factor inputs use `primus_rns::Residues` and `ResidueFactors` in modulus order.

`*_assign` mutates its receiver; `*_to` writes a separate output. `add_*_assign` accumulates into initialized storage. Consuming arithmetic and conversions can reuse mutable storage, while allocation-returning extraction methods allocate their result; consult the method contract rather than assuming an unsuffixed method is allocation-free.

Full GLWE extraction flattens all mask polynomials into an LWE mask. Compact extraction requires the omitted secret-key suffix to be zero. Packed `MultiMsgLwe` represents one RLWE mask; conversion from truncated GLWE requires `k == 1`. Inverse extraction embeds the constant-term LWE sample and zero-fills unused storage; it does not reconstruct all coefficients of the original GLWE plaintext.

## Correctness and workspace contracts

Raw constructors and mutable access do not establish ciphertext validity. Callers must supply compatible keys, encodings, dimensions, exact buffer lengths, modulus order, decomposition basis, and transform conventions. Unless explicitly documented otherwise, modular inputs must be canonical residues; every word value is canonical for the native modulus.

Checks belong at the highest layer that owns these parameters. This crate deliberately omits many checks: debug assertions are diagnostics, and malformed slices may panic or silently process only a common prefix or complete chunks. A call returning without panic does not establish correctness. Method rustdoc describes specific `Correctness` and `Panics` contracts.

| Workspace | What it binds |
| --- | --- |
| `FourierGlweExternalProductContext` / `NttGlweExternalProductContext` | GLWE layout and decomposition level count through `GadgetSize` |
| `FourierNtruExternalProductContext` / `NttNtruExternalProductContext` | Polynomial length for scalar NTRU gadget products |
| `DcrtGlevMulContext` | RNS gadget layout and BigUint limb-width requirements |

Contexts provide reusable scratch, not a validated basis/table/modulus domain. GLWE contexts support `rebind` for unchanged GLWE shape and `resize` when buffer sizes change. DCRT compatibility includes the RNS product's limb width. Owning callers must establish compatibility before entering the kernels.

Overwriting external products initialize their accumulator, and other scratch is written before use: no manual reset is needed between valid calls. Accumulating APIs preserve the existing output and require it to be initialized. CMUX selection additionally requires bit controls; `cmux_k_to` requires at most one active control. Noise growth and decryptability remain higher-layer obligations.

## Example

Borrow storage, add an already encoded polynomial to the body, then extract its second coefficient under an explicit modulus:

```rust
use primus_lattice::{GlweSize, glwe::Glwe, lwe::Lwe};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;

let size = GlweSize::new(2, 4);
let modulus = BarrettModulus::new(97u32);
let mut storage = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
assert_eq!(storage.len(), size.glwe_len());
let mut ciphertext = Glwe::new(storage.as_mut_slice());
let plaintext = Polynomial::new([10, 20, 30, 40]);
ciphertext.add_plaintext_assign(&plaintext, modulus);

let mut sample: Lwe<Vec<u32>> = Lwe::zero(size.mask_len());
ciphertext.extract_lwe_at_to(1, &mut sample, size.poly_length(), modulus);
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
