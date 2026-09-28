# primus_encoding

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Plaintext coefficient encoding and decoding for Primus FHE.

## APIs

`RoundedCodec::try_new` and `ScaledCodec::try_new` return `CodecError` for invalid domains or a failed fixed-scale recovery bound. Their `new` forms panic on the same errors. Construction checks do not establish a noise budget.

| Codec | Encoding | Current use |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE and TFHE lookup tables |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | Single-modulus GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS coefficient scaling (`rns` feature) |

Single-modulus constructors use `new(plaintext_modulus, ciphertext_modulus)`, for example `RoundedCodec::new(256u64, NativeModulus::new())` or `RoundedCodec::new(7u64, BarrettModulus::new(131))`. Construction requires `PrepareModulusSwitch` and `ReduceAdd`; `RingContext` already includes these capabilities, and `UintModulus` / `CompactModulus` also work. Construct once and reuse the codec. When t divides q, both encodings use exact scale q/t; otherwise Rounded rounds each message while Scaled uses one integer scale.

The output `RoundedCodec` for ordinary TFHE LUTs uses the accumulator modulus and may choose a different plaintext modulus from the input. Decode with the same output plaintext modulus at the returned ciphertext modulus, especially for NTRU Q→q. See the [output encoding guide](../primus_tfhe/README.md#choosing-the-output-encoding).

These are coefficient codecs. BFV/BGV integer slot packing, BGV's unscaled plaintext lifting, and CKKS canonical embedding are not implemented.

## Encoding contracts

Messages must be canonical residues in `[0,t)`. Unsigned embedding lifts them to `[0,t)`; centered embedding lifts them to `[-floor(t/2),ceil(t/2))`, including `1 -> -1` when `t=2`. Rounded encoding rounds the magnitude with ties upward, then applies its sign; decoding rounds the canonical phase times `t/q`, with ties upward, modulo `t`. Accumulators and decoding inputs must be canonical ciphertext residues in the codec's modulus or ordered RNS basis. These ciphertext input ranges are caller preconditions, not validated by the codecs.

`RoundedCodec` requires `t >= 2` and `q > t`. `ScaledCodec` additionally checks `abs(t*round(q/t)-q)*(t-1) < q/2`, a sufficient condition for noiseless recovery under either embedding. For a chosen integer lift `m` and noise `e`, its recovery condition is `abs((t*delta-q)*m + t*e) < q/2`. Encoding parameters and conventions must agree between producers and consumers.

`BfvRnsCodec` uses the product `Q` of its ordered ciphertext moduli. Its constructor checks conservative sufficient recovery bounds `Q > 4*(Q % t)*(t-1)` and `gamma > 4*k`, where `k` is the number of moduli, as well as the modulus and coprimality conditions documented in rustdoc. For phase `delta*m+e`, a sufficient decode bound is `abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`. For multiple ciphertext moduli, the destination modulus implementations for `t` and `gamma` must also satisfy the extra dot-product input requirements documented by `BaseConverter::fast_convert`; `FieldContext` alone does not imply them.

RNS encoding produces coefficient-domain `CrtPolynomial` data; callers perform NTT conversions separately. `decode_coeffs_to` overwrites its coefficient-domain input and needs exactly `decode_scratch_len(output.len())` scratch elements. This is zero for a single-modulus basis and one RNS polynomial for other bases. The codec is a BFV building block, not a complete BFV scheme.

Single-modulus slice methods use `_to` for separate output and `_assign` for in-place updates. RNS uses `encode_coeffs_to`, `add_encode_coeffs_assign`, and `decode_coeffs_to`; polynomial length is inferred from the plaintext slice. Batch encoding validates message ranges and exact lengths before writing. Encoding inputs and decoding outputs use the coefficient type `T`, with canonical values in `[0,t)`. Scalar inputs are `T` and slices are `[T]`; applications handle integer or semantic type conversions at their boundaries.

## Further reading

[Implementation notes](IMPLEMENTATION.md) record arithmetic kernels and benchmark boundaries. The [public API sources](src/lib.rs) document method contracts; the [testing guide](../../guides/development/testing.md) records validation scope.

## Features

- Default: single-modulus codecs only.
- `rns`: enables `primus_data`, `primus_poly`, and `primus_rns` dependencies.
- `simd`: enables nightly SIMD arithmetic; does not enable `rns` by itself.
