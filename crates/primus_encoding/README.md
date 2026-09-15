# primus_encoding

English | [简体中文](README.zh_CN.md)

Plaintext coefficient encoding and decoding for Primus FHE.

## APIs

| Codec | Encoding | Current use |
| --- | --- | --- |
| `RoundedCodec<T,M>` | `round(lift(m)*q/t) mod q` | LWE and TFHE lookup tables |
| `ScaledCodec<T,M>` | `lift(m)*round(q/t) mod q` | Single-modulus GLWE/NTRU |
| `BfvRnsCodec<T,M>` | `lift(m)*floor(Q/t) mod Q` | RNS coefficient scaling (`rns` feature) |

Public types are available directly at the crate root; implementation modules
are private. Single-modulus constructors take a typed modulus, for example
`RoundedCodec::new(256u64, NativeModulus::new())` for `q=2^64`, or
`RoundedCodec::new(7u64, BarrettModulus::new(131))`. They require `PrepareModulusSwitch` and `ReduceAdd`; the full `RingContext` is unnecessary.
`RingContext` includes preparation, but codecs also support `UintModulus` and
`CompactModulus` without requiring their full ring operation sets.
`RoundedCodec` prepares fixed `t → q` and `q → t` conversions at construction.
`ScaledCodec` keeps fixed-scale multiplication and shares the prepared decoder.
Magnitude rounding and decoding reuse the modulus-switch kernels. Batch paths
fuse signs, output writes and accumulation with their arithmetic without
intermediate buffers; scalar wrappers retain their direct specialization paths.
When `t` divides `q`,
both encode with the exact integer scale `q/t`. Otherwise `RoundedCodec` rounds
each scaled message, while `ScaledCodec` uses one rounded integer scale.

Integer scales use shifts when the scale is a power of two, and ordinary
one-word multiplication otherwise. The fixed-scale constructor's recovery bound
guarantees `(t-1)*delta < q`, so magnitude encoding needs no modular product.
Centered negation and accumulation still use the ciphertext modulus.

For non-integral ratios, rounded encoding decomposes `q = a*t + r` and computes
`m*a + floor((m*r + floor(t/2))/t)` on the message magnitude when the biased
residual product fits one word. Otherwise it retains wide arithmetic.

Decoding uses `round(c/delta) mod t` only when `t` divides `q`; a power-of-two
rounded scale alone does not imply this identity. Other parameters use the
native high-product or explicit narrow/wide ratio kernels. All batch arithmetic
dispatch occurs outside coefficient loops.

TFHE obtains its per-message codec from its own parameter layer. GLWE TFHE can
reuse its small-LWE codec because construction validates equal plaintext and
ciphertext moduli. NTRU lookup-table construction creates its output codec once
at the compilation boundary.

These are coefficient codecs. BFV/BGV integer slot packing, BGV's unscaled
plaintext lifting, and CKKS canonical embedding are not implemented.

## Encoding contracts

Messages must be canonical residues in `[0,t)`. Unsigned embedding lifts them
to `[0,t)`; centered embedding lifts them to `[-floor(t/2),ceil(t/2))`, including
`1 -> -1` when `t=2`. Rounded encoding rounds the magnitude with ties upward,
then applies its sign; decoding rounds the canonical phase times `t/q`, with
ties upward, modulo `t`. Accumulators and decoding inputs must be canonical
ciphertext residues in the codec's modulus or ordered RNS basis.
These ciphertext input ranges are caller preconditions, not validated by the codecs.

`RoundedCodec` requires `t >= 2` and `q > t`. `ScaledCodec` additionally checks
`abs(t*round(q/t)-q)*(t-1) < q/2`, a sufficient condition for noiseless recovery
under either embedding. For a chosen integer lift `m` and noise `e`, its recovery
condition is `abs((t*delta-q)*m + t*e) < q/2`. Encoding parameters and conventions
must agree between producers and consumers.

`BfvRnsCodec` uses the product `Q` of its ordered ciphertext moduli. Its
constructor checks conservative sufficient recovery bounds
`Q > 4*(Q % t)*(t-1)` and `gamma > 4*k`, where `k` is the number of moduli,
as well as the modulus and coprimality conditions documented in rustdoc.
For phase `delta*m+e`, a sufficient decode bound is
`abs(t*e-(Q % t)*m)/Q + k/gamma < 1/2`.
For multiple ciphertext moduli, the destination modulus implementations for `t`
and `gamma` must also satisfy the extra dot-product input requirements documented
by `BaseConverter::fast_convert`; `FieldContext` alone does not imply them.

RNS encoding produces coefficient-domain `CrtPolynomial` data; callers perform
NTT conversions separately. `decode_coeffs_to` overwrites its coefficient-domain
input and needs exactly `decode_scratch_len(output.len())` scratch elements.
This is zero for a single-modulus basis and one RNS polynomial for other bases.
The codec is a BFV building block, not a complete BFV scheme.

Single-modulus slice methods use `_to` for separate output and `_assign` for
in-place updates. RNS uses `encode_coeffs_to`, `add_encode_coeffs_assign`, and
`decode_coeffs_to`; polynomial length is inferred from the plaintext slice.
Batch encoding validates message ranges and exact lengths before writing.
Encoding inputs and decoding outputs use the coefficient type `T`, with
canonical values in `[0,t)`. Scalar inputs are `T` and slices are `[T]`;
applications handle integer or semantic type conversions at their boundaries.

## Source layout

- `rounded.rs` and `scaled.rs`: the two single-modulus codecs and their APIs.
- `integer_scale.rs`, `decode.rs`, and `helpers.rs`: shared private kernels and
  boundary helpers.
- `bfv_rns/`: the BFV RNS codec; `mod.rs` owns parameters and construction,
  `encode.rs` implements encoding and accumulation, and `decode.rs` implements
  decoding and its workspace contract.

Tests cover API consistency, independent arithmetic oracles, and BFV RNS
contracts. `benches/plaintext_codec.rs` measures single-modulus arithmetic and
scalar dispatch; `benches/bfv_rns.rs` measures RNS accumulation and decoding.
Inputs span both centered halves and each ciphertext modulus. Codecs and reusable
buffers are outside timing; destructive decode inputs are restored in fixed batches.
Throughput counts plaintext coefficients, with the RNS limb count in case names.

## Features

- Default: single-modulus codecs only.
- `rns`: enables `primus_data`, `primus_poly`, and `primus_rns` dependencies.
- `simd`: enables nightly SIMD arithmetic; does not enable `rns` by itself.

## Validation

```sh
cargo test -p primus_encoding
cargo test -p primus_encoding --features rns
cargo +nightly test -p primus_encoding --features rns,simd
cargo bench -p primus_encoding --bench plaintext_codec
cargo bench -p primus_encoding --bench bfv_rns --features rns
```
