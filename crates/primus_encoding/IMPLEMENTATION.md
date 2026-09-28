# Coefficient codec kernels

User-facing scales, ranges and recovery bounds are in the [README](README.md). The private kernels in [integer_scale.rs](src/integer_scale.rs), [decode.rs](src/decode.rs) and [helpers.rs](src/helpers.rs) implement the following choices.

Integer scales use shifts when the scale is a power of two, and ordinary one-word multiplication otherwise. The fixed-scale constructor's recovery bound guarantees `(t-1)*delta < q`, so magnitude encoding needs no modular product. Centered negation and accumulation still use the ciphertext modulus.

For non-integral ratios, rounded encoding decomposes `q = a*t + r` and computes `m*a + floor((m*r + floor(t/2))/t)` on the message magnitude when the biased residual product fits one word. Otherwise it retains wide arithmetic.

Decoding uses `round(c/delta) mod t` only when `t` divides `q`; a power-of-two rounded scale alone does not imply this identity. Other parameters use the native high-product or explicit narrow/wide ratio kernels. All batch arithmetic dispatch occurs outside coefficient loops.

`RoundedCodec` prepares t→q and q→t conversions during construction; `ScaledCodec` keeps integer-scale multiplication and shares the prepared decoder. Batch paths fuse signs, writes and accumulation without intermediate buffers. Scalar paths retain direct specializations.

The [single-modulus benchmark](benches/plaintext_codec.rs) covers arithmetic and scalar dispatch; the [RNS benchmark](benches/bfv_rns.rs) covers accumulation and decoding. Codecs and reusable buffers are outside timing; destructive decode inputs are restored in fixed batches. Throughput counts plaintext coefficients, and RNS IDs include the limb count. See source comments for commands and parameter ranges, and the [testing guide](../../guides/development/testing.md) for independent-oracle coverage.
