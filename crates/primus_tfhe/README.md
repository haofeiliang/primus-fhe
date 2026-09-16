# primus_tfhe

English | [简体中文](README.zh_CN.md)

Shared LUT compilation, encoding metadata and PBS traits for the GLWE and NTRU
families. This crate owns no client keys, transform tables or evaluator workspace.
Start with a backend example below for an end-to-end workflow.

## Crate map and capabilities

| Family | NTT backend | Fourier backend |
| --- | --- | --- |
| [GLWE parameters and clients](../primus_tfhe_glwe/README.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](../primus_tfhe_ntru/README.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md) |

| Backend | Ciphertext modulus | PBS / ManyLUT | Boolean gates | CBS |
| --- | --- | --- | --- | --- |
| GLWE NTT | Explicit field | Yes | Yes | Yes |
| GLWE Fourier | Native torus | Yes | Yes | Not implemented |
| NTRU NTT | Explicit field | Yes | Not implemented | Yes |
| NTRU Fourier | Native torus | Yes | Not implemented | Yes |

All four backends support secret-key and LWE public-key clients. Fourier backends
support RustFFT and TfheFFT. Parameters and APIs are experimental; example and
benchmark fixtures are not production security or failure-probability recommendations.

## LUTs and resource lifetime

1. A family parameter set describes the external LWE and accumulator ring.
2. A backend context binds those parameters to an NTT/FFT table and generates
   paired client/server keys.
3. Compile `LookupTable` or `ManyLookupTable` through the family parameters or
   context. Create an evaluator once; its scratch is reused by online `_to` calls.
4. Allocate caller outputs once, then encrypt and evaluate into the same storage.

A unary function or slice programs `0..ceil(t/2)` with outputs in `0..t`.
The other half follows negacyclic extension and is not independently programmable.
For ManyLUT, `output_count` is a non-zero power of two and
`ceil(t/2) <= N/output_count`. The callback receives `(input, output_index)` once
per pair, in input-major order; slices use the same order.
All outputs share one blind rotation (BR) and key switch,
then use separate extraction. More outputs reduce rotation resolution and the
available input-noise margin. This is one input evaluated by multiple functions,
not batching independent ciphertexts.

### Rotation layout

Let `D` be the programmed prefix length, `s = output_count` (one for an ordinary
LUT), and `M = N/s`. A message is encoded as `E(m) = round(m*q_in/t) mod q_in`,
then mapped to the virtual center `R(E(m), q_in, 2M)`. Here
`R(x,q,L) = floor((x*L + floor(q/2))/q) mod L`; both rounds have upward ties.
Native `q_in` is `2^T::BITS`. Combining these rounds can change the table.

The compiler assigns the nearest center's value, breaking midpoint ties toward
the higher center. A final center at `min(R(E(D), q_in, 2M), M)` carries `-f(0)` and ends
the programmed prefix. Coefficients beyond it are not another input domain.
Raw outputs must already be canonical under `q_acc`; out-of-range values are
rejected. The accumulator modulus and output scale are independent of `q_in`.

Single and ManyLUT compilation share one scan of the centers and intervals.
Each interval is filled directly in the result polynomial using its first row
as the output-value buffer. With built-in modulus types and a nonallocating
callback, compilation allocates only the result polynomial. Callback errors or
invalid outputs stop compilation without returning a partial table.

Every backend quantizes each LWE coefficient as `s*R(x, q_in, 2N/s)` and rotates
by `-R_s(b) + sum(R_s(a[i])*secret[i])`. This is not a single quantization of the
decrypted phase. The rotation is a multiple of `s`, preserving lanes at `s*r+j`;
extracting coefficient `j` reads that lane with the negacyclic sign.

## Encoding and key contracts

| Interface | Input / output meaning |
| --- | --- |
| Ordinary `encrypt` | Unsigned message in `0..t` |
| `encrypt_padded` | Same unsigned scale, restricted to `0..ceil(t/2)` for ordinary LUT input |
| `encrypt_centered` | Modular representative in `0..t`; upper-half values represent negatives, e.g. `3` means `-1` for `t=4` |
| GLWE Boolean | External `false/true` is `0/1` modulo 4; internal LUTs use signed values at the rounded modulus-8 scale, followed by a restoring shift |
| CBS | Ordinary unsigned LWE input becomes GGSW/NGSW at the selected gadget scales, under the accumulator secret; a `0/1` input yields a CMUX control |

Client decryption returns a canonical representative in `0..t`. Centered encryption
is not a replacement for the unsigned input contract of ordinary LUTs. PBS preserves
the LUT's output scale; it does not automatically convert Boolean or gadget outputs
to ordinary messages.

Raw `LweCiphertext` does not track its secret, encoding or noise. Callers must use
paired keys, canonical explicit-modulus coefficients and an adequate noise margin.
LUT and dimension checks happen before output writes; they cannot verify secret
identity. Fourier keys and evaluators must use the same FFT table instance.

The minimal traits are `ProgrammableBootstrap` and `ProgrammableBootstrapMany`.
Encoded LUT compilers and `backend_support` serve backend implementations; ordinary
applications should use context/family compilation methods.

## Validation

Run from the workspace root:

```sh
just tfhe
just tfhe-simd
```

These [recipes](../../justfile) cover all seven crates with default/nightly SIMD
checks, Clippy and tests; `tfhe` also checks the `xtask` consumer and builds docs.
`just ci` runs workspace checks and both the lower-level and TFHE SIMD checks.
Backend READMEs provide runnable examples and Criterion commands.
The shared raw-output LUT construction benchmark includes allocation and drop:

```sh
cargo bench -p primus_tfhe --bench lookup_table
```

## Typed rotation quantization

Raw LUT compilation accepts independent typed input and accumulator moduli.
`backend_support::RotationQuantizer::new(input_modulus, two_n, window)` prepares
a fixed modulus-pair conversion; `exponent(value)` reuses it without allocation.
GLWE keys and NTRU parameters cache ordinary-PBS quantization at construction.
ManyLUT prepares its stride-dependent conversion before processing coefficients.
For interleaved LUTs, it rounds in `two_n/window` positions before multiplying by
`window`. Modulus metadata remains `Option<T>` where it only describes a domain.
