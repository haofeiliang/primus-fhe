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

| Backend | Ciphertext modulus | PBS / ManyLUT | Factorized MVB | Boolean gates | CBS |
| --- | --- | --- | --- | --- | --- |
| GLWE NTT | Explicit field | Yes | Yes | Yes | Yes |
| GLWE Fourier | Native torus | Yes | Not implemented | Yes | Not implemented |
| NTRU NTT | Explicit field | Yes | Not implemented | Not implemented | Yes |
| NTRU Fourier | Native torus | Yes | Not implemented | Not implemented | Yes |

All four backends support secret-key and LWE public-key clients. Fourier backends
support RustFFT and TfheFFT. Parameters and APIs are experimental; example and
benchmark fixtures are not production security or failure-probability recommendations.

GLWE NTT also supports [experimental sparse PBS](../primus_tfhe_glwe_ntt/README.md#experimental-sparse-pbs)
for fixed-weight binary small secrets: both orders and ordinary/interleaved/factorized LUTs.
Sparse CBS is not supported.

## LUTs and resource lifetime

1. A family parameter set describes the external LWE and accumulator ring.
2. A backend context binds those parameters to an NTT/FFT table and generates
   paired client/server keys.
3. Compile `LookupTable` or `InterleavedLookupTable` through the family parameters or
   context. Create an evaluator once; its scratch is reused by online `_to` calls.
4. Allocate caller outputs once, then encrypt and evaluate into the same storage.

The front-half unary function or slice compiler programs `0..ceil(t_in/2)` with outputs in `0..t_out`,
as selected by the output codec.
Its remaining inputs are not independently programmed. Odd full-domain compilation
is a separate entry point described below.
For an interleaved LUT (ManyLUT), the effective output count `k` is positive and
the padded output count is `s = next_power_of_two(k)`, with `ceil(t/2) <= N/s`.
The callback receives `(input, output_index)` once per effective pair, in
input-major order; slices contain `D*k` values in the same order. With `k=3`,
three outputs occupy four slots: the compiler zeros the fourth slot without
calling the callback, and the evaluator returns exactly three ciphertexts.
All outputs share one blind rotation (BR) and key switch,
then use separate extraction. More outputs reduce rotation resolution and the
available input-noise margin. This is one input evaluated by multiple functions,
not batching independent ciphertexts.

### Front-half rotation layout

Let `D = input_domain_len()` be the programmed prefix length, `s = padded_output_count()`
(one for an ordinary LUT), and `M = N/s` the coefficients per output. An **output
group** contains `k` encoded function values followed by `s-k` zeros. An **input
interval** repeats that input's output group. Output `j` occupies coefficients
`s*r+j`; its `M` coefficients include repetitions and the negacyclic tail.

Neither `k` nor the plaintext modulus `t` must be a power of two. The padded
count `s = next_power_of_two(k)` always is and divides `N`. Distinct encoded
centers, the input-domain bound and an adequate noise margin are still required.

A message is encoded as `E(m) = round(m*q_in/t) mod q_in`,
then mapped to `R(E(m), q_in, 2M)` in per-output coefficient coordinates. Here
`R(x,q,L) = floor((x*L + floor(q/2))/q) mod L`; both rounds have upward ties.
Native `q_in` is `2^T::BITS`. Combining these rounds can change the table.

The compiler assigns the nearest center's value, breaking midpoint ties toward
the higher center. A final center at `min(R(E(D), q_in, 2M), M)` carries `-f(0)` and ends
the programmed prefix. Coefficients beyond it are not another input domain.

For example, with `q_in=2^32`, `N=64`, `t=8`, `k=3` and `D=4`, let
`F(m) = [f0(m), f1(m), f2(m), 0]` denote an encoded output group. The layout is:

```text
F(0) × 2 | F(1) × 4 | F(2) × 4 | F(3) × 4 | -F(0) × 2
```

These aligned centers give equal full interval lengths, but the first interval
is split across the polynomial boundary, with a negated tail. For a non-power-of-two
`t` or centers that do not align exactly, interval lengths may differ. The same
compiler handles both cases; `M` is not a repetition count.

The constructor's `input_ciphertext_modulus` is `q_in`; `coefficient_modulus`
is `q_acc`, shared by the LUT polynomial and accumulator. Raw outputs must already
be canonical under `q_acc`; out-of-range values are rejected. The coefficient
modulus and output scale are independent of `q_in`.

Single and ManyLUT compilation share one scan of the centers and intervals.
Each interval is filled directly in the result polynomial by writing and then
repeating its first output group. With built-in modulus types and a nonallocating
callback, compilation allocates only the result polynomial. Callback errors or
invalid outputs stop compilation without returning a partial table.

Every backend uses `rotation_step = padded_output_count()`, quantizes each LWE coefficient
as `s*R(x, q_in, 2N/s)` and rotates
by `-R_s(b) + sum(R_s(a[i])*secret[i])`. This is not a single quantization of the
decrypted phase. Compilation uses the same `2N/s` quantization domain with step
one. Execution multiplies by `s`; since `s` divides `N`, output indices modulo `s`
are preserved even across negacyclic wrap. Extracting coefficient `j` reads that
output with the negacyclic sign.

## Encoding and key contracts

| Interface | Input / output meaning |
| --- | --- |
| Ordinary `encrypt` | Unsigned message in `0..t` |
| `encrypt_padded` | Same unsigned scale, restricted to `0..ceil(t/2)` for front-half LUT input |
| `encrypt_centered` | Modular representative in `0..t`; upper-half values represent negatives, e.g. `3` means `-1` for `t=4` |
| GLWE Boolean | External `false/true` is `0/1` modulo 4; internal LUTs use signed values at the rounded modulus-8 scale, followed by a restoring shift |
| CBS | Ordinary unsigned LWE input becomes GGSW/NGSW at the selected gadget scales, under the accumulator secret; a `0/1` input yields a CMUX control |

Client `decrypt` uses the parameter codec and returns a canonical representative in `0..t`. Centered encryption
is not a replacement for the unsigned input contract of ordinary LUTs. PBS preserves
the LUT's output scale; it does not automatically convert Boolean or gadget outputs
to ordinary messages.

Raw `LweCiphertext` does not track its secret, encoding or noise. Callers must use
paired keys, canonical explicit-modulus coefficients and an adequate noise margin.
LUT and dimension checks happen before output writes; they cannot verify secret
identity. Fourier keys and evaluators must use the same FFT table instance.

The minimal traits are `ProgrammableBootstrap` and `ProgrammableBootstrapInterleaved`.
Ordinary applications use context/family compilation methods, which validate and
encode plaintext outputs. `LookupTable::try_new` and `InterleavedLookupTable::try_new`
accept already encoded outputs and an explicit programmed prefix length; Boolean
and CBS paths use these constructors for their distinct output scales.
Compatibility checks bind polynomial length and encoding moduli; callers remain
responsible for keeping the input within the table's programmed prefix.
`rotation` owns the quantization contract shared by LUT compilation and blind rotation.

### Choosing the output encoding

Ordinary and interleaved family/context LUT compilation methods take `&RoundedCodec<T, M>` as their first
argument. Input parameters determine the rotation centers and, together with the
chosen compilation mode, the input domain. The output codec determines `t_out`,
validates values in `0..t_out` and encodes them with unsigned embedding.
All columns of an interleaved LUT use that codec. Its ciphertext modulus must
match the accumulator, or compilation returns `OutputModulusMismatch`.
The current complete PBS chains also require `q_in = q_acc = q_out`;
choosing a different plaintext modulus does not change the ciphertext modulus.

For an NTRU context with `t_in=16`, compute `x % 4` at output modulus `t_out=4`:

```rust
use primus_encoding::RoundedCodec;

let output_codec = RoundedCodec::new(4u32, context.parameters().external_lwe().cipher_modulus());
let lut = context.compile_lookup_table_fn(&output_codec, |x| (x % 4) as u32).unwrap();
let input = encryptor.encrypt_padded(7u32, &mut rng).unwrap();
let output = evaluator.apply_lookup_table(&input, &lut);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 3);
```

For GLWE use `context.parameters().glwe().cipher_modulus()` to construct the
output codec. To keep the parameter encoding, pass `small_lwe().plaintext_codec()`
(GLWE) or `external_lwe().plaintext_codec()` (NTRU); ordinary `decrypt` then applies.
The basic backend examples show independent output encoding without extra keys.

`decrypt_phase` returns a canonical noisy residue under the external LWE secret;
the caller retains the output codec for decoding. LUT compatibility metadata
continues to describe the input and accumulator, without equating `t_out` to
`t_in`. Chaining another PBS requires its input encoding and LUT geometry to
match the previous output encoding; a context does not infer that change from
raw ciphertexts. Custom encodings, per-column scales and Boolean/CBS gadget
outputs use the raw constructors and retain their own decoding contracts.

## Odd full-domain PBS

Use `compile_odd_full_domain_lookup_table_fn(&output_codec, function)` or its
`_slice` form to program **all of `0..t_in`**, with odd `t_in >= 3` and `t_in <= N`.
Slices contain exactly `t_in` outputs in input order. Encrypt with ordinary
`encrypt`, then use the existing `apply_lookup_table_to` and output codec to decode.
For example, in a context configured with `t_in=15` and an output codec for `t_out=8`:

```rust,ignore
let lut = context.compile_odd_full_domain_lookup_table_fn(
    &output_codec, |x| ((x * x + 3) % 8) as u32,
).unwrap();
let input = encryptor.encrypt(14u32, &mut rng).unwrap();
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
let message = output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap());
assert_eq!(message, 7);
```

The raw constructor is `LookupTable::try_new_odd_full_domain`. It computes the
actual centers `c[m] = R(E(m), q_in, 2N)`, folding each center in `N..2N` back by
`N` and storing the negated output. Negacyclic extraction restores its sign.
Folded-center order is `0, (t+1)/2, 1, (t+3)/2, ...`; each callback runs once in
that order. Nearest-center intervals retain upward midpoint ties; the terminal
center at `N` carries `-f(0)` and handles wraparound. Colliding folded centers
return `RotationCenterCollision`, even when `t_in <= N`.

Typical spacing is `N/t_in`, so the noise margin is about half that of front-half
compilation. Capacity and collision checks establish LUT geometry, not a PBS
failure probability. Account for input error and per-coefficient modulus switching.
This entry supports single-output odd domains; interleaved and bivariate compilers
retain their front-half contracts. No extra key or online evaluator is needed.
The [derivation and parameter examples](../../docs/tfhe.md#p23-奇数明文模数全域)
explain the signed folding and its limits.

## Bounded two-input PBS

`BivariateLookupTable::try_new(B, R, N, input_codec, output_codec, function)`
compiles `f(x,y)` for `0 <= x < B`, `0 <= y < R` using `z = x + B*y`.
`B` and `R` must be positive and `D = B*R <= ceil(t_in/2)`; the ordinary LUT
capacity and rotation-center checks also apply. Only the prefix `0..D` is
compiled, with `x` varying fastest. `B` need not be a power of two.
The output codec selects `t_out` independently but must use the same ciphertext
modulus. The shared type works with all four backends and owns no keys or scratch.

For an NTRU context with `t_in=16`, reuse the existing client and evaluator:

```rust
use primus_tfhe::BivariateLookupTable;

let compare = BivariateLookupTable::try_new(
    3, 2, context.parameters().poly_length(),
    context.parameters().external_lwe().plaintext_codec(),
    &output_codec, |x, y| u32::from(x > y),
).unwrap();
let lhs = encryptor.encrypt_padded(2u32, &mut rng).unwrap();
let rhs = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
compare.pack_to(&lhs, &rhs, &mut packed);
evaluator.apply_lookup_table_to(&packed, compare.lookup_table(), &mut output);
assert_eq!(output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()), 1);
```

Allocate `packed` and `output` once with the external LWE dimension.
`pack_to` writes `lhs + B*rhs` in one modular multiply-add pass, without allocation;
it rejects unequal lengths or missing bodies before writing. Inputs must share
an actual secret, ciphertext modulus and the supplied unsigned input codec, with
canonical coefficients and messages inside the stated bounds. These semantic
conditions cannot be checked from raw ciphertexts. GLWE uses its order-dependent
external dimension and `small_lwe().plaintext_codec()`; no extra key material is needed.

Rounding matters even before encryption noise. For `E(m)=round(m*q/t_in)`,
packing produces `E(x+B*y) + e_x + B*e_y + rho` modulo `q`, where
`rho = E(x)+B*E(y)-E(x+B*y)`. If `t_in` divides `q`, `rho=0`; otherwise a conservative
bound is `|rho| <= (B+2)/2` ciphertext units. Include this discrepancy and the
amplified input errors in the PBS input-noise budget, together with any pre-BR
key-switch error and per-coefficient modulus-switch rounding. The capacity bound
prevents plaintext-index wrap; it does not establish a noise margin. This is a
bounded single-output workflow, not arbitrary-precision integer arithmetic or
LWE-to-ring packing. See the runnable [NTRU NTT example](../primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs).

## Fixed-scale factorized MVB

`FactorizedLookupTable::try_new(D, N, output_count, input_codec, output_codec, function)`
compiles a nonempty front-half prefix using Rounded input and unsigned Scaled output.
The coefficient modulus must be explicit and odd. For each unscaled integer LUT
`p_i`, it stores `W_i=(1-X)*p_i` and a common `V=(delta*inv2)*sum(X^j)`, satisfying
`V*W_i=delta*p_i` in the negacyclic ring. The callback receives `(input, output_index)`
once per pair, with **output index outermost**. Factors remain canonical modulo q,
not modulo the plaintext modulus; signed lifts determine their noise amplification.

All outputs share one BR at step one and then apply separate public polynomial
products. Positive output count is unpadded and does not reduce input capacity;
each output instead amplifies BR error by its factor. Input geometry alone is
not a sufficient noise budget. The Scaled codec must be retained for phase
decoding; chaining into Rounded-input PBS must account for differing centers.

The first backend is [GLWE NTT](../primus_tfhe_glwe_ntt/README.md#fixed-scale-factorized-mvb),
using classic or sparse keys and both orders. Its prepared program borrows one
context and its separate evaluator reuses scratch. Odd full-domain MVB, other
backends and CBS outputs are outside this implementation. Algebra and noise
conditions are detailed in the [MVB design](../../docs/tfhe-mvb.md).

## Source layout

The four public types are exported from the crate root. Odd full-domain compilation
is a `LookupTable` constructor; `InterleavedLookupTable` owns output lanes and
`BivariateLookupTable` owns input packing. `FactorizedLookupTable` owns the common
polynomial and coefficient-domain difference factors.

| File | Responsibility |
| --- | --- |
| [bootstrap.rs](src/bootstrap.rs) | Complete ordinary/interleaved PBS contracts for LWE inputs and outputs |
| [rotation.rs](src/rotation.rs) | Prepared, scalar and batch quantization shared by compilation and BR |
| [lookup_table.rs](src/lookup_table.rs) | Exports and shared encoding metadata |
| [single.rs](src/lookup_table/single.rs) | Single-output type with both front-half and odd full-domain constructors |
| [interleaved.rs](src/lookup_table/interleaved.rs) | Multi-output type, padded output count and effective output count |
| [bivariate.rs](src/lookup_table/bivariate.rs) | Input bounds and packing tied to an ordinary LUT |
| [factorized.rs](src/lookup_table/factorized.rs) | Fixed-scale common polynomial and negacyclic difference factors |
| [compile.rs](src/lookup_table/compile.rs) | Shared encoding validation, midpoints and negacyclic tail filling |
| [compile/front_half.rs](src/lookup_table/compile/front_half.rs) | Front-half single/interleaved compilation, domain and slot capacity checks |
| [compile/odd_full_domain.rs](src/lookup_table/compile/odd_full_domain.rs) | Odd-domain checks, signed centers and interval filling |

### Backend execution stages

The shared traits describe complete evaluation without prescribing a BSK algorithm,
secret distribution or transform representation. Backends separate `blind_rotate`
from `keyswitch_accumulator`, reusing their existing workspace:

| Stage | GLWE | NTRU |
| --- | --- | --- |
| BR input | BK uses small LWE directly; KB first applies ring KS and compact extraction to obtain small LWE | External LWE under the client secret |
| BR result | `main_glwe`, coefficient GLWE under the accumulator secret | `blind_rotation.current`, coefficient NTRU under `f_acc` |
| Ordinary/interleaved output | BK switches to the padded small secret before compact extraction; KB extracts kN LWE directly | Switch to the client ring secret, then compact extraction |
| CBS | Consume the BR result under the accumulator secret, then projection/SS | Keep `f_acc` for its projection/SS path |

BK/KB denote `BootstrapKeyswitch` / `KeyswitchBootstrap`. Output KS writes a separate
buffer and preserves the BR result; an MVB algorithm determines its own postprocessing
and KS placement. Current BR binary-secret restrictions remain. Ternary support must
address control keys, encoded LWE residues to signed GLWE secret conversion, and
parameter compatibility together. Automorphism algorithms and auxiliary keys are
not implemented.

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

Raw LUT compilation accepts independent typed input and coefficient moduli.
`rotation::RotationQuantizer::new(input_modulus, two_n, rotation_step)` prepares
a fixed modulus-pair conversion; `exponent(value)` reuses it without allocation.
The rotation domain `two_n = 2N` must be representable by the input coefficient
type; the target `two_n/rotation_step` is an explicit power of two, even for Native input.
GLWE keys and NTRU parameters cache ordinary-PBS quantization at construction.
ManyLUT prepares its conversion for the rotation step before processing coefficients.
For interleaved LUTs, it rounds in `two_n/rotation_step` positions before multiplying by
`rotation_step`, which equals the LUT padded output count. Modulus metadata remains `Option<T>`
where it only describes a domain.
