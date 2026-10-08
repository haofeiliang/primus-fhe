# primus_glwe

[English](README.md) | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Single-modulus GLWE keys and operations, with separate NTT and native-torus Fourier representations. Here `k` is the GLWE dimension and `N` the polynomial length.

## Quick start

This u64 NTT example shows both ordinary messages and encoded/phase primitives. The calling crate directly depends on `primus_glwe` with `ntt` enabled, plus `primus_ntt`, `primus_poly`, `primus_modulus`, `primus_encoding` and `rand`. N=32 is a small functional fixture, not a security parameter.

```rust
use primus_encoding::PlaintextEmbedding;
use primus_glwe::{GlweDimension, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::{PolyLength, Polynomial};

let poly_length = PolyLength::new(32);
let modulus = BarrettModulus::new(132_120_577u64);
let table = U64NttTable::new(poly_length, modulus).unwrap();
let params = GlweParameters::new(
    GlweDimension::new(1),
    poly_length,
    16,
    modulus,
    SecretKeyDistr::UniformBinary,
    0.7,
);
let mut rng = rand::rng();
let (_coeff_secret, secret) = NttGlweSecretKey::generate_pair(
    params.size(),
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let message = Polynomial::new(vec![3u64; poly_length.get()]);
let embedding = PlaintextEmbedding::Unsigned;

// Ordinary messages: the adapter uses the parameter codec.
let mut ciphertext = secret.encrypt_message(&message, &params, embedding, &table, &mut rng);
assert_eq!(
    secret.decrypt_message(&ciphertext, &params, &table),
    message
);

// Both the encoded input and the extracted phase are coefficient polynomials.
let codec = params.plaintext_codec();
let mut encoded = Polynomial::new(vec![0; poly_length.get()]);
codec.encode_slice_to(message.as_ref(), encoded.as_mut(), embedding);
secret.encrypt_encoded_to(
    &encoded,
    &mut ciphertext,
    params.encryption_parameters(),
    &table,
    &mut rng,
);
let mut phase = Polynomial::new(vec![0; poly_length.get()]);
secret.decrypt_phase_to(&ciphertext, &mut phase, modulus, &table);
let mut decoded = vec![0; poly_length.get()];
codec.decode_slice_to(phase.as_ref(), &mut decoded);
assert_eq!(decoded, message.as_ref());
```

For ordinary requests, `encrypt_message_to` reuses ciphertext storage without allocating a separate encoded polynomial. Use `encrypt_encoded_to` when controlling the encoding directly: its input and the `decrypt_phase_to` output are coefficients, while the ciphertext is in NTT form. Keep parameters, table, keys and output across requests; Fourier also reuses an FFT engine and workspaces, as described below.

## Keys and representation

`GlweParameters::new` / `try_new` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

`GlweParameters::try_new` returns `GlweParameterError` for layout, fixed-scale encoding and sampler errors, including fixed weights exceeding the complete kN secret length. `GlweEncryptionParameters::try_new` checks only modulus/samplers because it has no layout. The corresponding `new` constructors panic on invalid parameters; transform availability and noise/security budgets remain separate. `GlweParameterError::SecretKey` preserves the sampling/weight/modulus cause as `SecretKeySamplerError`; `Noise` preserves `GaussianError`.

| Type | Storage and role |
| --- | --- |
| `GlweSecretKey<T>` | Signed coefficient polynomials; sampling and input to key conversion/generation |
| `NttGlweSecretKey<T>` | Canonical NTT residues modulo `q`; NTT encryption and decryption |
| `FourierGlweSecretKey` | Integer-scaled Fourier secret polynomials; native-torus Fourier encryption and decryption |
| `NttGlwePublicKey<S>` | One NTT encryption of zero; public-key encryption |

Generate a secret with `generate_pair` for the chosen NTT or Fourier backend. It takes a checked `GlweSize` and borrowed `GlweEncryptionParameters`, samples once, and returns the signed coefficient key and its matching transform. No plaintext codec is needed:

```rust,ignore
let (coeff_sk, ntt_sk) = NttGlweSecretKey::generate_pair(size, &ntt_encryption, &ntt_table, &mut rng);
let (coeff_sk, fourier_sk) =
    FourierGlweSecretKey::generate_pair(size, &fourier_encryption, &mut fft, &mut rng);
```

Ordinary parameters supply `size()` and `encryption_parameters()`; gadget parameters supply `glwe_size()` and `encryption_parameters()`. Fixed secret weights are checked against the supplied layout before sampling.

Use `GlweSecretKey::generate` when only the signed coefficient key is needed. Use `from_coeff_secret_key` to transform an existing coefficient key. Fixed-weight distributions apply to all `k*N` coefficients, not separately to each polynomial. Secret buffers are erased on drop, including unwinding during generation or rejected coefficient/NTT/Fourier imports.

`NttGlweSecretKey` records explicit `q` at conversion/generation. Import transformed values with `NttGlweSecretKey::new(values, size, distribution, modulus)`; `modulus` implements `ExplicitModulus`, and `cipher_modulus()` returns its recorded value. Import checks the layout, not coefficient canonicality, distribution or transform provenance.

Ordinary, coefficient, truncated and gadget operations check key/parameter/table moduli at their public boundary, before sampling or writes; gadget/key-generation loops reuse this check. The key retains no table. Matching `q` and layout cannot prove NTT roots, evaluation order or secret identity, so callers must preserve the transform representation. Explicit `zeroize()` clears secret storage but retains public metadata; discard the erased key. Raw public-key bytes use native endianness and contain no parameter metadata.

## Encryption and decryption

NTT secret, Fourier secret and NTT public keys share these ordinary encryption methods:

| Method | Input | Output storage |
| --- | --- | --- |
| `encrypt_message` / `encrypt_message_to` | Message in `[0, t)`, explicit `PlaintextEmbedding` | Allocate / overwrite |
| `encrypt_encoded_to` | Already encoded ciphertext-ring coefficients | Overwrite; no plaintext scaling |
| `encrypt_zeros` / `encrypt_zeros_to` | Zero polynomial | Allocate / overwrite |

`encrypt_encoded_to`, `encrypt_zeros` / `encrypt_zeros_to`, and `NttGlwePublicKey::generate` take `&GlweEncryptionParameters` directly. Ordinary message methods take `&GlweParameters`, which also supplies the codec, and `primus_encoding::PlaintextEmbedding::{Unsigned, Centered}`. Both embeddings take canonical residues in `[0, t)`; centered `t - 1` represents `-1`. Secret keys supply their own layout. Raw public keys derive N from the NTT table and k from complete mask/body storage; output must have the same length as the key. Matching lengths do not establish transform provenance.

Secret keys provide `decrypt_message`, `decrypt_message_to` and `decrypt_phase_to`. Phase extraction returns noisy coefficient-domain values without decoding; both plaintext embeddings use the same decoder. Decrypted polynomials use the ciphertext coefficient type `T`; applications handle output type conversion.

```text
ntt_sk.encrypt_message_to(input, output, params, embedding, ntt_table, rng)
ntt_pk.encrypt_message_to(input, output, params, embedding, ntt_table, rng, workspace)
fourier_sk.encrypt_message_to(input, output, params, embedding, fft, rng, workspace)
ntt_sk.decrypt_phase_to(input, output, modulus, ntt_table)
fourier_sk.decrypt_phase_to(input, output, fft, workspace)
```

NTT-domain secret-key operations need no workspace. Fourier operations use `FourierGlweEncryptWorkspace<T>` / `FourierGlweDecryptWorkspace`; NTT public encryption uses `NttGlwePublicEncryptWorkspace<T>`. Construct these with `N` and reuse them at that length. Workspaces hold scratch, not parameters, and erase secret intermediates on drop.

For coefficient ciphertexts, `NttGlweSecretKey` provides `encrypt_message_coeff_to`, `decrypt_phase_coeff_to` and `decrypt_message_coeff_to`. They take an additional N-element scratch slice as the last argument, reuse all buffers, and save the body's forward NTT. Encryption selects the same explicit embedding and matches `encrypt_message_to` followed by inverse NTT exactly for the same RNG state. Scratch needs no initialization and retains secret-dependent products after encryption; use an erasing owner such as `zeroize::Zeroizing<Vec<T>>`.

`_to` paths reuse output and scratch. Checked layout and transform-length mismatches fail before output writes; matching lengths do not establish transform representation compatibility. Invalid plaintext values may panic after partial writes or randomness consumption. Encoded inputs to NTT encryption are coefficient polynomials with canonical residues in `[0, q)`; callers guarantee this range.

For diagnostics, extract the phase with `decrypt_phase_to`, encode the **expected message** using the actual codec and embedding, and compare the two coefficient slices with [`primus_encoding::phase_error_magnitude_slice_to`](../primus_encoding/README.md#phase-error-diagnostics). Decoding and re-encoding is not an independent reference: a wrong message may have zero residual against its own encoding.

Message adapters live in the secret/public key's `message.rs`; raw encryption and phase extraction need no codec. For transform-domain output, encoding adds directly to the sampled body noise (or the existing Fourier coefficient scratch), before a single body transform. GLev/GGSW generation uses the raw/zero cores and retains its own gadget scaling and injection order.

## Gadget and truncated ciphertexts

`encrypt_glev_to` and `encrypt_ggsw_to` apply the gadget basis to a coefficient-domain ring polynomial without plaintext scaling. A GGSW control bit is therefore the constant polynomial `0` or `1`. Both use a gadget workspace constructed from `GadgetSize`: GLev requires a matching polynomial length; GGSW also requires a matching level count.

Use `GlevParameters::try_from_parts(size, encryption, basis)` for gadget-only parameters: `size` is a checked `GlweSize`, `encryption` is an `Arc<GlweEncryptionParameters<T, M>>`, and `basis` is a prepared `ApproxSignedBasis<T>`. No plaintext modulus or codec is required. The constructor checks the basis modulus, fixed secret weight against the complete `kN` length, and gadget layout. It returns `GlevParameterError` and takes ownership without copying sampler tables or rebuilding the basis.

`GlweParameters::try_from_glev(&gadget, codec)` binds an ordinary `ScaledCodec` to an existing gadget domain. It shares the prepared sampling state and checks the codec modulus, without retaining or copying the gadget basis.

```rust,ignore
// Prepare the ring sampling state and gadget basis, without ordinary encoding.
let encryption = std::sync::Arc::new(GlweEncryptionParameters::try_new(modulus, secret_distr, sigma)?);
let basis = ApproxSignedBasis::try_new(encryption.cipher_modulus_value(), log_basis, levels)?;
let gadget = GlevParameters::try_from_parts(size, encryption.clone(), basis)?;

// Bind a codec only when ordinary message encryption is also needed.
let codec = primus_encoding::ScaledCodec::try_new(plain_modulus, modulus)?;
let ordinary = GlweParameters::try_from_parts(size, encryption, codec)?;
```

The ordinary constructor checks codec/ciphertext modulus agreement and the secret weight; the supplied parts already validate layout, sampling and fixed-scale recovery. `GlweParameters::try_new` remains the direct ordinary-encryption convenience constructor. Mask/noise samplers serve both ordinary ciphertext and evaluation-key row encryption; the secret sampler serves key generation. Different noise distributions need separate prepared states; identical sampler parameters can be shared across key roles.

When ordinary parameters already exist, `GlevParameters::try_with_basis(&glwe_params, basis)` shares their prepared state. `try_with_glwe_params` also constructs the basis from its logarithm and level count. Both use the same gadget binding checks; neither needs to inspect the ordinary codec. `gadget.try_with_new_basis(basis)` derives another gadget parameter set with the same GLWE layout and shared sampler state, without copying the old basis or converting ciphertexts. Parameter clones share immutable modulus/sampling precomputation. `encryption_parameters()` returns a borrowed `GlweEncryptionParameters`; layouts, plaintext encoding and gadget bases retain their separate ownership.

`encrypt_ggsw_constant_batch_to` encrypts a slice of ring constants into consecutive GGSWs, with one batch validation and no temporary allocation. NTT takes canonical residues, prepares each constant level by direct broadcast, and writes `input.len() * params.ggsw_len()` values; Fourier takes native-ring values and writes `input.len() * params.fourier_ggsw_len()` complex values. Fourier preserves native-ring scaling followed by the FFT for each level; adjacent equal constants reuse those transforms within the batch. Preparation time therefore depends on the input sequence. Empty batches still validate shared resources and consume no randomness.

`NttGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to` writes coefficient GGSWs directly. It preserves the exact ciphertext and RNG consumption of NTT encryption followed by inverse transforms, while avoiding a forward NTT of each sampled body. Only the gadget workspace's polynomial length must match; its level count is unused. Output has `input.len() * params.ggsw_len()` values.

`FourierGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to` writes coefficient GGSWs using the same encryption followed by inverse FFT. It takes an additional `params.fourier_ggsw_len()` scratch slice, reuses one transformed GGSW, and preserves the Fourier path's rounding and RNG consumption.

NTT `encrypt_zeros_truncated` also takes `&GlweEncryptionParameters`. Together with `decrypt_phase_truncated` and `decrypt_message_truncated`, it operates on coefficient ciphertexts with a full mask and at most `N` body coefficients. Phase extraction and decryption return only the retained coefficients, while their internal scratch still holds full polynomials.

## Evaluation primitives

`GlweKeySwitchingParameters::try_new(GlweDimension::new(input_dimension), output)` checks and retains
the complete input GLWE layout at construction, returning `GlweSizeError` on
input-layout or combined key-storage overflow. `new` panics on the same errors. Input and
output share the ring geometry from `output`; `input_size()` returns the stored
layout. Ordinary and gadget parameters retain the checked
[PolyLength](../primus_poly/README.md#ring-polynomial-length) through `GlweSize`;
their `poly_length()` accessors return this checked value. Pass it directly to
workspace and NTT/FFT table constructors, and use `.get()` at raw storage or scalar kernels. The shared FHE power-of-two range `32..=2^17` is checked centrally by `PolyLength`.
Dimension arguments and accessors use `GlweDimension`, re-exported from `primus_lattice`; `.get()` returns `k`. `primus_lattice::LweDimension::from(glwe_size)` explicitly derives the checked extracted LWE dimension `kN` from a GLWE size. Gadget constructors use `DecompositionBaseLog` and `Option<DecompositionLevelCount>` from `primus_decompose`.

Evaluation keys own their layouts and decomposition bases. NTT evaluation takes `input, output, modulus, ntt, workspace`; Fourier evaluation omits `modulus`. Workspaces are reusable workspaces. Preserve the key's transform representation: matching lengths and moduli alone do not prove compatibility.

Both automorphism keys provide coefficient-domain `apply_to`. `NttGlweAutomorphismKey::apply_ntt_to` and `FourierGlweAutomorphismKey::apply_fourier_to` reuse the same key for transform-domain input/output. Fourier evaluation requires the exact FFT table instance used at key generation; direct Fourier input/output can round differently from a coefficient roundtrip.

`NttGlweTraceKey<T>` and `FourierGlweTraceKey<T>` share their automorphism material across the following coefficient-domain operations. `M` denotes the input message; every output phase coefficient may contain evaluation error.

| Trace-key method | Target message |
| --- | --- |
| `apply_to` / `apply_reverse_to` | Constant `N*M[0]` / `M[0]` |
| `apply_partial_to(input, r, ...)` | `d * sum_j M[j*d] X^(j*d)`, where `d=N/r` |
| `apply_reverse_partial_to(input, r, ...)` | `sum_j M[j*d] X^(j*d)` |
| `project_coefficient_to` / `project_coefficients_to` | Constant `M[index]` / constants in selection order |
| `project_prefix_coefficients_to(input, count, ...)` | Constants `M[0]` through `M[count-1]`, with no zero-tail assumption |
| `expand_coefficients_to` | `N` constant GLWEs in coefficient order |
| `expand_partial_coefficients_to(input, count, ...)` | First `count` constants, assuming a zero message tail |
| `pack_lwe_to` / `pack_lwes_to` | Constant LWE message / `sum_i m[i] X^(i*N/p)` for `p` LWEs |

Partial trace's `retained_coefficient_count` (`r`) is a power of two in `1..=N`. It retains equally spaced positions in one GLWE: `N=8, r=2` retains indices 0 and 4. `r=N` copies the input; `r=1` is full trace. Reverse trace scales before each automorphism/addition: NTT multiplies by `2^-1 mod q`; Fourier uses unsigned coefficient `floor(x/2)`. The NTT field operation does not inherit the torus RevHomTrace noise bound.

Projection accepts arbitrary indices, including duplicates and an empty selection. It uses one reverse trace per index and writes `indices.len() * size.glwe_len()` values. Prefix projection accepts any `count` in `0..=N`, uses the same arithmetic, and needs no index array; even `count=1` performs a full reverse trace. Partial expansion instead builds a shared tree in `count` output GLWE blocks, using `count-1` automorphisms after normalizing once by `count`. `count` must be a power of two in `1..=N`; `count=1` copies the input and `count=N` is full expansion. NTT normalization uses the field inverse; Fourier uses unsigned floor division. These paths have different error behavior.

For partial expansion to produce constants, message coefficients `count..N` must be zero. This unchecked premise concerns the message, not ciphertext masks or bodies. Otherwise output `i` targets `sum_j M[i+j*count] X^(j*count)`. All outputs retain ring degree `N` and use the ordinary trace workspace.

Trace-key packing uses the [RevHomTrace algorithm](https://github.com/Stirling75/RevHomTrace/blob/main/src/glwe_conv_rev.rs). Each LWE must have dimension `k*N`, the flattened GLWE secret, and the same modulus and encoding. A batch is a flat slice of `p` complete LWEs, where `p` is a power of two in `1..=N`; slots are adjacent only at `p=N`. Construct `NttGlwePackingWorkspace::new(size, p)` or `FourierGlwePackingWorkspace::new(size, p)` for that fixed count. Single-LWE packing uses a trace workspace. Evaluation reuses output and scratch, checking shapes, indices and backend compatibility before writes.

`NttLwePackingKeySwitchingKey<T>` and `FourierLwePackingKeySwitchingKey<T>` instead convert from an independent LWE secret to the output GLWE secret. `generate` accepts `primus_lwe::LweSecretKeyRef`, the output secret, and GLev parameters. Input dimension can differ from `k*N`; input and output must use the same ciphertext modulus and message encoding.

| Packing-key method | Target message |
| --- | --- |
| `key_switch_to` | One LWE message as a constant GLWE |
| `pack_lwes_to` | `sum_i m[i] X^i`, for any `1 <= p <= N` |

The batch input is a flat slice of complete LWEs. These keys write consecutive message coefficients and require neither a power-of-two count nor trace keys. Construct the existing `NttGlweKeySwitchingWorkspace::new(output_size.glwe_size())` or Fourier counterpart once; it supports changing batch counts. Batch evaluation groups decomposition digits into polynomials and streams the transformed key; a single LWE uses scalar digits without digit transforms. Both paths perform one final inverse transform per output component. The zero target-message tail can still contain noise. Decoding margin must cover input noise, secret-weighted decomposition error and accumulated key noise; Fourier also incurs floating-point error. Storage is `input_dimension * output_size.glev_len()` residues for NTT, or `input_dimension * output_size.fourier_glev_len()` complex values for Fourier.

`NttGlweSchemeSwitchKey<T>` and `FourierGlweSchemeSwitchKey<T>` convert a coefficient-domain GLev into a GGSW in the key's transform domain using `apply_to`. Both secret representations passed to `generate` must represent the same secret. Construct `primus_lattice::workspace::{NttGlweExternalProductWorkspace, FourierGlweExternalProductWorkspace}` with `key.key_size()`. These buffers can be shared with other external products: `rebind` changes decomposition levels without allocation when the GLWE layout is unchanged; restore `key.key_size()` before scheme switching. The output inherits the input GLev's gadget scaling; `key.key_basis()` only controls external-product decomposition and can differ from the output basis. Each mask row uses an encryption of the negated secret polynomial; the body row is transformed directly from the input. Fourier products accumulate directly into output without an inverse/forward FFT roundtrip.

## Features

Default features are empty: parameters, coefficient ciphertexts and signed secrets need no transform backend. `ntt` / `fourier` enable their keys, conversions, encryption/decryption, evaluation and workspaces, forwarding the capability to lattice. `fourier` does not select a concrete FFT engine; `rustfft` / `tfhe-fft` also enable `fourier` and the corresponding implementation. All backend features can be combined. `simd` propagates only to active arithmetic dependencies without activating a transform or FFT engine.

Tests, examples and benchmarks declare their representations and engines in `required-features`. Mixed NTT/Fourier targets require `ntt` and their specified engines. Use `--features ntt,rustfft,tfhe-fft` for complete ordinary validation; Cargo skips entire targets whose requirements are missing.

## Further reading

Public contracts are documented in the [API sources](src). The [test and benchmark guide](benches/README.md) records coverage, workloads and reproduction commands; workspace validation entry points are in the [testing guide](../../guides/development/testing.md).
