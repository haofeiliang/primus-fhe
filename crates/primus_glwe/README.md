# primus_glwe

[English](README.md) | [简体中文](README.zh_CN.md)

Single-modulus GLWE keys and operations, with separate NTT and native-torus Fourier representations. Here `k` is the GLWE dimension and `N` the polynomial length.

## Keys and representation

| Type | Storage and role |
| --- | --- |
| `GlweSecretKey<T>` | Signed coefficient polynomials; sampling and input to key conversion/generation |
| `NttGlweSecretKey<T>` | Canonical NTT residues modulo `q`; NTT encryption and decryption |
| `FourierGlweSecretKey` | Integer-scaled Fourier secret polynomials; native-torus Fourier encryption and decryption |
| `NttGlwePublicKey<S>` | One NTT encryption of zero; public-key encryption |

Generate a secret with `generate_pair` for the chosen NTT or Fourier backend. It samples once and returns the signed coefficient key and its matching transform:

```rust,ignore
let (coeff_sk, ntt_sk) = NttGlweSecretKey::generate_pair(&ntt_params, &ntt_table, &mut rng);
let (coeff_sk, fourier_sk) =
    FourierGlweSecretKey::generate_pair(&fourier_params, &mut fft, &mut rng);
```

Use `GlweSecretKey::generate` when only the signed coefficient key is needed. Use `from_coeff_secret_key` to transform an existing coefficient key. Fixed-weight distributions apply to all `k*N` coefficients, not separately to each polynomial. Secret buffers are erased on drop, including unwinding during generation.

Keys do not store transform tables: preserve the modulus and transform representation used at generation. Raw public-key bytes use native endianness and contain no parameter metadata.

## Encryption and decryption

NTT secret, Fourier secret and NTT public keys share these ordinary encryption methods:

| Method | Input | Output storage |
| --- | --- | --- |
| `encrypt` / `encrypt_to` | Plaintext in `[0, t)`, unsigned embedding | Allocate / overwrite |
| `encrypt_centered_to` | Plaintext in `[0, t)`, centered embedding | Overwrite |
| `encrypt_encoded_to` | Already encoded ciphertext-ring coefficients | Overwrite; no plaintext scaling |
| `encrypt_zeros` / `encrypt_zeros_to` | Zero polynomial | Allocate / overwrite |

Secret keys provide `decrypt`, `decrypt_to` and `phase_to`. Phase extraction returns noisy coefficient-domain values without decoding; both plaintext embeddings use the same decoder. Decrypted polynomials use the ciphertext coefficient type `T`; applications handle output type conversion.

```text
ntt_sk.encrypt_to(input, output, params, ntt_table, rng)
ntt_pk.encrypt_to(input, output, params, ntt_table, rng, context)
fourier_sk.encrypt_to(input, output, params, fft, rng, context)
ntt_sk.phase_to(input, output, modulus, ntt_table)
fourier_sk.phase_to(input, output, fft, context)
```

NTT-domain secret-key operations need no context. Fourier operations use `FourierGlweEncryptContext<T>` / `FourierGlweDecryptContext`; NTT public encryption uses `NttGlwePublicEncryptContext<T>`. Construct these with `N` and reuse them at that length. Contexts hold scratch, not parameters, and erase secret intermediates on drop.

For coefficient ciphertexts, `NttGlweSecretKey` provides `encrypt_coeff_to`, `phase_coeff_to`
and `decrypt_coeff_to`. They take an additional N-element scratch slice as the last argument,
reuse all buffers, and save the body's forward NTT. Encryption accepts unsigned plaintexts
and matches `encrypt_to` followed by inverse NTT exactly for the same RNG state.
Scratch needs no initialization and retains secret-dependent products after encryption;
use an erasing owner such as `zeroize::Zeroizing<Vec<T>>`.

`_to` paths reuse output and scratch. Checked layout and transform-length mismatches fail before output writes; matching lengths do not establish transform representation compatibility. Invalid plaintext values may panic after partial writes or randomness consumption. Encoded NTT inputs must be canonical residues in `[0, q)`; callers guarantee this range.

## Gadget and truncated ciphertexts

`encrypt_glev_to` and `encrypt_ggsw_to` apply the gadget basis to a coefficient-domain ring polynomial without plaintext scaling. A GGSW control bit is therefore the constant polynomial `0` or `1`. Both use a gadget context constructed from `GadgetSize`: GLev requires a matching polynomial length; GGSW also requires a matching level count.

Use `GlevParameters::try_with_basis(&glwe_params, basis)` to reuse an existing decomposition basis. It takes ownership without rebuilding the basis and checks the modulus and gadget layout. `try_with_glwe_params` constructs a basis from its logarithm and level count instead; both return `GlevParameterError`.

`encrypt_ggsw_constant_batch_to` encrypts a slice of ring constants into consecutive GGSWs, with one batch validation and no temporary allocation. NTT takes canonical residues, prepares each constant level by direct broadcast, and writes `input.len() * params.ggsw_len()` values; Fourier takes native-ring values and writes `input.len() * params.fourier_ggsw_len()` complex values. Fourier preserves native-ring scaling followed by the FFT for each level; adjacent equal constants reuse those transforms within the batch. Preparation time therefore depends on the input sequence. Empty batches still validate shared resources and consume no randomness.

`NttGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to` writes coefficient GGSWs directly. It preserves the exact ciphertext and RNG consumption of NTT encryption followed by inverse transforms, while avoiding a forward NTT of each sampled body. Only the gadget context's polynomial length must match; its level count is unused. Output has `input.len() * params.ggsw_len()` values.

`FourierGlweSecretKey::encrypt_ggsw_constant_batch_coeff_to` writes coefficient GGSWs using the same encryption followed by inverse FFT. It takes an additional `params.fourier_ggsw_len()` scratch slice, reuses one transformed GGSW, and preserves the Fourier path's rounding and RNG consumption.

NTT `encrypt_truncated_zeros`, `phase_truncated` and `decrypt_truncated` operate on coefficient ciphertexts with a full mask and at most `N` body coefficients. Phase extraction and decryption return only the retained coefficients, while their internal scratch still holds full polynomials.

## Evaluation primitives

Evaluation keys own their layouts and decomposition bases. NTT evaluation takes `input, output, modulus, ntt, context`; Fourier evaluation omits `modulus`. Contexts are reusable workspaces. Preserve the key's transform representation: matching lengths and moduli alone do not prove compatibility.

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

For partial expansion to produce constants, message coefficients `count..N` must be zero. This unchecked premise concerns the message, not ciphertext masks or bodies. Otherwise output `i` targets `sum_j M[i+j*count] X^(j*count)`. All outputs retain ring degree `N` and use the ordinary trace context.

Trace-key packing uses the [RevHomTrace algorithm](https://github.com/Stirling75/RevHomTrace/blob/main/src/glwe_conv_rev.rs). Each LWE must have dimension `k*N`, the flattened GLWE secret, and the same modulus and encoding. A batch is a flat slice of `p` complete LWEs, where `p` is a power of two in `1..=N`; slots are adjacent only at `p=N`. Construct `NttGlwePackingContext::new(size, p)` or `FourierGlwePackingContext::new(size, p)` for that fixed count. Single-LWE packing uses a trace context. Evaluation reuses output and scratch, checking shapes, indices and backend compatibility before writes.

`NttLwePackingKeySwitchingKey<T>` and `FourierLwePackingKeySwitchingKey<T>` instead convert from an independent LWE secret to the output GLWE secret. `generate` accepts `primus_lwe::LweSecretKeyRef`, the output secret, and GLev parameters. Input dimension can differ from `k*N`; input and output must use the same ciphertext modulus and message encoding.

| Packing-key method | Target message |
| --- | --- |
| `key_switch_to` | One LWE message as a constant GLWE |
| `pack_lwes_to` | `sum_i m[i] X^i`, for any `1 <= p <= N` |

The batch input is a flat slice of complete LWEs. These keys write consecutive message coefficients and require neither a power-of-two count nor trace keys. Construct the existing `NttGlweKeySwitchingContext::new(output_size.glwe_size())` or Fourier counterpart once; it supports changing batch counts. Batch evaluation groups decomposition digits into polynomials and streams the transformed key; a single LWE uses scalar digits without digit transforms. Both paths perform one final inverse transform per output component. The zero target-message tail can still contain noise. Decoding margin must cover input noise, secret-weighted decomposition error and accumulated key noise; Fourier also incurs floating-point error. Storage is `input_dimension * output_size.glev_len()` residues for NTT, or `input_dimension * output_size.fourier_glev_len()` complex values for Fourier.

`NttGlweSchemeSwitchKey<T>` and `FourierGlweSchemeSwitchKey<T>` convert a coefficient-domain GLev into a GGSW in the key's transform domain using `apply_to`. Both secret representations passed to `generate` must represent the same secret. Construct `primus_lattice::context::{NttGlweExternalProductContext, FourierGlweExternalProductContext}` with `key.key_size()`. These buffers can be shared with other external products: `rebind` changes decomposition levels without allocation when the GLWE layout is unchanged; restore `key.key_size()` before scheme switching. The output inherits the input GLev's gadget scaling; `key.key_basis()` only controls external-product decomposition and can differ from the output basis. Each mask row uses an encryption of the negated secret polynomial; the body row is transformed directly from the input. Fourier products accumulate directly into output without an inverse/forward FFT roundtrip.

## Source and tests

[Secret keys](src/secret_key), [public keys](src/public_key), [key switching](src/key_switch), [automorphism](src/automorphism), [trace/packing](src/trace), [packing key switching](src/packing_key_switch) and [scheme switching](src/scheme_switch) contain the public contracts and implementation details.

Tests are grouped by operation: ordinary key workflows, gadget phases and external products, constant-batch equivalence, CMUX, key switching, automorphism, scheme switching, and trace/expansion/packing. `tests/common` holds the small schoolbook phase oracle shared by evaluation tests. Boundary rejection and capacity zeroization have dedicated test binaries. Fourier constant batches, automorphism, trace, packing key switching and scheme-switching tests exercise both RustFFT and tfhe-fft.

```sh
cargo test -p primus_glwe
cargo clippy -p primus_glwe --all-targets -- -D warnings
cargo +nightly test -p primus_glwe --features simd
```

## Benchmarks

```sh
cargo bench -p primus_glwe --bench encryption
cargo bench -p primus_glwe --bench primitives
cargo bench -p primus_glwe --bench key_conversion
# Check every case without collecting timing samples:
cargo bench -p primus_glwe -- --test
```

All benches use `(k, N) = (1, 1024)` and `(2, 4096)`. Each iteration performs one operation with reusable output/scratch; key/table construction and allocation remain outside timing. Parameters and fixed seeds are recorded in the bench sources. These workloads track regressions rather than compare matched security; they are not security parameter recommendations.

| Bench | Work measured |
| --- | --- |
| [encryption](benches/encryption.rs) | Secret/public encryption, secret decryption (including coefficient NTT paths), GLev/GGSW generation and batches of 8 constant GGSWs; includes sampling, coding and required transforms |
| [primitives](benches/primitives.rs) | Ordinary/reverse trace; projection and partial expansion for 8 and `N/8` coefficients; full expansion; packing 1, 8 and `N` LWEs; direct Fourier automorphism on both FFT backends |
| [key_conversion](benches/key_conversion.rs) | Independent-key packing of 1, 8 and `N` LWEs (input dimension 512; single-LWE cases cover bases `2^3` and `2^10`); NTT/Fourier GLev-to-GGSW scheme switching |

Ordinary and reverse trace measure their respective API scales. Projection/partial expansion use the same encrypted zero-tail message and report output-message throughput. Codec variants are benchmarked in `primus_encoding`.
