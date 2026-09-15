# primus_lwe

English | [简体中文](README.zh_CN.md)

Single-modulus LWE key generation, secret-key and public-key encryption, and key
switching for Primus FHE. Ciphertext storage and arithmetic come from
[`primus_lattice`](../primus_lattice/README.md); message encoding uses
[`RoundedCodec`](../primus_encoding/README.md). The crate is under active
development and does not promise a stable API.

## APIs

Public types are exported at the crate root; implementation modules are private.

| Type | Role |
| --- | --- |
| `LweParameters<T, M>` | Dimension, moduli, plaintext codec, secret distribution and precomputed samplers |
| `LweSecretKey<T>` | Owned encoded coefficients; message encryption/decryption, raw batches and packed messages |
| `LweSecretKeyRef<'a, T>` | Borrowed `Encoded` or `Signed` coefficients; raw single-ciphertext operations |
| `LwePublicKey<T>` | Square-matrix Lindner–Peikert-style public-key encryption |
| `LweKeySwitchingKey<T>` | Switches the secret key and optionally the dimension, under the same ciphertext modulus |
| `LweCiphertext<T>` | Alias for `primus_lattice::lwe::Lwe<Vec<T>>` |
| `MultiMsgLweCiphertext<T>` | Alias for `primus_lattice::lwe::MultiMsgLwe<Vec<T>>` |

`encrypt` / `encrypt_batch` allocate output. Their `_to` variants overwrite
caller-owned storage without allocating. Secret-key decryption accepts owned or
borrowed ciphertexts. Public-key ciphertexts use the same decoder and key switch.

## Quick start

This example uses small dimensions to demonstrate storage reuse, independent
public-key batches and key switching. These are not evaluated security parameters.
The imports require `primus_lwe`, `primus_lattice`, `primus_modulus`,
`primus_decompose` and `rand` as direct dependencies of the calling crate.

```rust
use primus_decompose::primitive::ApproxSignedBasis;
use primus_lattice::lwe::{Lwe, LweIter};
use primus_lwe::{LweKeySwitchingKey, LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

fn main() {
    let params = LweParameters::new(
        64,
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret = LweSecretKey::generate(&params, &mut rng);

    let ciphertext = secret.encrypt(3u32, &params, &mut rng);
    assert_eq!(secret.decrypt::<_, u32>(&ciphertext, &params), 3);

    let mut storage = vec![0u32; ciphertext.lwe_len()];
    secret.encrypt_to(2u32, &mut Lwe::new(&mut storage[..]), &params, &mut rng);
    assert_eq!(
        secret.decrypt::<_, u32>(&Lwe::new(&storage[..]), &params),
        2
    );

    let public = LwePublicKey::generate(secret.as_view(), &params, &mut rng);
    let messages = [0u32, 1, 2, 3];
    let batch = public.encrypt_batch(&messages, &params, &mut rng);
    assert_eq!(secret.decrypt_batch::<_, u32>(&batch, &params), messages);
    for (sample, &message) in LweIter::new(&batch, ciphertext.lwe_len()).zip(&messages) {
        assert_eq!(secret.decrypt::<_, u32>(&sample, &params), message);
    }

    let output_params = LweParameters::new(
        32,
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let output_secret = LweSecretKey::generate(&output_params, &mut rng);
    let basis = ApproxSignedBasis::new(params.cipher_modulus_value(), 4, None);
    let switching = LweKeySwitchingKey::generate(
        secret.as_view(),
        &output_secret,
        &output_params,
        basis,
        &mut rng,
    );
    let switched = switching.key_switch_batch(&batch, params.cipher_modulus());
    assert_eq!(
        output_secret.decrypt_batch::<_, u32>(&switched, &output_params),
        messages
    );
}
```

[examples/basic.rs](examples/basic.rs) provides a runnable secret/public-key and
batch workflow: `cargo run -p primus_lwe --example basic`.

## Parameters and encoding

`LweParameters::new(n, t, modulus, secret_distribution, noise_standard_deviation)`
requires `n != 0`, a representable `n + 1`, and the validity conditions of its
codec and samplers. In particular, `t >= 2` and `q > t`. `NativeModulus<T>` denotes
`q = 2^T::BITS`; `cipher_modulus_value()` returns `None` for that modulus and
`Some(q)` for an explicit modulus. The noise standard deviation is measured in
ciphertext coefficient units.

Message APIs take canonical residues in `[0,t)`. `encrypt` uses unsigned
embedding; `encrypt_with_embedding` selects `PlaintextEmbedding::Unsigned` or
`PlaintextEmbedding::Centered` from `primus_encoding`. Centered embedding still
takes unsigned residues: `t - 1` represents `-1`. Both embeddings use the same
`decrypt` and return residues in `[0,t)`.

For an LWE ciphertext `[a, b]`, secret-key encryption sets
`b = <a,s> + e + Encode(message) mod q`. Decoding recovers the message only while
the phase noise stays within the codec's decoding margin. The key, ciphertext
and parameters must agree on dimension and modulus; encoded coefficients must
be canonical residues. Secret keys do not retain a modulus, so callers must
maintain this agreement rather than rely on every mismatch being checked.

Raw single-secret operations are available through `secret.as_view()`:
`encrypt_encoded` / `encrypt_encoded_to` take an already encoded residue, the
modulus, uniform sampler, noise sampler and RNG; `decrypt_phase` returns
`b - <a,s>` without decoding. Passing zero to raw encryption produces a randomized
encryption of zero. `LweSecretKeyRef::Signed` borrows signed coefficients without
allocating an encoded copy. Its dot product uses the modulus backend's
`ReduceDotProductSigned` implementation, which fuses encoding and multiplication.
For explicit `q` they must satisfy `-q < s_i < q`;
all signed values are valid under the native modulus. Raw samplers must use the
same modulus. These range and sampler contracts are caller preconditions.

`secret.decrypt_with_noise(input, params, embedding)` returns the decoded
message and circular distance from its selected encoding; it does not estimate
a noise distribution or certify decryption correctness.

## Public-key encryption

`LwePublicKey::generate` accepts `LweSecretKeyRef`: pass `secret.as_view()`
for an owned LWE secret, or `LweSecretKeyRef::Signed` for GLWE/NTRU
coefficients. Generation does not copy the secret. The borrowed coefficients
must satisfy the view's range contract for the supplied modulus.

The public key stores `n` rows `[A_i, b_i]`, with square `A` and `b = A s + e`:
`n * (n + 1)` coefficients. Encryption samples sparse ternary `r` with
`Pr[0] = 1/2`, `Pr[-1] = Pr[1] = 1/4`, plus fresh Gaussian `e1, e2`, and computes:

```text
a = A^T r + e1
c = b^T r + e2 + Encode(message)
phase = Encode(message) + e^T r + e2 - e1^T s  (mod q)
```

The fresh-noise sampler describes `e1` and `e2`, not the total output noise.
Parameters must account for the long-term and ephemeral secrets, the extra
noise terms and the desired decryption failure probability. Secret-key parameters
are not automatically suitable for public-key encryption. The implementation
checks dimensions and modulus identity, not security or noise bounds. It is a
CPA encryption primitive, without a KEM or CCA transform. Row selection branches
on ephemeral coefficients, so this implementation is not constant-time.

## Independent batches and packed messages

An independent batch is a flat `Vec<T>` or slice containing `count` consecutive
`[a, b]` samples, each of length `n + 1`. The count is not limited by `n`.
There is no separate batch container.
`Lwe::lwe_len()` includes the body. `LweIter` / `LweIterMut` borrow individual
samples from this layout; the iterators themselves omit incomplete tails, while
LWE batch APIs reject them.

- `encrypt_batch_to` requires exactly `messages.len() * (n + 1)` output elements.
  `decrypt_batch_to` requires one output message per sample.
- `encrypt_batch_with_embedding` and its `_to` variant select the embedding.
  Raw batches use `encrypt_encoded_batch` / `encrypt_encoded_batch_to` and
  `decrypt_phase_batch` / `decrypt_phase_batch_to`.
- All secret-key batch methods require owned `LweSecretKey<T>` with encoded
  coefficients. Signed views support single-ciphertext raw operations only.
- Secret-key batching reuses single-message encryption. Public-key batching
  processes small tiles to reuse matrix rows; its RNG order need not match a
  loop of single encryptions. Empty independent batches consume no randomness.
- Public-key encryption packs 16 ephemeral ternary coefficients per random
  word and discards unused bits after each ciphertext or batch tile. Fixed seeds
  do not guarantee identical ciphertext bytes across library versions.
- Batch boundaries validate complete buffer lengths before processing. Invalid
  messages or RNG failures can leave partial output and consume randomness.

Packed encryption has a different layout: `encrypt_multi_messages` stores one
length-`n` mask and `count <= n` bodies, using `n + count` coefficients. Body `i`
uses the mask rotated right by `i`, with the first `i` coefficients negated.
These samples share a mask structure. Use `decrypt_multi_messages` or
`MultiMsgLwe::extract_lwe_at` for this representation, not `LweIter` over its
storage. `encrypt_multi_zeros` constructs packed zero messages; an empty packed
message list still retains and samples the shared mask.

## Key switching

`LweKeySwitchingKey::generate` accepts an `Encoded` or `Signed` input key view,
an encoded `&LweSecretKey<T>` output key, output parameters and an owned
`ApproxSignedBasis<T>`. The key retains its dimensions and decomposition basis,
not a full `LweParameters` object. Entries are ordered by input coefficient,
then decomposition level, then the output ciphertext's `[a, b]` coefficients.
Storage uses `input_dimension * levels * (output_dimension + 1)` elements.

`key_switch` / `key_switch_to` process a single sample; `key_switch_batch` /
`key_switch_batch_to` use independent batch slices. Input and output use their
respective dimensions and the same ciphertext modulus. Key switching does not
re-encode messages or switch moduli. Decryption parameters must preserve the
encoding, and the noise budget must cover decomposition error and key-entry
noise. Batch output equals repeated single key switching coefficient for
coefficient; the `_to` path reuses key entries without heap scratch.

## Source layout

- [src/parameter.rs](src/parameter.rs): parameter validation, codec and samplers.
- [src/secret_key/](src/secret_key/): owned storage and generation (`owned.rs`),
  raw views (`borrowed.rs`), message APIs (`single.rs`), independent batches
  (`batch.rs`) and shared-mask messages (`packed.rs`).
- [src/public_key/](src/public_key/): key generation and single encryption in
  `mod.rs`, tiled encryption in `batch.rs`.
- [src/key_switch/](src/key_switch/): key generation and single switching in
  `mod.rs`, tiled switching in `batch.rs`.
- [src/batch.rs](src/batch.rs): private batch length and layout helpers.

## Features and validation

The default feature set is empty. `simd` enables the underlying crates' nightly
SIMD arithmetic. Run these commands from the workspace root:

```sh
cargo test -p primus_lwe
cargo clippy -p primus_lwe --all-targets -- -D warnings
cargo +nightly test -p primus_lwe --features simd
cargo run -p primus_lwe --example basic
cargo bench -p primus_lwe --bench secret_key
cargo bench -p primus_lwe --bench public_key
cargo bench -p primus_lwe --bench key_switch
```

Tests focus on independent arithmetic checks, key representations, packed
extraction and boundary contracts. The three benchmarks cover secret-key
allocation/reuse and packed encryption, public-key generation and row reuse,
and key-switch generation and single/batch processing.
