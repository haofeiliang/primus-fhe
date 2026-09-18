# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption,
and Boolean semantics. Transform tables, server keys and evaluator scratch belong
to [NTT](../primus_tfhe_glwe_ntt/README.md) or
[Fourier](../primus_tfhe_glwe_fourier/README.md).
See the [shared capability and encoding guide](../primus_tfhe/README.md).

The shared layer and both backends use the same role names: `Encryptor`, `Decryptor`,
`ClientKey`, `EncryptionKey`, `PbsOrder` and `TfheParameters`. Client ciphertexts are
`LweCiphertext`; GLWE describes the PBS accumulator family.

## Parameters and external key domain

Prefer `TfheParameters::try_from_config(TfheConfig { .. })`: specify `t/q` once in
`small_lwe`, then name the accumulator dimension, length, secret distribution and
noise, the blind-rotation/key-switch `DecompositionConfig { log_basis, level_count }`,
and PBS order. `level_count: None` retains the full decomposition; bases inherit
the shared modulus. GLWE evaluation keys inherit accumulator noise. Use the direct
constructor below when supplying existing ring parameters or prepared bases.

`TfheParameters::try_new(small_lwe, accumulator_glwe, blind_rotation_basis,
key_switching_basis, order)` derives BSK layout from the accumulator and the
padded key-switch target from the small LWE. Plaintext and ciphertext moduli must
match, the small secret must belong to a binary or ternary family, and `n <= kN`. The rotation domain `2N`
must be representable by the input coefficient type `T`.
Ternary LWE keys store `0/1/q-1`; padded GLWE key construction maps `q-1` to signed `-1`.
Uniform, custom-probability, fixed-weight and fixed-composition distributions use the
same workflow. Gaussian small secrets are unsupported.

| `PbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Use `external_lwe_dimension()` to
allocate outputs and `client_key.external_lwe_secret_key()` to borrow that secret.
`accumulator_glwe()` describes the accumulator domain; `blind_rotation_ggsw()`
describes its GGSW controls, and `glwe_key_switching()` describes the ring key switch.
Basis/layout compatibility does not prove actual secret identity.

## Clients and LUTs

`ClientKey::generate(&parameters, &mut rng)` generates client secrets without
transform tables. For a paired client/server key, use `context.try_generate_keys(circuit_bootstrap, rng)`;
the backend reuses the transformed secret during server-key generation.
The context also exposes `encryptor` / `decryptor`.
Generic client encryption takes `T`, and decryption returns
`Result<T, TfheClientError>` with a canonical residue in `[0,t)`; applications
handle message type conversions. Boolean encryption takes `bool`; decryption
returns `Result<bool, BooleanError>` and validates the Boolean value.
Direct family construction uses `Encryptor::try_new` and `Decryptor::try_new`.
Encryption accepts either `ClientKey` or an `LwePublicKey` generated with
`client_key.try_generate_public_key(parameters, rng)`; decryption needs the client key.
The public key follows the selected external domain, including the signed `kN` secret.
See [LWE public-key noise and identity requirements](../primus_lwe/README.md#public-key-encryption).

`encrypt`, `encrypt_padded` and `encrypt_centered` have corresponding
`*_to(message, output, rng)` methods. These reuse output storage; message or dimension
errors leave output and RNG unchanged. For front-half LUT input, use `encrypt_padded`.
Compile ordinary LUTs through `context.parameters().compile_lookup_table_fn(...)`
and the corresponding slice, interleaved or odd full-domain methods.

LUT compilation takes an explicit output `RoundedCodec` first. Reuse
`parameters.input_plaintext_codec()` for the input scale, or construct a
codec with another plaintext modulus and the same ciphertext modulus. Decode
that output with `output_codec.decode_value(decryptor.decrypt_phase(&output)?)`.
See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding)
for range checks, raw output and subsequent PBS contracts.

For odd full domains, use `compile_odd_full_domain_lookup_table_fn` / `_slice`
and ordinary `encrypt`. The output codec and PBS evaluator are unchanged. See
[odd full-domain PBS](../primus_tfhe/README.md#odd-full-domain-pbs) for capacity,
folded-center and noise requirements.

For bounded two-input functions, use the shared `BivariateLookupTable` to pack
`x+B*y` and pass its ordinary LUT to the existing evaluator. See
[bounded two-input PBS](../primus_tfhe/README.md#bounded-two-input-pbs) for input
bounds, common encoding and the amplified-error budget.

## Boolean and CBS

Boolean operations use `LweCiphertext<T>` with unsigned rounded `0/1` encoding modulo 4.
`BooleanEncryptor` accepts a secret or public key and provides `encrypt` / `encrypt_to`;
`BooleanDecryptor` requires the client secret and rejects decoded values other than 0/1.
Both client types use `try_new(parameters, key)` and require plaintext modulus 4.
Backend `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` factories
bind the same parameters. Reuse `evaluate_binary_to`, `not_to` and `mux_to`; the
shared evaluator owns affine preprocessing, internal LUT scales and correction.
`BooleanEvaluator<T, M, E>::try_new` also accepts a custom PBS implementation, whose
parameters must match the supplied family parameters. The evaluator retains the
modulus, dimension and encoding constants it needs without borrowing those parameters.
Raw inputs must use the Boolean encoding and the matching external key; these
properties cannot be verified from an LWE ciphertext.

CBS is an optional facility in both backends, with separate output basis,
trace/scheme-switch parameters and keys. Both PBS orders and classic binary/ternary
small secrets are supported. CBS outputs remain under the accumulator secret and
use gadget scales; sparse CBS is not supported.

## Examples and validation

Follow the backend basic examples to see both orders, public-key input, LUTs and
Boolean operations with reused output. All example fixtures, including NTT's
`boolean_parameters()`, are for development, not production recommendations.

```sh
cargo test -p primus_tfhe_glwe
cargo doc -p primus_tfhe_glwe --no-deps
```
