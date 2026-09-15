# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption,
and Boolean semantics. Transform tables, server keys and evaluator scratch belong
to [NTT](../primus_tfhe_glwe_ntt/README.md) or
[Fourier](../primus_tfhe_glwe_fourier/README.md).
See the [shared capability and encoding guide](../primus_tfhe/README.md).

## Parameters and external key domain

`GlweTfheParameters::try_new(small_lwe, accumulator_glwe, bootstrapping_basis,
key_switching_basis, order)` derives BSK layout from the accumulator and the
padded key-switch target from the small LWE. Plaintext and ciphertext moduli must
match, the small secret must be binary, and `n <= kN`.

| `GlwePbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Use `ciphertext_lwe_dimension()` to
allocate outputs. Basis/layout compatibility does not prove actual secret identity.

## Clients and LUTs

A backend context generates paired keys and exposes `encryptor` / `decryptor`.
Generic client encryption takes `T`, and decryption returns
`Result<T, GlweClientError>` with a canonical residue in `[0,t)`; applications
handle message type conversions. Boolean encryption takes `bool`; decryption
returns `Result<bool, BooleanError>` and validates the Boolean value.
Direct family construction uses `GlweEncryptor::try_new` and `GlweDecryptor::try_new`.
Encryption accepts either `GlweClientKey` or an `LwePublicKey` generated with
`client_key.try_generate_public_key(parameters, rng)`; decryption needs the client key.
The public key follows the selected external domain, including the signed `kN` secret.
See [LWE public-key noise and identity requirements](../primus_lwe/README.md#public-key-encryption).

`encrypt`, `encrypt_padded` and `encrypt_centered` have corresponding
`*_to(message, output, rng)` methods. These reuse output storage; message or dimension
errors leave output and RNG unchanged. For ordinary LUT input, use `encrypt_padded`.
LUT compilation methods on parameters are also available through backend contexts.

## Boolean and CBS

`BooleanCiphertext` wraps an LWE with the external `0/1` encoding modulo 4.
Backend `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` factories
bind the same parameters. Reuse `evaluate_binary_to`, `not_to` and `mux_to`; the
shared evaluator owns affine preprocessing, internal LUT scales and correction.
Its generic `try_new` also accepts a custom PBS implementation, whose parameters
must match the supplied family parameters.

CBS is an optional backend facility. NTT supports it with separate output basis,
trace/scheme-switch parameters and keys; Fourier GLWE CBS is not implemented.
CBS outputs remain under the accumulator secret and use gadget scales.

## Examples and validation

Follow the backend basic examples to see both orders, public-key input, LUTs and
Boolean operations with reused output. All example fixtures, including NTT's
`boolean_parameters()`, are for development, not production recommendations.

```sh
cargo test -p primus_tfhe_glwe
cargo doc -p primus_tfhe_glwe --no-deps
```
