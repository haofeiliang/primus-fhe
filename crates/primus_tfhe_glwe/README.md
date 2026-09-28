# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption, and Boolean semantics. Transform tables, server keys and evaluator scratch belong to [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md). See the [shared capability and encoding guide](../primus_tfhe/README.md).

The shared layer and both backends use the same role names: `Encryptor`, `Decryptor`, `ClientKey`, `EncryptionKey`, `PbsOrder` and `TfheParameters`. Client ciphertexts are `LweCiphertext`; GLWE describes the PBS accumulator family.

## Parameters and external key domain

`TfheParameters<T, M>` and clients share one ciphertext modulus type `M`; backend aliases fix their modulus implementation.

Prefer `TfheParameters::try_from_config(TfheConfig { .. })`: specify `t/q` once in `small_lwe`, then name the accumulator dimension, length, secret distribution and noise, the blind-rotation/key-switch `DecompositionConfig { log_basis, level_count }`, and PBS order. `level_count: None` selects the maximum supported level count, which may still omit low bits (see [decomposition precision](../primus_decompose/README.md)); bases inherit the shared modulus. GLWE evaluation keys inherit accumulator noise. Use the direct constructor below when supplying existing ring parameters or prepared bases.

`TfheParameters::try_new(small_lwe, accumulator_glwe, blind_rotation_basis, key_switching_basis, order)` derives BSK layout from the accumulator and the padded key-switch target from the small LWE. Plaintext and ciphertext moduli must match, the small secret must belong to a binary or ternary family, and `n <= kN`. The rotation domain `2N` must be representable by the input coefficient type `T`. Ternary LWE keys store `0/1/q-1`; padded GLWE key construction maps `q-1` to signed `-1`. Uniform, custom-probability, fixed-weight and fixed-composition distributions use the same workflow. Gaussian small secrets are unsupported.

| `PbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Backend `context.allocate_lwe_ciphertext()` uses `external_lwe_dimension()` to allocate outputs; `client_key.external_lwe_secret_key()` borrows that secret. `accumulator_glwe()` describes the accumulator domain; `blind_rotation_ggsw()` describes its GGSW controls, and `glwe_key_switching()` describes the ring key switch. Basis/layout compatibility does not prove actual secret identity.

`ClientKey::new` imports coefficient secrets. Parameter binding checks the small-LWE binary/ternary coefficient domain and returns `TfheKeyError::InvalidLweSecretKeyCoefficient` on invalid values. Gaussian accumulator secrets remain supported; backend magnitude requirements still apply.

## Clients and LUTs

Prefer `context.try_generate_keys(circuit_bootstrap, rng)` for paired client/server keys. Use `ClientKey::generate(&parameters, &mut rng)` when only coefficient secrets are needed.

Bind the external key with the context's `encryptor(&client)`, `public_encryptor(&public)` and `decryptor(&client)`. `client.try_generate_public_key(parameters, rng)` creates the corresponding LWE public key. Each PBS order uses its own external secret and dimension. See the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for its total noise requirements.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. `compile_lookup_table_fn` preserves the parameter plaintext modulus by default. To change the output plaintext modulus, supply a `RoundedCodec` at the same ciphertext modulus and use it to decode `decrypt_phase`. ManyLUT, Boolean, bivariate and MVB interfaces and encodings are described in the [common guide](../primus_tfhe/README.md).

## Boolean and CBS

For plaintext modulus t=4, contexts provide `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. These use ordinary PBS material; see the [common Boolean contract](../primus_tfhe/README.md#boolean-gates) for calls and chaining.

CBS is an optional facility in both backends, with separate output basis, trace/scheme-switch parameters and keys. Both PBS orders support classic binary/ternary and sparse binary keys. CBS outputs remain under the accumulator secret and use gadget scales. The family defines `CircuitBootstrapParameters<T, M>`; backends provide concrete modulus aliases. Output bases with the same level count can reuse the scheme-switch key; numerical and transform requirements belong to the corresponding backend contracts.

## Examples

Backend basic examples show default encoding and reusable ordinary PBS storage; select the PBS order with their `ORDER` constant. Independent output encoding is explained in the shared guide. MVB and CBS have dedicated examples; Boolean usage is in the [shared guide](../primus_tfhe/README.md#boolean-gates). All fixtures are for development, not production recommendations.

## Further reading

[Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
