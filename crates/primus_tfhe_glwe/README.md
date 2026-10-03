# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption, and Boolean semantics. Transform tables, server keys and evaluator scratch belong to [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md). See the [shared capability and encoding guide](../primus_tfhe/README.md).

The shared layer and both backends use the same role names: `Encryptor`, `Decryptor`, `ClientKey`, `EncryptionKey`, `PbsOrder` and `TfheParameters`. Client ciphertexts are `LweCiphertext`; GLWE describes the PBS accumulator family.

This family uses only coefficient types, parameters and client operations by default, without pulling in NTT/FFT. Select a concrete backend below for homomorphic evaluation; its normal dependencies enable the required representation.

## Parameters and external key domain

`TfheParameters<T, M>` and clients share one ciphertext modulus type `M`; backend aliases fix their modulus implementation.

Prefer `TfheParameters::try_from_config(TfheConfig { .. })`: supply a codec-free `LweParametersInner` in `small_lwe`, specifying `q` once, then name the accumulator dimension, length, secret distribution and noise, the blind-rotation/key-switch `DecompositionConfig { log_basis, level_count }`, and PBS order. `level_count: None` selects the maximum supported level count, which may still omit low bits (see [decomposition precision](../primus_decompose/README.md)); bases inherit the shared modulus. Ordinary BR and KS keys inherit accumulator noise. The padded KS target is constructed directly from its GLWE layout, sampling state and basis, without a message codec. CBS trace and scheme-switch keys use the same codec-free construction with their separately configured noise. Use the direct constructor below when supplying existing ring parameters or prepared bases.

Dimension choices use `LweDimension` and, for GLWE, `GlweDimension`; decomposition choices use `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Construct these checked units once and pass parameter accessors directly to workspaces. `.get()` exposes the integer at raw storage or kernel boundaries; composed lengths and basis/modulus compatibility remain constructor checks.

`TfheParameters::try_new(small_lwe, blind_rotation_ggsw, key_switching_basis, order)` accepts the small LWE sampling domain and prepared GGSW parameters, then derives the padded key-switch target. Ciphertext moduli must match, the small secret must belong to a binary or ternary family, and `n <= kN`. The rotation domain `2N` must be representable by the input coefficient type `T`. Ternary LWE keys store `0/1/q-1`; padded GLWE key construction maps `q-1` to signed `-1`. Uniform, custom-probability, fixed-weight and fixed-composition distributions use the same workflow. Gaussian small secrets are unsupported.

| `PbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Backend `context.allocate_lwe_ciphertext()` uses `external_lwe_dimension()` to allocate outputs; `client_key.external_lwe_secret_key()` borrows that secret. `blind_rotation_ggsw()` describes the accumulator ring domain and GGSW controls, and `glwe_key_switching()` describes the ring key switch. Basis/layout compatibility does not prove actual secret identity.

`ClientKey::new` imports coefficient secrets. Full setup and BR→KS external binding check the owning LWE secret’s recorded modulus; a different modulus returns `TfheKeyError::LweSecretKeyModulusMismatch`, even for identical binary coefficients. These boundaries also check the small-LWE binary/ternary coefficient domain and return `TfheKeyError::InvalidLweSecretKeyCoefficient` on invalid values. Gaussian accumulator secrets remain supported; backend magnitude requirements still apply.

## Clients and LUTs

`ClientKey` remains the complete setup bundle for generating server keys. For ordinary messages, use `let external_secret = client.external_lwe_secret_key();`: it borrows `ExternalLweSecretKey::SmallLwe(&small)` for BR→KS or `ExternalLweSecretKey::ExtractedGlwe(&glwe)` for KS→BR. These variants also accept independently retained owners; `into_parts()` moves both keys out without copying. Message clients check only that external role, while setup checks both secrets. Ring clients accept only `client.glwe_secret_key()`.

Prefer `context.try_generate_keys(circuit_bootstrap, rng)` for paired client/server keys. Use `ClientKey::generate(&parameters, &mut rng)` when only coefficient secrets are needed.

Choose a `RoundedCodec` independently of key generation. Bind the external key with the context's `encryptor(external_secret, &codec)`, `public_encryptor(&public, &codec)` and `decryptor(external_secret, &codec)`. `parameters.try_generate_public_key(external_secret, rng)` creates the corresponding LWE public key. Each PBS order uses its own external secret and dimension. See the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for its total noise requirements.

Client reads/writes accept borrowed LWE views: pass `output.as_mut_view()` to `encrypt_to` and `ciphertext.as_view()` to `decrypt` or `decrypt_phase`. Allocating encryption methods still return `LweCiphertext<T>`; Boolean clients follow the same convention.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. `parameters.lookup_table_compiler(&input_codec)?` checks the input ciphertext modulus and creates a reusable compiler whose default output codec is the input codec; call `compile_fn` / `compile_slice`, or the interleaved / odd full-domain methods. `compiler.try_with_output_codec(&codec)?` selects a different output plaintext modulus. Supply a `RoundedCodec` at the same ciphertext modulus and use it to decode `decrypt_phase`. ManyLUT, Boolean, bivariate and MVB interfaces and encodings are described in the [common guide](../primus_tfhe/README.md).

## Boolean and CBS

With an explicit t=4 `RoundedCodec` argument, contexts provide `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. These use ordinary PBS material; see the [common Boolean contract](../primus_tfhe/README.md#boolean-gates) for calls and chaining.

Input encoding and ManyLUT capacity are checked at CBS program binding: both backends use `CircuitBootstrapEvaluator::try_new(&resources, parameters, key, &input_codec)`. The same keys can serve several message moduli, provided each program fits and has sufficient noise margin. `accumulator_client(client.glwe_secret_key(), scaled_codec)` independently binds ordinary ring messages; its `ScaledCodec` need not use the input LWE message modulus.

CBS is an optional facility in both backends, with separate output basis, trace/scheme-switch parameters and keys. Both PBS orders support classic binary/ternary and sparse binary keys. CBS outputs remain under the accumulator secret and use gadget scales. The family defines `CircuitBootstrapParameters<T, M>`; backends provide concrete modulus aliases. Output bases with the same level count can reuse the scheme-switch key; numerical and transform requirements belong to the corresponding backend contracts.

Backends support independent BR, ring KS and CBS material alongside convenient complete `ServerKey` generation. CBS generation takes only the accumulator secret. Independent BR→KS CBS needs no ring KS, while KS→BR still needs it to prepare the input. Ordinary PBS requires both BR and ring KS in either order. See the backend guides for APIs and examples.

## Examples

Backend basic examples show default encoding and reusable ordinary PBS storage; select the PBS order with their `ORDER` constant. Independent output encoding is explained in the shared guide. MVB and CBS have dedicated examples; Boolean usage is in the [shared guide](../primus_tfhe/README.md#boolean-gates). All fixtures are for development, not production recommendations.

## Further reading

[Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
