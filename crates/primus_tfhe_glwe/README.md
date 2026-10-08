# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption, and Boolean semantics. Transform tables, server keys and evaluator scratch belong to [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md). See the [shared capability and encoding guide](../primus_tfhe/README.md).

The shared layer and both backends use the same role names: `Encryptor`, `Decryptor`, `ClientKey`, `EncryptionKey`, `PbsOrder` and `TfheParameters`. Client ciphertexts are `LweCiphertext`; GLWE describes the PBS accumulator family.

This family uses coefficient types, sparse key storage, parameters and client operations by default, without pulling in NTT/FFT. Select a concrete backend below for homomorphic evaluation; its normal dependencies enable the required representation.

`TfheConfig::poly_length` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

## Parameters and external key domain

`TfheParameters<T, M>` and clients share one ciphertext modulus type `M`; backend aliases fix their modulus implementation.

Prefer `TfheParameters::try_from_config(TfheConfig { .. })`: supply a codec-free `LweEncryptionParameters` in `small_lwe`, specifying `q` once, then name the accumulator dimension, length and secret distribution, blind-rotation and key-switch configurations, and PBS order. Both `blind_rotation` and `key_switching` use `GadgetEncryptionConfig { decomposition, noise_standard_deviation }`, with `DecompositionConfig { log_basis, level_count }` in `decomposition`. `level_count: None` selects the maximum supported level count, which may still omit low bits (see [decomposition precision](../primus_decompose/README.md)); bases inherit the shared modulus. `blind_rotation.noise_standard_deviation` supplies BR and accumulator encryption noise; `key_switching.noise_standard_deviation` independently selects ring-KS noise. The padded KS target is constructed directly from its GLWE layout, sampling state and basis, without a message codec. CBS `output`, `trace` and `scheme_switch` each select a `DecompositionConfig`; trace and scheme-switch rows inherit BR/accumulator encryption noise. Use the direct constructor below when supplying existing ring parameters or prepared bases.

Changing KS noise affects only ring-KS key generation, in either PBS order. Accumulator noise also controls fresh external encryption for KS→BR; fresh small-LWE noise remains independently configurable, while CBS trace/scheme-switch rows inherit accumulator noise. All standard deviations use coefficient units. Invalid KS sampling parameters return `TfheParameterError::KeySwitchingEncryption` during construction.

Dimension choices use `LweDimension` and, for GLWE, `GlweDimension`; decomposition choices use `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Construct these checked units once and pass parameter accessors directly to workspaces. `.get()` exposes the integer at raw storage or kernel boundaries; composed lengths and basis/modulus compatibility remain constructor checks.

`TfheParameters::try_new(small_lwe, blind_rotation_ggsw, key_switching, order)` accepts the small LWE sampling domain, prepared GGSW parameters and `GadgetEncryptionConfig<ApproxSignedBasis<T>>`, then derives the padded key-switch target. The prepared KS basis is moved into the parameters without rebuilding it. Ciphertext moduli must match, the small secret must belong to a binary or ternary family, and `n <= kN`. The rotation domain `2N` must be representable by the input coefficient type `T`. Ternary LWE keys store `0/1/q-1`; padded GLWE key construction maps `q-1` to signed `-1`. Uniform, custom-probability, fixed-weight and fixed-composition distributions use the same workflow. Gaussian small secrets are unsupported.

| `PbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Backend `context.allocate_lwe_ciphertext()` uses `external_lwe_dimension()` to allocate outputs; `client_key.external_lwe_secret_key()` borrows that secret. `blind_rotation_ggsw()` describes the accumulator ring domain and GGSW controls, and `glwe_key_switching()` describes the ring key switch. Basis/layout compatibility does not prove actual secret identity.

`ClientKey::new` imports coefficient secrets. Full setup and BR→KS external binding check the owning LWE secret’s recorded modulus; a different modulus returns `TfheKeyError::LweSecretKeyModulusMismatch`, even for identical binary coefficients. These boundaries also check the small-LWE binary/ternary coefficient domain and return `TfheKeyError::InvalidLweSecretKeyCoefficient` on invalid values. Gaussian accumulator secrets remain supported; backend magnitude requirements still apply.

## Sparse coefficient keys

`SparseGlweBootstrappingKey<T, M>` owns the shared coefficient GGSWs, public bucket map, layout, modulus and basis. The NTT backend uses `M = BarrettModulus<T>`; Fourier uses `NativeModulus<T>`. Both re-export the family type. `bucket(i)` borrows the increasing input indices and GGSWs, with one additional dummy last.

Prefer the backend `KeyGenerator` for encryption. `try_new(data, map, hamming_weight, &ggsw_parameters)` imports already prepared coefficient controls and checks their combined layout without transforming or copying the ciphertexts. The encrypted assignment, actual secrets and noise budget remain the producer's responsibility. Raw sparse BR runs through the backend's `SparseGlweBlindRotationWorkspace::blind_rotate_lookup_table_to(&key, input, lut, output, table_or_fft)`; ordinary PBS/CBS callers continue using their evaluators.

## Clients and LUTs

Use `PbsMessageConfig::new(t_in)` for equal input/output message moduli, or `.with_output_modulus(t_out)` to override the output. `parameters.pbs_codecs(messages)?` prepares Rounded codecs; `parameters.factorized_pbs_codecs(messages)?` prepares Rounded input and Scaled outputs for MVB. Both return named `input_codec()`, `lut_output_codec()` and `output_codec()` roles, deriving the correct ciphertext moduli without copying keys or allocating buffers. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding) for compilation and output decoding.

`ClientKey` remains the complete setup bundle for generating server keys. For ordinary messages, use `let external_secret = client.external_lwe_secret_key();`: it borrows `ExternalLweSecretKey::SmallLwe(&small)` for BR→KS or `ExternalLweSecretKey::ExtractedGlwe(&glwe)` for KS→BR. These variants also accept independently retained owners; `into_parts()` moves both keys out without copying. Message clients check only that external role, while setup checks both secrets. Ring clients accept only `client.glwe_secret_key()`.

Prefer `context.try_generate_keys(blind_rotation, circuit_bootstrap, rng)` for paired client/server keys. Use `ClientKey::generate(&parameters, &mut rng)` when only coefficient secrets are needed.

Choose a `RoundedCodec` independently of key generation. Bind the external key with the context's `encryptor(external_secret, &codec)`, `public_encryptor(&public, &codec)` and `decryptor(external_secret, &codec)`. `parameters.try_generate_public_key(external_secret, rng)` creates the corresponding LWE public key. Each PBS order uses its own external secret and dimension. See the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for its total noise requirements.

Client reads/writes accept borrowed LWE views: pass `output.as_mut_view()` to `encrypt_to` and `ciphertext.as_view()` to `decrypt` or `decrypt_phase`. Allocating encryption methods still return `LweCiphertext<T>`; Boolean clients follow the same convention.

For LUT results, pass the returned-output codec to `decryptor(external_secret, &output_codec)` and call `decrypt()`. Both Rounded and Scaled codecs are accepted, including MVB output with a different message modulus. The prepared decoding state is copied; the secret remains borrowed. `decrypt_phase` remains available for diagnostics.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. Prepare codecs with `parameters.pbs_codecs(PbsMessageConfig::new(t_in))?`; output message moduli default to the input choice. Call `.with_output_modulus(t_out)` before preparation to override it. `parameters.lookup_table_compiler(&codecs)?` binds the selected input/output encodings directly; call `compile_fn` / `compile_slice`, or the interleaved / odd full-domain methods. Bind the output decryptor to `codecs.output_codec()`. Input, LUT and returned ciphertexts share one ciphertext modulus. ManyLUT, Boolean, bivariate and MVB interfaces and encodings are described in the [common guide](../primus_tfhe/README.md).

## Boolean and CBS

`let (input_codec, ring_message_codec) = parameters.circuit_bootstrap_codecs(8, 8)?;` prepares Rounded input and Scaled candidate ring messages for CBS → CMux with independent plaintext moduli. Parameters supply the common ciphertext modulus q=Q; only these two codecs are prepared, without an extra returned-output codec. The ring codec does not describe CBS output gadget scales. Capacity and noise margins remain operation contracts; existing concrete codecs can still be bound directly.

Compile a custom integer function with `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_lookup_table_slice`. Bind the resulting `CircuitBootstrapLookupTable` with `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?`; `try_new` keeps the identity default. Output lanes use `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other ring integers require the external-product noise contract. Both backends support classic binary/ternary and sparse binary programs.

Both backends provide `context.try_generate_circuit_bootstrap_keys(blind_rotation, cbs_config, rng)` for a client and a `CircuitBootstrapServerKey` containing only ring-output material. CBS is required in this bundle; ordinary return material is not generated. GLWE KS→BR still includes its input KS. For mixed PBS/CBS, retain the complete `ServerKey`. See [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

With an explicit t=4 `RoundedCodec` argument, contexts provide `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. These use ordinary PBS material; see the [common Boolean contract](../primus_tfhe/README.md#boolean-gates) for calls and chaining.

Input encoding and ManyLUT capacity are checked at CBS program binding: both backends use `CircuitBootstrapEvaluator::try_new(&resources, key, &input_codec)`. The default constructor uses the key's parameters; `try_with_parameters` explicitly selects a compatible alternate output basis. The same keys can serve several message moduli, provided each program fits and has sufficient noise margin. `accumulator_client(client.glwe_secret_key(), scaled_codec)` independently binds ordinary ring messages; its `ScaledCodec` need not use the input LWE message modulus.

CBS is an optional facility in both backends, with separate output basis, trace/scheme-switch parameters and keys. Both PBS orders support classic binary/ternary and sparse binary keys. CBS outputs remain under the accumulator secret and use gadget scales. The family defines `CircuitBootstrapParameters<T, M>`; backends provide concrete modulus aliases. Output bases with the same level count can reuse the scheme-switch key; numerical and transform requirements belong to the corresponding backend contracts.

`CircuitBootstrapParameters::try_from_config` derives trace and scheme-switch parameters from BR, preserving the same GLWE layout and sharing its immutable sampler state through `Arc`. Their gadget bases and random draws remain independent.

Backends support independent BR, ring KS and CBS material alongside convenient complete `ServerKey` generation. Independent CBS component generation takes only the accumulator secret. Independent BR→KS CBS needs no ring KS, while KS→BR still needs it to prepare the input. Ordinary PBS requires both BR and ring KS in either order. See the backend guides for APIs and examples.

## Examples

Backend basic examples show default encoding and reusable ordinary PBS storage; basic examples use BR→KS, and MVB examples use KS→BR. Independent output encoding is explained in the shared guide. MVB and CBS have dedicated examples; Boolean usage is in the [shared guide](../primus_tfhe/README.md#boolean-gates). All fixtures are for development, not production recommendations.

## Further reading

[Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
