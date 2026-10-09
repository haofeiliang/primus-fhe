# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent GLWE-TFHE parameters, client keys, encryption/decryption, and Boolean semantics. Transform tables, server keys and evaluator scratch belong to [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md). See the [shared capability and encoding guide](../primus_tfhe/README.md).

The shared layer and both backends use the same role names: `Encryptor`, `Decryptor`, `ClientKey`, `EncryptionKey`, `PbsOrder` and `PbsParameters`. Client ciphertexts are `LweCiphertext`; GLWE describes the PBS accumulator family.

This family uses coefficient types, sparse key storage, parameters and client operations by default, without pulling in NTT/FFT. Select a concrete backend below for homomorphic evaluation; its normal dependencies enable the required representation.

`PbsConfig::bsk_poly_length` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

## Experimental paired parameters

`PbsConfig` directly describes PBS/ManyLUT/MVB LWE/ring domains, `bsk_gadget`, `method`, required `key_switching` and `messages`. `CbsConfig { pbs, gadget }` adds CBS decompositions to the same domain; the selector input modulus is `pbs.messages.input_modulus`. Configs are copyable numerical choices without prepared samplers or codecs.

`bsk_dimension` and `bsk_poly_length` describe the ring layout shared by accumulator and BSK ciphertexts. `bsk_secret_distr` samples the ring secret that encrypts the BSK; `bsk_gadget` selects its decomposition and row noise. BR output uses that secret; public `(0, LUT * X^(-b))` initialization samples no encryption noise. The LWE config separately describes the input secret. `method: BlindRotationMethod` selects classic or sparse and its bucket geometry.

`PbsParameters::try_from_config(pbs_config)` returns `PbsParameters` with required KS, the algorithm and default messages. `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` combines it with `CbsGadgetParameters` and the input codec. A backend context owns complete operation state in one Box; `try_from_pbs_config` / `try_from_cbs_config` move prepared parameters in. `parameters()` always borrows the complete PBS domain; `cbs_parameters()` exposes additional CBS capability. `try_with_circuit_bootstrap(gadget)` adds CBS while sharing the common parameters and transform table.

Both PBS and CBS require a `GadgetEncryptionConfig` in `key_switching`; its decomposition and noise are independent of BR. CBS itself produces ring/gadget ciphertexts, while downstream consumers reuse the same KS to return LWE results. Input LWE and ring secrets remain independently sampled. GLWE KS→BR applies KS during input preparation; BR→KS applies it on return.

Prepare parameters with `PbsParameters::try_from_config(pbs_config)`, `CbsParameters::try_from_config(pbs_config, gadget_config)` or `CbsParameters::try_with_config(pbs_parameters, gadget_config)`. The last entry moves existing common state without rebuilding samplers. Move prepared state into a Context by value; BR, trace and scheme-switch retain their existing ring-sampler Arc. Explicit `clone()` may copy LWE sampler data.

Concrete backends provide `experimental::*_U64` teaching configs for PBS, ManyLUT, MVB and CBS. `PbsMessageConfig::new(t)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes only the output. Backend PBS/ManyLUT clients and compilers derive Rounded encoding from these messages; MVB selects Scaled output through its own factories. CBS retains its input codec while the consumer chooses candidate-ring messages. Security and failure probability are unassessed; see [provenance and conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

## Parameters and external key domain

`PbsParameters<T, M>` and clients share one ciphertext modulus type `M`; backend aliases fix their modulus implementation.

The numerical PBS config uses `small_lwe` for its codec-free small LWE domain and `bsk_dimension`, `bsk_poly_length`, `bsk_secret_distr`, `bsk_gadget` for accumulator/BSK ring state. `key_switching` independently selects ring-KS decomposition and noise; `order` selects the PBS chain. Both gadgets use `GadgetEncryptionConfig { decomposition, noise_standard_deviation }` with `DecompositionConfig { log_basis, level_count }`. `level_count: None` selects the maximum supported levels and may omit low bits (see [decomposition precision](../primus_decompose/README.md)). `CbsConfig` adds output/trace/scheme-switch decompositions; its PBS part always retains required KS for input preparation or downstream LWE returns.

Changing KS noise affects only ring-KS key generation, in either PBS order. Accumulator noise also controls fresh external encryption for KS→BR; fresh small-LWE noise remains independently configurable, while CBS trace/scheme-switch rows inherit accumulator noise. All standard deviations use coefficient units. Invalid KS sampling parameters return `TfheParameterError::KeySwitchingEncryption` during construction.

Dimension choices use `LweDimension` and, for GLWE, `GlweDimension`; decomposition choices use `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Construct these checked units once and pass parameter accessors directly to workspaces. `.get()` exposes the integer at raw storage or kernel boundaries; composed lengths and basis/modulus compatibility remain constructor checks.

`PbsParameters::try_from_config` prepares the LWE/ring samplers and chosen decompositions once, then derives the padded KS target. Small secrets must belong to a binary or ternary family, with `n <= kN`; the rotation domain `2N` must fit coefficient type `T`. Ternary LWE keys store `0/1/q-1`; KS-target construction maps `q-1` to signed `-1`. Uniform, custom-probability, fixed-weight and fixed-composition distributions use the same workflow. Gaussian small secrets are unsupported.

| `PbsOrder` | Complete PBS chain | External LWE secret / dimension |
| --- | --- | --- |
| `BootstrapKeyswitch` | BR → ring key switch → compact extraction | Small LWE / `n` |
| `KeyswitchBootstrap` | Inverse extraction → ring key switch → compact extraction → BR → full extraction | GLWE coefficient vector / `kN` |

Both orders return to their external secret. Backend `context.allocate_lwe_ciphertext()` uses `external_lwe_dimension()` to allocate outputs; `client_key.external_lwe_secret_key()` borrows that secret. `blind_rotation_params()` describes the accumulator ring domain and GGSW controls, and `glwe_key_switching()` describes the ring key switch. Basis/layout compatibility does not prove actual secret identity.

`ClientKey::new` imports coefficient secrets. Full setup and BR→KS external binding check the owning LWE secret’s recorded modulus; a different modulus returns `TfheKeyError::LweSecretKeyModulusMismatch`, even for identical binary coefficients. These boundaries also check the small-LWE binary/ternary coefficient domain and return `TfheKeyError::InvalidLweSecretKeyCoefficient` on invalid values. Gaussian accumulator secrets remain supported; backend magnitude requirements still apply.

## Sparse coefficient keys

`SparseGlweBootstrappingKey<T, M>` owns the shared coefficient GGSWs, public bucket map, layout, modulus and basis. The NTT backend uses `M = BarrettModulus<T>`; Fourier uses `NativeModulus<T>`. Both re-export the family type. `bucket(i)` borrows the increasing input indices and GGSWs, with one additional dummy last.

Prefer the backend `KeyGenerator` for encryption. `try_new(data, map, hamming_weight, &ggsw_parameters)` imports already prepared coefficient controls and checks their combined layout without transforming or copying the ciphertexts. The encrypted assignment, actual secrets and noise budget remain the producer's responsibility. Raw sparse BR runs through the backend's `SparseGlweBlindRotationWorkspace::blind_rotate_lookup_table_to(&key, input, lut, output, table_or_fft)`; ordinary PBS/CBS callers continue using their evaluators.

## Clients and LUTs

Choose `config.messages` with `PbsMessageConfig::new(t_in)` and an optional `with_output_modulus(t_out)`. Backend `context.encryptor(external_secret)` and `public_encryptor(&public)` prepare Rounded input; `pbs_decryptor` selects Rounded PBS/ManyLUT output and `mvb_decryptor` selects Scaled MVB output. No codec or LUT is passed to these clients. `pbs_lookup_table_compiler()` and `compile_mvb_fn` use the same defaults. Family `PbsParameters` provide the same default client factories without a transform table; contexts delegate to them. For advanced same-key domains, bind prepared codecs through the family `*_with_codec` factories; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

`ClientKey` remains the complete setup bundle for generating server keys. For ordinary messages, use `let external_secret = client.external_lwe_secret_key();`: it borrows `ExternalLweSecretKey::SmallLwe(&small)` for BR→KS or `ExternalLweSecretKey::ExtractedGlwe(&glwe)` for KS→BR. These variants also accept independently retained owners; `into_parts()` moves both keys out without copying. Message clients check only that external role, while setup checks both secrets. Ring clients accept only `client.glwe_secret_key()`.

Prefer `context.try_generate_keys(rng)` for paired client/server keys. Use `ClientKey::generate(&parameters, &mut rng)` when only coefficient secrets are needed.

For explicit encoding, choose a `RoundedCodec` independently of key generation. Bind the external key with `br.encryptor_with_codec(external_secret, &codec)`, `br.public_encryptor_with_codec(&public, &codec)` and `br.decryptor_with_codec(external_secret, &codec)`. `br.try_generate_public_key(external_secret, rng)` creates the corresponding LWE public key. Each PBS order uses its own external secret and dimension. See the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for its total noise requirements.

Client reads/writes accept borrowed LWE views: pass `output.as_mut_view()` to `encrypt_to` and `ciphertext.as_view()` to `decrypt` or `decrypt_phase`. Allocating encryption methods still return `LweCiphertext<T>`; Boolean clients follow the same convention.

For explicit decoding, pass the returned-output codec to `br.decryptor_with_codec(external_secret, &output_codec)` and call `decrypt()`. Both Rounded and Scaled codecs are accepted, including MVB output with a different message modulus. The prepared decoding state is copied; the secret remains borrowed. `decrypt_phase` remains available for diagnostics.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. For explicit compilation, prepare codecs with `br.pbs_codecs(PbsMessageConfig::new(t_in))?`; output message moduli default to the input choice. Call `.with_output_modulus(t_out)` before preparation to override it. `br.lookup_table_compiler(&codecs)?` binds the selected input/output encodings directly; call `compile_fn` / `compile_slice`, or the interleaved / odd full-domain methods. Bind the output decryptor to `codecs.output_codec()`. Input, LUT and returned ciphertexts share one ciphertext modulus. ManyLUT, Boolean, bivariate and MVB interfaces and encodings are described in the [common guide](../primus_tfhe/README.md).

## Boolean and CBS

`let (input_codec, ring_message_codec) = br.circuit_bootstrap_codecs(8, 8)?;` prepares Rounded input and Scaled candidate ring messages for CBS → CMux with independent plaintext moduli. Parameters supply the common ciphertext modulus q=Q; only these two codecs are prepared, without an extra returned-output codec. The ring codec does not describe CBS output gadget scales. Capacity and noise margins remain operation contracts; existing concrete codecs can still be bound directly.

Compile a custom integer function with `key.parameters().compile_lookup_table_fn(&input_codec, |m| u64::from(m >= 2))?`, or pass the complete front-half result slice to `compile_lookup_table_slice`. Bind the resulting `CircuitBootstrapLookupTable` with `CircuitBootstrapEvaluator::try_with_lookup_table(&resources, key, program)?`; `try_new` keeps the identity default. Output lanes use `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other ring integers require the external-product noise contract. Both backends support classic binary/ternary and sparse binary programs.

Both backends provide `context.try_generate_circuit_bootstrap_keys(rng)` returning `(ClientKey, CircuitBootstrapServerKey)`. This combines one BR/KS `ServerKey` with required CBS material. Borrow `server.server_key()` for ordinary PBS; CBS shares its BR. KS→BR input preparation uses the existing KS; BR→KS CBS allocates no return scratch, while downstream LWE returns can still reuse KS. See [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

With an explicit t=4 `RoundedCodec` argument, contexts provide `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. These use ordinary PBS material; see the [common Boolean contract](../primus_tfhe/README.md#boolean-gates) for calls and chaining.

Input encoding and ManyLUT capacity are checked at CBS program binding: both backends use `CircuitBootstrapEvaluator::try_new(&resources, key, &input_codec)`. The default constructor uses the key's parameters; `try_with_parameters` explicitly selects a compatible alternate output basis. The same keys can serve several message moduli, provided each program fits and has sufficient noise margin. `accumulator_client(client.glwe_secret_key(), scaled_codec)` independently binds ordinary ring messages; its `ScaledCodec` need not use the input LWE message modulus.

CBS is an optional facility in both backends, with separate output basis, trace/scheme-switch parameters and keys. Both PBS orders support classic binary/ternary and sparse binary keys. CBS outputs remain under the accumulator secret and use gadget scales. The family defines `CbsGadgetParameters<T, M>`; backends provide concrete modulus aliases. Output bases with the same level count can reuse the scheme-switch key; numerical and transform requirements belong to the corresponding backend contracts.

`CbsGadgetParameters::try_from_config` derives trace and scheme-switch parameters from BR, preserving the same GLWE layout and sharing its immutable sampler state through `Arc`. Their gadget bases and random draws remain independent.

Backends support independent BR, ring KS and CBS material alongside convenient complete `ServerKey` generation. Independent CBS component generation takes only the accumulator secret. Independent BR→KS CBS needs no ring KS, while KS→BR still needs it to prepare the input. Ordinary PBS requires both BR and ring KS in either order. See the backend guides for APIs and examples.

## Examples

Backend basic examples show default encoding and reusable ordinary PBS storage; basic examples use BR→KS, and MVB examples use KS→BR. Independent output encoding is explained in the shared guide. MVB and CBS have dedicated examples; Boolean usage is in the [shared guide](../primus_tfhe/README.md#boolean-gates). All fixtures are for development, not production recommendations.

## Further reading

[Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
