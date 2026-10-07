# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Parameters and LWE clients for NTRU-TFHE. The [NTT](../primus_tfhe_ntru_ntt/README.md) and [Fourier](../primus_tfhe_ntru_fourier/README.md) backends provide contexts, evaluation keys and evaluators.

This family uses coefficient types, sparse key storage, parameters and client operations by default, without pulling in NTT/FFT. Select a concrete backend below for homomorphic evaluation; its normal dependencies enable the required representation.

`TfheConfig::poly_length` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

## Parameters and key domains

`TfheParameters<T, M, LM=M>` separates ring modulus Q from external LWE modulus q, sharing coefficient type T. Construct it with `TfheParameters::try_from_config(TfheConfig { .. })`: `external_lwe` selects the external dimension, q, binary/ternary distribution and encryption noise; `accumulator_modulus` selects Q. `blind_rotation` and `key_switching` each use `GadgetEncryptionConfig { decomposition, noise_standard_deviation }`. BR decomposition and noise use Q, while return-key decomposition and noise use q. BR noise also serves accumulator encryption; external LWE encryption keeps its own noise in `external_lwe`. `level_count: None` selects the maximum supported level count; still check the [decomposition precision](../primus_decompose/README.md).

Dimension choices use `LweDimension`; decomposition choices use `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Construct these checked units once and pass parameter accessors directly to workspaces. `.get()` exposes the integer at raw storage or kernel boundaries; composed lengths and basis/modulus compatibility remain constructor checks.

The direct composition entry is `TfheParameters::try_new(external_lwe, blind_rotation, key_switching)`. `external_lwe` is a codec-free `LweEncryptionParameters`; `blind_rotation` is `NlevParameters`. Both constructors take `key_switching: GadgetEncryptionConfig { decomposition, noise_standard_deviation }`, with `DecompositionConfig` built at external q and independently selected return-key noise in coefficient units at q. 2N must fit T; the external dimension n need not be at most N. Constructors report specific parameter errors but do not validate security or a complete noise budget.

`accumulator_ntru()` borrows the ring/sampling state owned by the blind-rotation gadget at Q. Key parameters contain no message codec. CBS `trace` and `scheme_switch` each use an `GadgetEncryptionConfig` at Q to construct codec-free NLev parameters with independent noise. CBS `output` remains a `DecompositionConfig` for output gadget scalars.

`ClientKey` holds independent LWE secret s and NTRU ring secret f. Generate paired material with `context.try_generate_keys(cbs_config, rng)`, or import it with `ClientKey::new(s, f)`. Only f requires invertibility checks and, for Fourier, inverse stability. External secrets require neither padding, invertibility nor odd weight. `external_lwe_secret_key()` returns the LWE secret at q. Binding checks its recorded modulus before borrowing a raw view; a different q returns `TfheKeyError::LweSecretKeyModulusMismatch`, even for identical binary coefficients.

Ordinary PBS returns through: blind rotation under f,Q → coefficient-wise nearest rounding Q→q → phase-coefficient extraction → LWE key switching at q to s. ManyLUT shares blind rotation but returns each output separately. `context.allocate_lwe_ciphertext()` uses the external dimension.

Classic PBS, ManyLUT, CBS, Boolean and MVB support binary/ternary external secrets. Sparse requires the explicit fixed-weight binary generation entry, allows even weight, and supports ordinary/ManyLUT PBS, factorized MVB, CBS and one-hot. The `SparseTernary` distribution alone does not select bucket aggregation. First lifting and sparse-bucket derivations live in the [implementation notes](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation).

## Sparse coefficient keys

`SparseNtruBootstrappingKey<T>` owns the shared coefficient controls and public bucket map; both backends re-export this type. Bucket zero exposes NLEV controls through `first_bucket()`; later buckets expose NGSWs through `ngsw_bucket(i)`, always with a dummy last. The backend BR owner retains the basis and modulus, so sharing a storage type does not make NTT residues and native-torus coefficients interchangeable.

Prefer the backend `KeyGenerator` for encryption. For independently prepared controls, `try_new(data, map, hamming_weight, &nlev_parameters)` moves the buffer and checks the combined layout. It does not verify the encrypted selection, actual secret or noise budget; no transform engine is required to own or inspect the coefficients.

## Clients and LUTs

Use `PbsMessageConfig::new(t_in)` for equal input/output message moduli, or `.with_output_modulus(t_out)` to override the output. `parameters.pbs_codecs(messages)?` prepares Rounded codecs; `parameters.factorized_pbs_codecs(messages)?` prepares Rounded input and Scaled outputs for MVB. Both return named `input_codec()`, `lut_output_codec()` and `output_codec()` roles, deriving the correct ciphertext moduli without copying keys or allocating buffers. See [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding) for compilation and output decoding.

`ClientKey` is the complete setup bundle; ordinary clients need only `let external_secret = client.external_lwe_secret_key();`, an `&LweSecretKey`. You can generate that owner directly from `parameters.external_lwe()`, or move it out with `client.into_parts()`, without retaining an accumulator secret. Binding checks only the external domain; accumulator shape, invertibility and return-key bounds belong to their own consumers. Ring clients accept only `client.accumulator_ntru_secret_key()`.

Choose a `RoundedCodec` at external q, then use the context's `encryptor(external_secret, &input_codec)`, `public_encryptor(&public, &input_codec)` and `decryptor(external_secret, &input_codec)`. `parameters.try_generate_public_key(external_secret, rng)` creates an LWE public key under independent external s. This is not an NTRU ring public key; see the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for total noise requirements. Ordinary messages use T and `decrypt` returns `Result<T, ClientError>`.

Client reads/writes accept borrowed LWE views: pass `output.as_mut_view()` to `encrypt_to` and `ciphertext.as_view()` to `decrypt` or `decrypt_phase`. Allocating encryption methods still return `LweCiphertext<T>`; Boolean clients follow the same convention.

For LUT results, pass the returned-output codec to `decryptor(external_secret, &output_codec)` and call `decrypt()`. Both Rounded and Scaled codecs are accepted, including MVB output with a different message modulus. The prepared decoding state is copied; the secret remains borrowed. `decrypt_phase` remains available for diagnostics.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. Prepare codecs with `parameters.pbs_codecs(PbsMessageConfig::new(t_in))?`; output message moduli default to the input choice. Call `.with_output_modulus(t_out)` before preparation to override it. `parameters.lookup_table_compiler(&codecs)?` binds the selected input/output encodings directly; call `compile_fn` / `compile_slice`, or the interleaved / odd full-domain methods. Bind the output decryptor to `codecs.output_codec()`. The compiler checks input q and LUT-output Q without preparing an unused default output. The return path scales existing encodings rather than re-encoding; budget Q→q rounding and key-switch errors.

The [common guide](../primus_tfhe/README.md) covers ManyLUT, odd full domains and MVB. MVB compiles with an unsigned `ScaledCodec` at Q and decodes with a Scaled codec at q, budgeting the difference between their fixed scales. Bounded two-input `BivariateLookupTable` currently requires q=Q.

## Boolean clients and gates

Pass an explicit t=4 `RoundedCodec` to `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. They handle Boolean external LWE encoding with ordinary PBS keys; see [Boolean gates](../primus_tfhe/README.md#boolean-gates) for calls and chaining contracts.

## CBS and examples

The backends expose independent `BlindRotationKey`, return and `CircuitBootstrapKey` owners, with `ServerKey::new` / `into_parts` for moving them into or out of a complete bundle. `parameters.try_generate_lwe_return_key(&client, rng)` generates return material without a transform workspace; `parameters.check_lwe_return_key(&key)` checks N/Q/q/dimension/basis at composition. CBS-only generation and binding do not require a return key or f's magnitude bound at external q. The accumulator's backend conversion requirements still apply.

`context.try_generate_keys(Some(cbs_config), rng)` includes trace/scheme-switch material. For sparse BR, use `context.try_generate_server_key(&client, BlindRotationConfig::Sparse { copy_count: copies, bucket_count: buckets }, Some(cbs_config), rng)`; `None` omits CBS material. Both backends compose common `BootstrapResources` with `CircuitBootstrapEvaluator::try_new`. See each backend README for resource reuse. CBS skips the ordinary PBS return path and produces NGSW under f. An input bit 0/1 produces a CMux control; candidate ring ciphertexts must share f, Q and encoding. Backend examples show the complete consumption chain.

`CircuitBootstrapParameters` chooses independent output, trace and scheme-switch bases. Output retains the requested level count and the scheme-switch key binds the complete output basis. Matching lengths do not establish basis or actual secret identity. BR decomposition must resolve the LUT and smallest output gadget scale. CBS input encoding and ManyLUT capacity are checked when binding the evaluator; the same key material can serve several t values. `accumulator_client(client.accumulator_ntru_secret_key(), scaled_codec)` independently binds ordinary ring messages at Q, sharing the gadget’s sampling state; its message modulus may differ from the input LWE modulus.

NTT reverse trace uses modular inverses; Fourier uses native integer halving and adds FFT error. Scheme switching multiplies input error by f and decomposition error by f². Publishing `NGSW_f[f]` requires a separately justified key-dependent-message/circular-security assumption; see the [NTRU contract](../primus_ntru/README.md#same-secret-scheme-switching).

## One-hot CBS

`OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)` reuses CBS material with classic binary/ternary or sparse fixed-weight binary BR and borrows common resources per call. Require t=2M, M=2^tau and tau>=1; encrypt inputs in 0..M with `encrypt_padded`. For L output gadget levels, let W=next_power_of_two(L) and require 2MW<=N.

Full-output APIs allocate with `allocate_nlev_output` / `allocate_ngsw_output`, then write δ_r(m), r=0..M-1, with `one_hot_nlev_to`, `one_hot_ngsw_to` or `one_hot_to`. NLEV uses coefficient representation at Q; NGSW uses the backend's transform representation. Layout is `[selector][level][row element]`, with levels in `output_basis().scalar_iter()` order. Rows contain N integers, or N/2 complex values for Fourier NGSW. Transform NLEV before lifting public polynomials; use NGSW for CMux on encrypted candidates.

For nonzero branches only, use `allocate_nonzero_ngsw_output` and `one_hot_nonzero_ngsw_to`. Compact slot r-1 represents r=1..M-1, skipping r=0 projection and scheme switching. For m=0 all target bits are zero. Each call shares one BR and reuses output/workspace. Use `one_hot_to` for both full batches, or `one_hot_nlev_and_nonzero_ngsw_to` for full NLEV plus nonzero NGSW: it projects branch zero for NLEV and skips its scheme switch, sharing the other projections.

Let S=N/M and A=N/(2MW). Correct selection requires the quantized phase to satisfy `u_bar=S*m+W*e mod 2N` with `-A<=e<A`. The window is left-closed/right-open and a midpoint belongs to the larger message. The error e includes input noise, encoding rounding and per-coordinate quantization. Shape checks prove neither this guard nor output decryptability; see the [one-hot normalization and guard derivation](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs).

The separate [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) crate handles multiple chunks and multiple table polynomials.

## NTRU→LWE returns

`LweReturnEvaluator::new(server.key_switching_key(), q_modulus)` borrows the
Q→q, f→s key and binds external q without allocating. Both backends re-export it.
Prepare only the storage you need with `new_scalar_workspace()` and/or
`new_batch_workspace()`. The latter returns `LweReturnBatchWorkspace`, containing
bounded tiles and the stream's valid-prefix state. Input must be canonical
coefficient-domain NTRU under the paired ring secret at Q, with a valid noise budget.

- `return_at_to(input.as_view(), index, output.as_mut_view(), &mut scalar)` returns one phase coefficient.
- `return_prefix_to(input.as_view(), outputs, &mut batch)` returns consecutive coefficients, sharing one Q→q conversion for multiple outputs.
- For different sources, call `batch.begin_batch()`, then ordered `append_at(input.as_view(), index, &mut batch)`, then `return_batch_to(outputs, &mut batch)`.

Each append retains only an extracted LWE; source and one-hot/FFT buffers may be
reused immediately. Submit exactly the appended count, at most
`batch.batch_capacity()` (currently eight). Empty and singleton batches are valid.
Successful submission ends the stream; `batch.discard_batch()` cancels it, and
restarting discards the previous prefix. Failed validation preserves it for retry.
Shared-prefix return rejects an active batch; independent scalar scratch remains
usable. All appends and submission must use the same actual secrets and Q/q;
workspace shape does not establish key identity. Finish or discard before
reusing batch storage with a different binding. Online operations allocate nothing.

## Further reading

[Operations and resource reuse](../primus_tfhe/README.md) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../../benchmarks/tfhe/BENCHMARKS.md)
