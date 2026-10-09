# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Parameters and LWE clients for NTRU-TFHE. The [NTT](../primus_tfhe_ntru_ntt/README.md) and [Fourier](../primus_tfhe_ntru_fourier/README.md) backends provide contexts, evaluation keys and evaluators.

This family uses coefficient types, sparse key storage, parameters and client operations by default, without pulling in NTT/FFT. Select a concrete backend below for homomorphic evaluation; its normal dependencies enable the required representation.

`PbsConfig::bsk_poly_length` takes `primus_poly::PolyLength`. Construct it once with `PolyLength::try_new(n)?` (or `new` for known constants) and reuse it for parameters, sizes and transform tables. Invalid integers are reported by `PolyLengthError`; parameter construction retains its combined-layout, modulus and sampler checks.

## Experimental paired parameters

`PbsConfig` directly describes PBS/ManyLUT/MVB LWE/ring domains, `bsk_gadget`, `algorithm`, required `key_switching` and `messages`. `CbsConfig { pbs, gadget }` adds CBS decompositions to the same domain; the selector input modulus is `pbs.messages.input_modulus`. Configs are copyable numerical choices without prepared samplers or codecs.

`bsk_poly_length` and `acc_modulus` describe the ring shared by accumulator and BSK ciphertexts. `bsk_secret_distr` samples the ring secret that encrypts the BSK; `bsk_gadget` selects its decomposition and row noise. BR output uses that secret; the public LUT itself samples no encryption noise. `external_lwe` separately describes the input secret. `algorithm: BlindRotationMethod` selects classic or sparse and its bucket geometry.

`PbsParameters::try_from_config(pbs_config)` returns `PbsParameters` with required KS, the algorithm and default messages. `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` combines it with `CbsGadgetParameters` and the input codec. A backend context owns complete operation state in one Box; `try_from_pbs_config` / `try_from_cbs_config` move prepared parameters in. `parameters()` always borrows the complete PBS domain; `cbs_parameters()` exposes additional CBS capability. `try_with_circuit_bootstrap(gadget)` adds CBS while sharing the common parameters and transform table.

Both PBS and CBS require a `GadgetEncryptionConfig` in `key_switching`; its decomposition and noise are independent of BR. CBS itself produces ring/gadget ciphertexts, while downstream consumers reuse the same KS to return LWE results. Input LWE and ring secrets remain independently sampled. NTRU return KS runs at external q.

Prepare parameters with `PbsParameters::try_from_config(pbs_config)`, `CbsParameters::try_from_config(pbs_config, gadget_config)` or `CbsParameters::try_with_config(pbs_parameters, gadget_config)`. The last entry moves existing common state without rebuilding samplers. Move prepared state into a Context by value; BR, trace and scheme-switch retain their existing ring-sampler Arc. Explicit `clone()` may copy LWE sampler data.

Concrete backends provide `experimental::*_U64` teaching configs for PBS, ManyLUT, MVB and CBS. `PbsMessageConfig::new(t)` defaults to equal input/output message moduli; `.with_output_modulus(t_out)` changes only the output. Backend PBS/ManyLUT clients and compilers derive Rounded encoding from these messages; MVB selects Scaled output through its own factories. CBS retains its input codec while the consumer chooses candidate-ring messages. Security and failure probability are unassessed; see [provenance and conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries).

## Parameters and key domains

`PbsParameters<T, M, LM=M>` separates ring modulus Q from external LWE modulus q, sharing coefficient type T. `PbsParameters::try_from_config(pbs_config)` prepares ordinary PBS: `external_lwe` selects the external dimension, q, binary/ternary distribution and fresh noise; `acc_modulus` selects Q. `bsk_gadget` selects BR decomposition and row noise at Q, while `key_switching` selects return-key decomposition and row noise at q. Ring encryption clients reuse BR row noise; external LWE encryption keeps its independent noise. `level_count: None` selects the maximum supported levels; check the [decomposition precision](../primus_decompose/README.md). `CbsParameters::try_from_config(cbs_config.pbs, cbs_config.gadget)` prepares ring-output CBS/one-hot, return KS is always prepared and shared with PBS.

Dimension choices use `LweDimension`; decomposition choices use `DecompositionBaseLog` and `Option<DecompositionLevelCount>`. Construct these checked units once and pass parameter accessors directly to workspaces. `.get()` exposes the integer at raw storage or kernel boundaries; composed lengths and basis/modulus compatibility remain constructor checks.

`PbsParameters::try_from_config` prepares external LWE, the BR ring domain and required return KS once. Return decomposition is built at external q, with independently selected key-row noise in coefficient units at q. `2N` must fit T; external n and ring N are independent. CBS/one-hot reuse this return state without preparing a second copy. Constructors report specific parameter errors, but do not establish security or a complete noise budget.

`accumulator_ntru()` borrows the ring/sampling state owned by the blind-rotation gadget at Q. Key parameters contain no message codec. CBS `output`, `trace` and `scheme_switch` each use a `DecompositionConfig` at Q. `CbsGadgetParameters::try_from_config` derives codec-free trace/scheme-switch NLev parameters from BR, sharing its ring and sampler state through `Arc`. All key rows use the accumulator encryption noise; gadget bases and random draws remain independent.

`ClientKey` holds independently sampled LWE secret s and NTRU ring secret f. Use `context.try_generate_keys(rng)` for ordinary PBS or `try_generate_circuit_bootstrap_keys(rng)` for ring-output CBS; import existing material with `ClientKey::new(s, f)`. Only f requires invertibility checks and, for Fourier, inverse stability. External secrets require neither padding, invertibility nor odd weight. `external_lwe_secret_key()` returns the LWE secret at q. Binding checks its recorded modulus before borrowing a raw view; a different q returns `TfheKeyError::LweSecretKeyModulusMismatch`, even for identical binary coefficients.

Ordinary PBS returns through: blind rotation under f,Q → coefficient-wise nearest rounding Q→q → phase-coefficient extraction → LWE key switching at q to s. ManyLUT shares blind rotation but returns each output separately. `context.allocate_lwe_ciphertext()` uses the external dimension.

Classic PBS, ManyLUT, CBS, Boolean and MVB support binary/ternary external secrets. With independent secrets, sparse requires the explicit fixed-weight binary generation entry, allows even weight, and supports ordinary/ManyLUT PBS, factorized MVB, CBS and one-hot. The `SparseTernary` distribution alone does not select bucket aggregation. First lifting and sparse-bucket derivations live in the [implementation notes](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation).

## Sparse coefficient keys

`SparseNtruBootstrappingKey<T>` owns the shared coefficient controls and public bucket map; both backends re-export this type. Bucket zero exposes NLEV controls through `first_bucket()`; later buckets expose NGSWs through `ngsw_bucket(i)`, always with a dummy last. The backend BR owner retains the basis and modulus, so sharing a storage type does not make NTT residues and native-torus coefficients interchangeable.

Prefer the backend `KeyGenerator` for encryption. For independently prepared controls, `try_new(data, map, hamming_weight, &nlev_parameters)` moves the buffer and checks the combined layout. It does not verify the encrypted selection, actual secret or noise budget; no transform engine is required to own or inspect the coefficients.

## Clients and LUTs

Choose `config.messages` with `PbsMessageConfig::new(t_in)` and an optional `with_output_modulus(t_out)`. Backend `context.encryptor(external_secret)` and `public_encryptor(&public)` prepare Rounded input; `pbs_decryptor` selects Rounded PBS/ManyLUT output and `mvb_decryptor` selects Scaled MVB output. No codec or LUT is passed to these clients. `pbs_lookup_table_compiler()` and `compile_mvb_fn` use the same defaults. Family `PbsParameters` provide the same default client factories without a transform table; contexts delegate to them. For advanced same-key domains, bind prepared codecs through the family `*_with_codec` factories; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding).

`ClientKey` is the complete setup bundle; ordinary clients need only `let external_secret = client.external_lwe_secret_key();`, an `&LweSecretKey`. You can generate that owner directly from `br.external_lwe()`, or move it out with `client.into_parts()`, without retaining an accumulator secret. Binding checks only the external domain; accumulator shape, invertibility and return-key bounds belong to their own consumers. Ring clients accept only `client.accumulator_ntru_secret_key()`.

For explicit encoding, choose a `RoundedCodec` at external q, then use `br.encryptor_with_codec(external_secret, &input_codec)`, `br.public_encryptor_with_codec(&public, &input_codec)` and `br.decryptor_with_codec(external_secret, &input_codec)`. `br.try_generate_public_key(external_secret, rng)` creates an LWE public key under independent external s. This is not an NTRU ring public key; see the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for total noise requirements. Ordinary messages use T and `decrypt` returns `Result<T, ClientError>`.

Client reads/writes accept borrowed LWE views: pass `output.as_mut_view()` to `encrypt_to` and `ciphertext.as_view()` to `decrypt` or `decrypt_phase`. Allocating encryption methods still return `LweCiphertext<T>`; Boolean clients follow the same convention.

For explicit decoding, pass the returned-output codec to `br.decryptor_with_codec(external_secret, &output_codec)` and call `decrypt()`. Both Rounded and Scaled codecs are accepted, including MVB output with a different message modulus. The prepared decoding state is copied; the secret remains borrowed. `decrypt_phase` remains available for diagnostics.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. For explicit compilation, prepare codecs with `br.pbs_codecs(PbsMessageConfig::new(t_in))?`; output message moduli default to the input choice. Call `.with_output_modulus(t_out)` before preparation to override it. `br.lookup_table_compiler(&codecs)?` binds the selected input/output encodings directly; call `compile_fn` / `compile_slice`, or the interleaved / odd full-domain methods. Bind the output decryptor to `codecs.output_codec()`. The compiler checks input q and LUT-output Q without preparing an unused default output. The return path scales existing encodings rather than re-encoding; budget Q→q rounding and key-switch errors.

The [common guide](../primus_tfhe/README.md) covers ManyLUT, odd full domains and MVB. MVB compiles with an unsigned `ScaledCodec` at Q and decodes with a Scaled codec at q, budgeting the difference between their fixed scales. Bounded two-input `BivariateLookupTable` currently requires q=Q.

## Boolean clients and gates

Pass an explicit t=4 `RoundedCodec` to `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. They handle Boolean external LWE encoding with ordinary PBS keys; see [Boolean gates](../primus_tfhe/README.md#boolean-gates) for calls and chaining contracts.

## CBS and examples

`CbsParameters` retains Rounded input encoding and gadgets and compiles identity or custom integer functions with `compile_lookup_table` / `_fn` / `_slice`. Backend Context methods `compile_cbs_identity` / `compile_cbs_fn` / `compile_cbs_slice` use the same state; input encryption shares `context.encryptor`. Candidate ring clients take independent t_ring and prepare Scaled encoding at accumulator Q. Independent codec pairings use low-level explicit compilation/client interfaces.

`context.circuit_bootstrap_evaluator_with_lookup_table(&server, program)?` creates default `CbsEvaluator` owning common resources; `context.circuit_bootstrap_evaluator(&server)?` compiles and binds identity. Output is `g_j * F(m) mod Q`, with no output message codec or extra BR. CMux requires bit-valued F throughout the input domain; other integers require the external-product noise contract. Both NTT/Fourier support classic binary/ternary and sparse binary. Explicit input encodings and per-call resource borrowing remain on low-level `CircuitBootstrapEvaluator`.

Both backends provide `context.try_generate_circuit_bootstrap_keys(rng)` returning `(ClientKey, CircuitBootstrapServerKey)`. This combines one BR/KS `ServerKey` with one required `CircuitBootstrapKey`, and also serves one-hot and high-precision lookup. Borrow `server.server_key()` for ordinary PBS; CBS/one-hot share its BR without duplicate keys. Complete bundle generation also checks the return-q secret-magnitude bound; online CBS still allocates no return scratch. See [material selection](../primus_tfhe/README.md#selecting-blind-rotation).

Independent BR, return-KS and CBS component APIs remain available. `ServerKey::new(br, ks)` / `into_parts()` move BR/KS; `CircuitBootstrapServerKey::new(server_key, circuit_key)` / `into_parts()` move the complete CBS composition without copying ciphertext buffers. `parameters.try_generate_lwe_return_key(&client, rng)` returns `Result<NtruLweKeySwitchingKey<_>, _>` directly, without a transform workspace; `check_lwe_return_key(&key)` checks N/Q/q/dimension/basis. Standalone BR/CBS components inherit only their actual numerical requirements; complete PBS/CBS bundles also require the return-q secret-magnitude bound.

`context.try_with_circuit_bootstrap(gadget)?` adds CBS to a PBS context; `context.try_generate_circuit_bootstrap_keys(rng)` then reuses the accumulator transform to generate a CBS bundle with shared BR/KS. CBS skips the ordinary return and produces NGSW under f. CMux requires a bit-valued function and candidates sharing f, Q and encoding.

`CbsGadgetParameters` chooses independent output, trace and scheme-switch bases. Output retains the requested level count and the scheme-switch key binds the complete output basis. Matching lengths do not establish basis or actual secret identity. BR decomposition must resolve the LUT and smallest output gadget scale. CBS input encoding and ManyLUT capacity are checked when binding the evaluator; the same key material can serve several t values. `accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` independently binds ordinary ring messages at Q, sharing the gadget’s sampling state; its message modulus may differ from the input LWE modulus.

NTT reverse trace uses modular inverses; Fourier uses native integer halving and adds FFT error. Scheme switching multiplies input error by f and decomposition error by f². Publishing `NGSW_f[f]` requires a separately justified key-dependent-message/circular-security assumption; see the [NTRU contract](../primus_ntru/README.md#same-secret-scheme-switching).

## One-hot CBS

Backend `context.one_hot_evaluator(&server)?` uses the same CBS capability and combines selector state with common resources. Low-level `OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)` serves explicit numerical combinations and per-call resource borrowing. Both support classic binary/ternary or sparse fixed-weight binary BR. Require t=2M, M=2^tau and tau>=1; encrypt 0..M with `encrypt_padded`. For L output levels, let W=next_power_of_two(L) and require 2MW<=N.

Full-output APIs allocate with `allocate_nlev_output` / `allocate_ngsw_output`, then write δ_r(m), r=0..M-1, with `one_hot_nlev_to`, `one_hot_ngsw_to` or `one_hot_to`. NLEV uses coefficient representation at Q; NGSW uses the backend's transform representation. Layout is `[selector][level][row element]`, with levels in `output_basis().scalar_iter()` order. Rows contain N integers, or N/2 complex values for Fourier NGSW. Transform NLEV before lifting public polynomials; use NGSW for CMux on encrypted candidates.

For nonzero branches only, use `allocate_nonzero_ngsw_output` and `one_hot_nonzero_ngsw_to`. Compact slot r-1 represents r=1..M-1, skipping r=0 projection and scheme switching. For m=0 all target bits are zero. Each call shares one BR and reuses output/workspace. Use `one_hot_to` for both full batches, or `one_hot_nlev_and_nonzero_ngsw_to` for full NLEV plus nonzero NGSW: it projects branch zero for NLEV and skips its scheme switch, sharing the other projections.

Let S=N/M and A=N/(2MW). Correct selection requires the quantized phase to satisfy `u_bar=S*m+W*e mod 2N` with `-A<=e<A`. The window is left-closed/right-open and a midpoint belongs to the larger message. The error e includes input noise, encoding rounding and per-coordinate quantization. Shape checks prove neither this guard nor output decryptability; see the [one-hot normalization and guard derivation](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs).

For branch access, use the evaluator's `nlev_selectors`, `ngsw_selectors` or
`nonzero_ngsw_selectors` to borrow a checked view over the existing output.
`selector(r)` uses the mathematical branch number; `iter()` yields
`(r, ciphertext)`. The nonzero view starts at r=1 and has no selector zero.
Coefficient NLEVs use the shared `NlevSelectors`; the backends expose distinct
`NttNgswSelectors` and `FourierNgswSelectors`. Views allocate nothing and reject
partial or mismatched batches. Basis, secret and transform identity remain caller contracts.

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
