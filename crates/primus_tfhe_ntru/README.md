# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Parameters and LWE clients for NTRU-TFHE. The [NTT](../primus_tfhe_ntru_ntt/README.md) and [Fourier](../primus_tfhe_ntru_fourier/README.md) backends provide contexts, evaluation keys and evaluators.

## Parameters and key domains

`TfheParameters<T, M, LM=M>` separates ring modulus Q from external LWE modulus q, sharing coefficient type T. Construct it with `TfheParameters::try_from_config(TfheConfig { .. })`: `external_lwe` selects the external dimension, q, plaintext modulus, binary/ternary distribution and encryption noise; `accumulator_modulus` selects Q. `blind_rotation` decomposition uses Q, while `key_switching` decomposition and return-key noise use q. `level_count: None` selects the maximum supported level count; still check the [decomposition precision](../primus_decompose/README.md).

The direct composition entry is `TfheParameters::try_new(external_lwe, blind_rotation, key_switching, key_switching_noise_standard_deviation)`. Both domains share plaintext modulus t, and 2N must fit T; the external dimension n need not be at most N. Constructors report specific parameter errors but do not validate security or a complete noise budget.

`ClientKey` holds independent LWE secret s and NTRU ring secret f. Generate paired material with `context.try_generate_keys(cbs_config, rng)`, or import it with `ClientKey::new(s, f)`. Only f requires invertibility checks and, for Fourier, inverse stability. External secrets require neither padding, invertibility nor odd weight. `external_lwe_secret_key()` returns the LWE secret at q.

Ordinary PBS returns through: blind rotation under f,Q → coefficient-wise nearest rounding Q→q → phase-coefficient extraction → LWE key switching at q to s. ManyLUT shares blind rotation but returns each output separately. `context.allocate_lwe_ciphertext()` uses the external dimension.

Classic PBS, ManyLUT, CBS, Boolean and MVB support binary/ternary external secrets. Sparse requires the explicit fixed-weight binary generation entry, allows even weight, and supports only ordinary/ManyLUT PBS. The `SparseTernary` distribution alone does not select bucket aggregation. First lifting and sparse-bucket derivations live in the [implementation notes](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation).

## Clients and LUTs

Use the context's `encryptor(&client)`, `public_encryptor(&public)` and `decryptor(&client)`. `client.try_generate_public_key(parameters, rng)` creates an LWE public key under independent external s. This is not an NTRU ring public key; see the [LWE public-key contract](../primus_lwe/README.md#public-key-encryption) for total noise requirements. Ordinary messages use T and `decrypt` returns `Result<T, ClientError>`.

Use `encrypt_padded` for front-half LUTs and ordinary `encrypt` for odd full domains. Default LUTs compile at Q with the parameter plaintext modulus and use ordinary `decrypt` after returning to q. Explicit `*_with_codec_fn` / `_slice` methods accept an output `RoundedCodec` at Q. Decode `decrypt_phase` with the same plaintext modulus and a codec at q. The return path scales existing encodings rather than re-encoding; budget rounding and key-switch errors.

The [common guide](../primus_tfhe/README.md) covers ManyLUT, odd full domains and MVB. MVB compiles with an unsigned `ScaledCodec` at Q and decodes with a Scaled codec at q, budgeting the difference between their fixed scales. Bounded two-input `BivariateLookupTable` currently requires q=Q.

## Boolean clients and gates

For t=4, use `boolean_encryptor`, `boolean_public_encryptor`, `boolean_decryptor` and `boolean_evaluator`. They handle Boolean external LWE encoding with ordinary PBS keys; see [Boolean gates](../primus_tfhe/README.md#boolean-gates) for calls and chaining contracts.

## CBS and examples

`context.try_generate_keys(Some(cbs_config), rng)` includes trace/scheme-switch material; bind it through `context.circuit_bootstrap_evaluator(&server)`. CBS skips the ordinary PBS return path and produces NGSW under f. An input bit 0/1 produces a CMux control; candidate ring ciphertexts must share f, Q and encoding. Backend examples show the complete consumption chain.

`CircuitBootstrapParameters` chooses independent output, trace and scheme-switch bases. Output retains the requested level count and the scheme-switch key binds the complete output basis. Matching lengths do not establish basis or actual secret identity. BR decomposition must resolve the LUT and smallest output gadget scale.

NTT reverse trace uses modular inverses; Fourier uses native integer halving and adds FFT error. Scheme switching multiplies input error by f and decomposition error by f². Publishing `NGSW_f[f]` requires a separately justified key-dependent-message/circular-security assumption; see the [NTRU contract](../primus_ntru/README.md#same-secret-scheme-switching).

## One-hot CBS

`OneHotCircuitBootstrapEvaluator::try_new(&context, &server)` reuses classic binary/ternary CBS material. Require t=2M, M=2^tau and tau>=1; encrypt inputs in 0..M with `encrypt_padded`. For L output gadget levels, let W=next_power_of_two(L) and require 2MW<=N.

Full-output APIs allocate with `allocate_nlev_output` / `allocate_ngsw_output`, then write δ_r(m), r=0..M-1, with `one_hot_nlev_to`, `one_hot_ngsw_to` or `one_hot_to`. NLEV uses coefficient representation at Q; NGSW uses the backend's transform representation. Layout is `[selector][level][row element]`, with levels in `output_basis().scalar_iter()` order. Rows contain N integers, or N/2 complex values for Fourier NGSW. Transform NLEV before lifting public polynomials; use NGSW for CMux on encrypted candidates.

For nonzero branches only, use `allocate_nonzero_ngsw_output` and `one_hot_nonzero_ngsw_to`. Compact slot r-1 represents r=1..M-1, skipping r=0 projection and scheme switching. For m=0 all target bits are zero. Each call shares one BR and reuses output/workspace; request both representations together through `one_hot_to`.

Let S=N/M and A=N/(2MW). Correct selection requires the quantized phase to satisfy `u_bar=S*m+W*e mod 2N` with `-A<=e<A`. The window is left-closed/right-open and a midpoint belongs to the larger message. The error e includes input noise, encoding rounding and per-coordinate quantization. Shape checks prove neither this guard nor output decryptability; see the [one-hot normalization and guard derivation](../primus_tfhe/IMPLEMENTATION.md#one-hot-cbs).

The separate [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) crate handles multiple chunks and multiple table polynomials.

## Further reading

[Operations and resource reuse](../primus_tfhe/README.md) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmark guide](../primus_tfhe/BENCHMARKS.md)
