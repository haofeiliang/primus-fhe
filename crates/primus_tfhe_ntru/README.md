# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Backend-independent NTRU-TFHE parameters and LWE clients. Transform-domain server keys and evaluators belong to [NTT](../primus_tfhe_ntru_ntt/README.md) or [Fourier](../primus_tfhe_ntru_fourier/README.md). See the [shared capability and encoding guide](../primus_tfhe/README.md).

## Parameters and key domains

`TfheParameters<T, M, LM = M>` separates accumulator modulus `Q` from external LWE modulus `q`, sharing integer type `T`. In `TfheConfig`, `accumulator_modulus` supplies `Q`; `external_lwe` supplies `q`, dimension, binary/ternary distribution, plaintext modulus and fresh encryption noise. `blind_rotation` decomposes at `Q`; `key_switching` and its independent noise apply at `q`. `level_count: None` retains full decomposition.

The direct constructor is `TfheParameters::try_new(external_lwe, blind_rotation, key_switching, key_switching_noise_standard_deviation)`. Both domains share plaintext modulus `t`, and `2N` must fit in `T`. The external dimension no longer needs to satisfy `n <= N`.

`ClientKey` owns independent `LweSecretKey<T>` secret `s` and `NtruSecretKey<T>` secret `f`. The external secret is neither padded nor screened for NTRU invertibility. Only `f` undergoes invertibility rejection and, for Fourier, inverse-stability screening. `ClientKey::new(s, f)` imports both secrets; `external_lwe_secret_key()` returns the LWE secret encoded at `q`. The former client-NTRU/prefix APIs are removed. Prefer `context.try_generate_keys(circuit_bootstrap, rng)` for paired generation.

Ordinary PBS follows one order: blind rotation under `f,Q` → coefficient-wise nearest rounding `Q→q` → phase-coefficient extraction → LWE key switching to `s` at `q`. The return path reuses `primus_ntru::NtruLweKeySwitchingKey` without online allocation. ManyLUT shares one blind rotation and applies one LWE key switch per output. `context.allocate_lwe_ciphertext()` uses the external dimension.

Classic PBS/ManyLUT, Boolean, CBS and MVB accept binary/ternary external secrets. The first fused step uses NLEV and later coordinates use NGSW; ternary stores positive/negative control pairs. `SparseTernary` describes a distribution without selecting bucket aggregation. External secrets are no longer conditioned by ring-key rejection.

Bucket aggregation in [NTT](../primus_tfhe_ntru_ntt/README.md#experimental-sparse-pbs) and [Fourier](../primus_tfhe_ntru_fourier/README.md#experimental-sparse-pbs) is an explicit choice for fixed-weight binary external secrets, with either odd or even weight. It supports ordinary/ManyLUT PBS; sparse CBS/MVB are rejected. The public map is sampled after fixing the external secret, and matching failure never resamples that secret.

## Clients and LUTs

`Encryptor`, `Decryptor`, `BooleanEncryptor` and `BooleanDecryptor` are re-exported from [`primus_tfhe`](../primus_tfhe/README.md#client-and-server-roles). Family constructors validate the client key and select the external LWE secret and noise; the shared clients own encoding, range checks and output reuse. They borrow LWE key views rather than family parameters or client keys.

Client encryption takes `T`, and decryption returns `Result<T, ClientError>` with a canonical residue in `[0,t)`; applications handle message type conversions.

Both parameters and contexts expose `encryptor(&client)`, `public_encryptor(&public)` and `decryptor(&client)`. Family secret-key construction returns `TfheClientError`; public-key construction and raw operations return shared `ClientError`. Generate the `LwePublicKey` with `client_key.try_generate_public_key(parameters, rng)`. This is an external LWE public key under the independent external secret, not an NTRU ring public key. Decryption requires the client key. Generation and fresh encryption use the `external_lwe` noise sampler, but the combined error is `e^T r + e2 - e1^T s`. The public key stores `n * (n + 1)` coefficients for the external secret. Dimension/modulus checks do not prove key identity; use paired client/server keys and budget the combined noise for PBS/ManyLUT. See [LWE public-key noise and identity requirements](../primus_lwe/README.md#public-key-encryption).

`encrypt`, `encrypt_padded` and `encrypt_centered` each provide `*_to(message, output, rng)`. Both key types reuse output storage and reject message or dimension errors before sampling/writing. Front-half LUTs compiled by the parameters use padded unsigned input; centered modular messages have a separate encoding contract.

ManyLUT compiles several functions of one input. The backend sparse message/carry example computes `x % 4`, `x / 4` and `x % 2`; it does not implement a complete encrypted integer type or arithmetic system.

Compile ordinary/interleaved LUTs through `context.parameters().compile_*`. Default outputs use rounded encoding at `Q` with the parameter plaintext modulus and can be decoded with ordinary `decrypt` after returning to `q`. `*_with_codec_fn` / `_slice` accept an output `RoundedCodec` at `Q`; for a different output plaintext modulus, decode `decrypt_phase` using that same plaintext modulus and external ciphertext modulus `q`. Raw LUT values are rescaled by `q/Q`, without re-encoding; budget rounding and return-key errors.

For odd full domains, use `compile_odd_full_domain_lookup_table_fn` / `_slice` and ordinary `encrypt`. The output codec and PBS evaluator are unchanged. See [odd full-domain PBS](../primus_tfhe/README.md#odd-full-domain-pbs) for capacity, folded-center and noise requirements.

For bounded two-input functions, use the shared `BivariateLookupTable` to pack `x+B*y` and pass its ordinary LUT to the existing evaluator. See [bounded two-input PBS](../primus_tfhe/README.md#bounded-two-input-pbs) for input bounds, common encoding and the amplified-error budget.

For factorized MVB, compile through `context.compile_factorized_lookup_table_fn` with an unsigned `ScaledCodec`, then bind `context.factorized_evaluator(&server_key)`. See the backend contracts for [odd-q NTT](../primus_tfhe_ntru_ntt/README.md#fixed-scale-factorized-mvb) and [Native even-scale Fourier](../primus_tfhe_ntru_fourier/README.md#fixed-scale-factorized-mvb).

## Boolean clients and gates

For plaintext modulus 4, contexts provide `boolean_encryptor(&client)`, `boolean_public_encryptor(&public)`, `boolean_decryptor(&client)` and `boolean_evaluator(&server)`. Direct Boolean constructors take prepared raw clients: `BooleanEncryptor::try_new(encryptor)` and `BooleanDecryptor::try_new(decryptor)`. Encryption accepts `bool`; decryption rejects decoded values other than 0/1. Operations return shared `BooleanError`, whose `Client` variant wraps `ClientError`; family secret-key factories return `TfheClientError` for construction failures. Evaluator construction returns `TfheEvaluationError`. Gate preprocessing, signed LUTs and output correction are shared in `primus_tfhe::BooleanEvaluator`. See [usage and encoding contracts](../primus_tfhe/README.md#boolean-gates).

## CBS and examples

Both backends provide optional CBS parameters, keys and evaluators. CBS branches after BR, projects coefficients and applies trace/scheme switching under `f_acc`; it skips ordinary PBS's return key switch and extraction. Input uses unsigned rounded LWE encoding, including for bits. Its NGSW output uses gadget scales and can control CMUX for `0/1` inputs. CMUX candidates must also use `f_acc`. LWE-to-ring packing is not provided by this TFHE layer.

`CircuitBootstrapParameters<T, M>` owns shared CBS layout and capacity validation; the NTT/Fourier backends expose aliases for their modulus domains. Explicit moduli retain modular-trace checks, while Fourier output lengths are available only for the native domain. CBS parameters select independent output, trace and scheme-switch bases. The internal ManyLUT pads its output groups; the projected NLev and output NGSW retain the requested level count. The scheme-switch key binds the complete output basis.

Ordinary and CBS keys must share the accumulator secret and transform table. Scheme switching multiplies input error by f and decomposition error by f²; its `NGSW_f[f]` material requires a justified key-dependent-message/circular-security assumption; see the [NTRU contracts](../primus_ntru/README.md). NTT uses modular trace normalization; Fourier adds native halving and FFT errors.

Backend READMEs link runnable PBS and CBS → CMUX examples. Fixtures do not establish production noise margins or security.

## One-hot CBS

`OneHotLookupTable::try_new(tfhe, cbs)` compiles the packed polynomial shared by both backends. `OneHotBootstrapError` distinguishes encoding, capacity, storage-overflow and evaluation-resource errors. The first version requires plaintext modulus `t=2*M`, `M=2^tau`, `tau>=1`. Encrypt chunks with the unsigned Rounded encoding of `encrypt_padded`: `round(q*m/(2*M))`, `0<=m<M`. External q and ring Q may differ.

For L gadget levels, let `W=next_power_of_two(L)`, `S=N/M`, and `A=N/(2*M*W)`. Capacity requires `2*M*W<=N`; padding levels are zero. The BR quantization step is W, not M*W. The test polynomial is `sum_{j=1-A}^{A} sum_l g_l X^(l-j*W)`. If the actual per-coordinate quantized phase satisfies `u_bar=S*m+W*e mod 2N`, `-A<=e<A`, then shifting the negative-BR output by `X^(r*S-l)` and applying full reverse trace extracts `g_l*delta_r(m)`. This left-closed, right-open window assigns a midpoint between adjacent messages to the higher message. The error e includes encryption noise, encoding rounding and quantization; parameter shape checks do not prove the guard condition.

The backends' `OneHotCircuitBootstrapEvaluator` full-output methods produce all M selectors, explicitly including r=0. NLEV outputs use coefficient representation; NGSW outputs use the backend's transform representation. Request either representation or both from one shared BR. `one_hot_nonzero_ngsw_to` instead writes only r=1..M-1 in compact `[r-1][level][row element]` order, skipping r=0 projection and scheme switching; all target bits are zero when m=0. Full projection works with nonzero message tails and needs no additional partial-trace workspace API. Scheme switching retains ordinary CBS's f/f² noise budget; Fourier also needs native-halving and FFT error budgets. This extension leaves ordinary CBS unchanged and does not implement multi-polynomial high-precision lookup.

Multi-chunk evaluation is provided by the separate [primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) crate, which consumes these selectors and the shared return keys.

## Further reading

[Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
