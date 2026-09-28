# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

NTRU-based TFHE with an explicit field modulus. Start with the [task and encoding guide](../primus_tfhe/README.md#choosing-an-operation), then the [NTRU parameter and key domains](../primus_tfhe_ntru/README.md). Examples use functional parameters, not certified security or failure-probability recommendations.

## Quick start

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_basic
```

The [basic example](examples/ntru_ntt_basic.rs) shows parameters → context → paired keys → clients → one compiled LUT → reused evaluator and ciphertext buffers. It computes `x % 4`, keeping `t=32` encoding for both input and output, and decodes with `decrypt`. `compile_lookup_table_fn(function)` defaults to the parameter codec. For a different output plaintext modulus, use `compile_lookup_table_with_codec_fn(&output_codec, function)`; see [choosing the output encoding](../primus_tfhe/README.md#choosing-the-output-encoding). Public-key encryption starts with `context.public_encryptor(&public)`; see the [family guide](../primus_tfhe_ntru/README.md#clients-and-luts). The example uses external `q=2^24`, distinct from ring `Q`: LUT compilation is at `Q` and the returned LWE is at `q`.

Examples default to u32; change `type Word = u32` to `u64` and the `Table` import from `U32NttTable` to `U64NttTable`. Rerun the same command after the edit. Each file defines its own `parameters()` using an explicit `TfheConfig`: dimensions, modulus types, secret distributions, noise and BR/KS decompositions are visible together. CBS examples also define `circuit_config()` for the output, trace and scheme-switch bases. Basic PBS uses n=866/N=2048; CBS uses n=800/N=1024; MVB and sparse PBS use n=728/h=32/N=1024. See the [arithmetic profiles](../../guides/development/tfhe-parameters.md) for the numerical choices. Each example shows one workflow and two requests using the same buffers.

Examples separate client encryption, server evaluation and client decryption; see [client/server roles and buffer allocation](../primus_tfhe/README.md#client-and-server-roles).

| Operation | Complete example |
| --- | --- |
| Classic PBS | [basic](examples/ntru_ntt_basic.rs) |
| Sparse PBS / interleaved ManyLUT | [sparse](examples/ntru_ntt_sparse.rs); `SPARSE=false` selects classic ManyLUT |
| Classic CBS → CMux | [circuit_bootstrap](examples/ntru_ntt_circuit_bootstrap.rs) |
| Factorized MVB | [thresholds](examples/ntru_ntt_mvb_thresholds.rs) |
| One-hot CBS → CMux | [one_hot](examples/ntru_ntt_one_hot.rs) |
| High-precision lookup | [lookup](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs) |

ManyLUT interleaves outputs within one blind rotation; factorized MVB uses public factors and a different evaluation interface. NTRU sparse supports ordinary/interleaved PBS, but not CBS, one-hot or factorized MVB.

## Parameters and representation

`TfheParameters::try_from_config(TfheConfig { .. })` checks mathematical choices; `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` prepares the transform table. Use `TfheContext::try_new(parameters, table)` to bind an existing table. `TfheConfig`, `TfheParameters`, `Encryptor` and `Decryptor` specialize the family API to `BarrettModulus`. `LM` in `TfheParameters<T, LM>` / `TfheContext<T, Table, LM>` selects the independent external modulus type, defaulting to the backend modulus type. `accumulator_modulus` supplies ring `Q`.

NTT tables must implement `MonomialNttTable`; built-in tables support it. Context construction checks length and modulus. All transformed keys/values must follow the supplied table's representation.

PBS performs fused lifting and blind rotation under `f,Q`, then coefficient-wise `Q→q`, phase extraction and LWE key switching to independent external secret `s`. Only ring secret `f` is screened for invertibility and, for Fourier, inverse stability. ManyLUT shares blind rotation with one LWE key switch per output. External binary/ternary secrets need no padding, invertibility screening or odd-weight restriction.

Classic binary/ternary BR fuses the first CMux with public-LUT lifting: coordinate zero uses NLEV bit controls, later coordinates use NGSW. It decomposes the rotated LUT once against `I + (R-1)B+ + (R^-1-1)B-`, omitting `B-` for binary. A zero first exponent still lifts with `I=NLEV[1]`. Ordinary PBS, ManyLUT, MVB and CBS share this path. The BR basis must resolve the programmed LUT scale, including the smallest CBS output gadget weight; parameter shape checks do not certify this numerical budget.

## Reusing evaluators

Ordinary/interleaved calls reuse `Evaluator`; use `_to` with existing outputs. For PBS/MVB/CBS alternation, follow the [shared ownership workflow](../primus_tfhe/README.md#reusing-evaluators).

Use `FactorizedEvaluator::try_from_bootstrapper` or `CircuitBootstrapEvaluator::try_from_bootstrapper`. Both reject sparse server keys. The PBS borrow is always available, and `into_bootstrapper()` allocates nothing.

## Fixed-scale factorized MVB

`context.compile_factorized_lookup_table_fn(&scaled_codec, input_domain_len, output_count, function)` returns `NttFactorizedLookupTable`, bound to that context instance. Bind a `FactorizedEvaluator` once, or consume an existing ordinary evaluator. Keep the unsigned Scaled codec for decoding; the result is not automatically a Boolean gate input. Compile with a `ScaledCodec` at `Q`; the returned scale is `(q/Q)*round(Q/t_out)`. Decode with a Scaled codec at `q` and the same plaintext modulus, budgeting its difference from `round(q/t_out)` and return noise.

The coefficient modulus must be odd. Factors stay in NTT form after preparation.

Classic binary/ternary keys share encrypted initialization and BR, then key-switch each product. Factor norms amplify initialization and BR noise; return-KS noise is added afterward.

Run the [17-threshold example](examples/ntru_ntt_mvb_thresholds.rs) with `--example ntru_ntt_mvb_thresholds`. It demonstrates output counts beyond interleaved capacity. See the [shared MVB contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) for algorithm selection and encoding limits.

## Experimental sparse PBS

Select a fixed-weight binary external-LWE distribution and choose sparse generation explicitly; a low-weight distribution alone still selects classic BR. Require `0<h<n`, `copy_count>=1` and `bucket_count>=max(copy_count,h)`.

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

Ordinary/interleaved PBS use the same evaluator. CBS/MVB reject sparse keys, including CBS binding with standalone material. `server.sparse_bootstrapping_key()` exposes selectors.

Bucket zero stores NLEV selectors and a NLEV dummy. Their monomial-weighted sum lifts the public rotated LUT directly; later buckets aggregate NGSW controls. Empty or unoccupied first buckets and zero exponents still process the dummy and encrypted zeros. There is no separate sparse initializer. `first_bucket()` exposes the first NLEV controls; `ngsw_bucket(j)` accepts only `j >= 1` and exposes NGSW controls. Both include the dummy last. Online evaluation reuses the aggregate and external-product buffers without allocation.

Matching retries at most eight public maps with the fixed client; it never resamples the client. Every bucket, including encrypted zeros and dummies, contributes noise. Successful matching does not certify security or a complete failure bound. See [sparse rotation invariants](../primus_tfhe/IMPLEMENTATION.md#ternary-and-sparse-rotation) and the [message/carry example](examples/ntru_ntt_sparse.rs).

## Optional circuit bootstrapping

Generate paired material with `context.try_generate_keys(Some(cbs_config), &mut rng)`; `ServerKey` owns the additional parameters and trace/scheme-switch keys. Create `context.circuit_bootstrap_evaluator(&server)` or consume ordinary workspace as above. With a classic key generated using `None`, binding CBS returns `MissingCircuitBootstrapKey`. Use `allocate_output`, `circuit_bootstrap_to` and `cmux_to`; the [CBS → CMUX example](examples/ntru_ntt_circuit_bootstrap.rs) shows their complete consumption chain.

The output is `NttNgswCiphertext` under `f_acc`. The circuit key binds the complete output basis; `try_from_parts(context, server, circuit_key)` obtains parameters from that key. NTT trace normalization requires odd Q below `2^(T::BITS-1)`.

Standalone component generation must use paired secrets and the same transform representation; shape checks cannot prove identity. See [CBS input/output and consumption](../primus_tfhe/README.md#cbs-output-and-consumption) and the [family CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples).

## One-hot CBS

The [one-hot example](examples/ntru_ntt_one_hot.rs) generates four selectors from a two-bit input and consumes `delta_2` in a CMux. Change the public `TARGET` index to select another r.

`OneHotCircuitBootstrapEvaluator::try_new(&context, &server)` binds existing CBS keys for one chunk. Full-output methods include the default selector r=0. Use `try_from_bootstrapper` to reuse PBS workspace, `bootstrapper_mut()` to borrow ordinary PBS, and `into_bootstrapper()` to recover it. Classic binary/ternary keys are supported; sparse keys and missing CBS material are rejected. Ordinary CBS interfaces are unchanged.

Allocate with `allocate_nlev_output()` / `allocate_ngsw_output()`, then reuse `one_hot_nlev_to`, `one_hot_ngsw_to`, or `one_hot_to(input, nlev, ngsw)`. Each call performs one BR; requesting one representation does not generate a complete batch of the other. NLEV uses coefficient representation at Q with N integers per row; NGSW uses NTT representation with N integers per row. Flat layout is `[selector][level][row element]`, without padding; levels follow `evaluator.parameters().output_basis().scalar_iter()`. Outputs are overwritten completely, with no online allocation.

If the consumer needs only nonzero branches, allocate with `allocate_nonzero_ngsw_output()` and call `one_hot_nonzero_ngsw_to(input, output)`. This writes M-1 NGSWs in `[r-1][level][row element]` order for r=1..M-1, skipping the projection and scheme switch for r=0. For input m=0, all target bits are zero. The shared BR, input guard and noise requirements remain unchanged; the public first LUT layer still uses all M NLEV selectors.

For selection among public polynomials, use `NlevCiphertext::write_ntt_form` into preallocated transformed storage before the NLEV external product. NGSW slices can directly be wrapped as `NttNgswCiphertext` to consume encrypted candidates with the same basis. See the [one_hot integration test](tests/one_hot.rs) for both consumers and the [shared one-hot contract](../primus_tfhe_ntru/README.md#one-hot-cbs) for encoding, capacity and the noise guard.

## High-precision lookup

[primus_tfhe_ntru_lut](../primus_tfhe_ntru_lut/README.md) composes one-hot CBS with table selection, aggregated negative rotations and the independent LWE return. It supports uniform input/output chunk widths and independently chosen counts. For lower-level composition, `ServerKey::initializer()` exposes the classic NLEV[1] under the context's BR basis; `key_switching_key()` exposes the Q→q, f→s return key.

A complete chunk-encryption and lookup workflow is in [ntt_lookup.rs](../primus_tfhe_ntru_lut/examples/ntt_lookup.rs).

## Lower-level composition

Rustdoc groups server material in `key`, CBS in `circuit_bootstrap`, MVB programs/execution in `factorized`, and bucket material in `sparse`. Common workflow types remain root imports.

## Further reading

[Boolean gates](../primus_tfhe/README.md#boolean-gates) · [Error boundaries](../primus_tfhe/README.md#error-boundaries) · [Implementation notes](../primus_tfhe/IMPLEMENTATION.md) · [Benchmarks and performance decisions](../primus_tfhe/IMPLEMENTATION.md#performance-decisions-and-reproducibility)
