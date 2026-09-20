# primus_tfhe_glwe_fourier

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over the native torus. Supports both PBS orders, ManyLUT,
even-scale MVB, Boolean gates, classic CBS and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

`Encryptor`, `Decryptor`, `TfheConfig` and `TfheParameters` specialize the shared types to
`NativeModulus`; `ClientKey`, `EncryptionKey` and `PbsOrder` are re-exported directly.

## Reusing evaluators

Move an existing `Evaluator` into `FactorizedEvaluator::from_bootstrapper` or
`CircuitBootstrapEvaluator::try_from_bootstrapper` to allocate only the additional MVB/CBS buffers.
Use `bootstrapper_mut()` to alternate ordinary single-output/interleaved PBS; import
`primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved}` for those operations.
This borrow exposes PBS operations without allowing replacement of the bound evaluator.
`into_bootstrapper()` releases the extra buffers and recovers ordinary workspace; recovery
allocates nothing when the specialized evaluator was constructed from an ordinary one.

Standalone BR→KS CBS omits return-KS workspace, so `bootstrapper_mut()` returns `None`;
`into_bootstrapper()` explicitly allocates the missing workspace in this case. KS→BR CBS retains
input KS. For frequent PBS/CBS alternation, consume an ordinary evaluator: the PBS borrow is
`Some`, and online calls never reconstruct workspace.

## Run the complete example

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_basic
```

The [example source](examples/fourier_basic.rs) runs both orders with the same
workflow: parameters → context → paired keys → public-key encryptor/client decryptor
→ compiled LUT → reusable evaluator/output. It demonstrates single PBS, two-output
ManyLUT with `t_in=4 → t_out=8`, Scaled `t_out=10` MVB, client `encrypt_padded_to`, Boolean gates, NOT and MUX.

For `BootstrapKeyswitch`, external ciphertexts have dimension `n`; for
`KeyswitchBootstrap`, they have dimension `kN`. Both inputs and outputs follow
the chosen external key. Example dimensions, noise and decomposition choices are
for functional demonstration, not production security or failure-probability recommendations.

## Context and reuse

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves FFT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext::try_new` checks the FFT length. Every transformed key, value and
evaluator must use the same FFT table instance; matching lengths do not establish
representation identity. The example uses `RustFftTable`; `TfheFftTable` is also
supported. Create FFT engines and evaluators from the same context.

Compile front-half LUTs through `context.parameters()` with
`compile_lookup_table_fn` / `compile_lookup_table_slice`,
or their `compile_interleaved_lookup_table_*` counterparts, passing an output
`RoundedCodec` first. Decode a different output scale using `decrypt_phase` and
that codec. Use unsigned padded input and
account for ManyLUT's coarser rotation resolution. The evaluator holds mutable
scratch; create it once and reuse `apply_lookup_table_to` / `apply_interleaved_lookup_table_to`.
These calls validate all output dimensions before writing.

For odd full domains, use the parameters' `compile_odd_full_domain_lookup_table_fn`
/ `_slice` with ordinary `encrypt` and the existing single-output evaluator.
See the [shared contract](../primus_tfhe/README.md#odd-full-domain-pbs).

Use `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` for `t=4`.
These APIs use ordinary `LweCiphertext` buffers with Boolean 0/1 encoding modulo 4.
The encryptor accepts secret or public keys and supports `encrypt_to`.
The evaluator handles the internal modulus-8 LUT scale. Use `evaluate_binary_to`,
`not_to` and `mux_to` for repeated Boolean evaluation.

## Fixed-scale factorized MVB

Use unsigned Rounded inputs and an explicit unsigned `ScaledCodec` for outputs:

```rust,ignore
let codec = ScaledCodec::new(10u32, NativeModulus::new());
// Assumes t_in >= 8 and sufficient noise margins.
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 4, 3, |m, i| u32::from(m > i),
)?;
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
let value = codec.decode_value(decryptor.decrypt_phase(&outputs[0])?);
```

The arguments after the codec are the input prefix length and exact output count.
`FourierFactorizedLookupTable` borrows this context; a different instance is rejected
even with equal parameters. Lower-level callers may prepare a shared
`FactorizedLookupTable` through `FourierFactorizedLookupTable::new`.

Supports u32/u64, RustFFT/TfheFFT, classic binary/ternary and fixed-weight sparse binary keys in both orders.
The actual `delta=round(2^BITS/t_out)` must be even; odd scales return
`LookupTableError::OddFactorizationScale`. The plaintext modulus need not be a
power of two: 10 works for both supported widths. Sparse MVB uses the same
`KeyGenerator::try_generate_sparse_server_key` as ordinary sparse PBS.

Factors are prepared once as signed integers, without torus scaling. One BR is
shared; BK key-switches each product, while KB switches the input before BR.
`apply_lookup_table_to` checks context and all dimensions before writing and
allocates nothing. Extra workspace is `(d+2)*N/2` complex values, independent of
output count. The prepared program stores N torus coefficients and `output_count*N/2`
complex values; it retains no coefficient copy of the factors.

Factor norms amplify BR noise, and Fourier products add numerical phase error.
Successful construction does not establish a noise budget, including for u64.
Decode with the supplied Scaled codec; account for different Rounded centers when
chaining. See the [encoding contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb)
and [precision evidence and limits](../../docs/tfhe-mvb-fourier.md).

The [17-threshold example](examples/fourier_mvb_thresholds.rs) turns one score in
`0..64` into 17 numeric flags where interleaving cannot fit. These Scaled `t_out=2`
flags require their own codec; they are not Boolean gate ciphertexts or inputs at
another plaintext modulus. Algorithm choice depends on factor norms, available
interleaved capacity, output count and key size; see [measured costs](../../docs/tfhe-mvb-fourier-costs.md).

```sh
cargo run -p primus_tfhe_glwe_fourier --example fourier_mvb_thresholds
```

## Binary and ternary small secrets

Select `SecretKeyDistr::UniformTernary` or another ternary family in `LweParameters`;
the key-generation and evaluator APIs are unchanged. The basic example uses this
configuration. Both PBS orders, ordinary/interleaved LUTs and public-key inputs work.
Ternary keys require more key and workspace storage than binary keys; see the
[ternary design and costs](../../docs/tfhe-ternary.md).

## Experimental sparse PBS

For a `FixedHammingWeightBinary` small-LWE secret, explicitly generate a sparse
server key, then use the ordinary evaluator and LUT APIs:

```rust,ignore
let server = KeyGenerator::new(&context)
    .try_generate_sparse_server_key(&client, copy_count, bucket_count, None, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
```

Both PBS orders, ordinary LUTs and ManyLUT work with RustFFT and TfheFFT. Require
`0 < h < n`, `copy_count >= 1` and `bucket_count >= max(copy_count, h)`.
Server and standalone sparse BSK generation return `KeyGenerationError`; `SparseBootstrapping` wraps
`SparseBootstrappingKeyError`, whose `BucketMap` variant preserves mapping failures. Matching retries at most eight public maps with the same secret.
The private matching is erased after generation.

The sparse BSK stores `(copy_count*n + bucket_count)` coefficient GGSWs. Every
bucket contributes an external product, including unoccupied buckets and encrypted
zero entries. Key storage, aggregation noise and transform costs must be budgeted;
speedups depend on the workload. Fixed-weight security and complete noise bounds
remain experimental; see the [construction and limitations](../../docs/tfhe-sparse-pbs.md).
Sparse ternary is not supported. Optional sparse CBS material is described below.

`ServerKey::bootstrapping_key()` and `into_parts()` expose `BootstrappingKey::{Classic, Sparse}`;
the evaluator binds and dispatches the selected workspace automatically. Raw composition
uses `try_generate_sparse_bootstrapping_key`, `SparseGlweBlindRotationContext::new(&key)`
and `fourier_blind_rotate_lookup_table_to` / `fourier_blind_rotate_interleaved_lookup_table_to`.
These raw calls output coefficient GLWE under the accumulator secret, without key
switching or extraction. `bucket(j)` borrows public input indices and their selectors,
followed by one dummy.

## Circuit bootstrapping

CBS supports classic binary/ternary and fixed-weight binary sparse keys, both
PBS orders and both FFT engines. It produces Fourier GGSW under the accumulator secret.

Choose a `CircuitBootstrapConfig` naming output/trace/scheme-switch decompositions and independent
trace/SS noise. The native modulus, ring layout and secret distribution come from the
accumulator; construction checks padded gadget-level capacity and binds the input
plaintext modulus. `CircuitBootstrapParameters::try_new` also accepts existing bases and GLev/GGSW parameters.
The scheme-switch key binds the output layout; another output basis with the same
level count can reuse the key.

Generate a paired client/server key with
`context.try_generate_keys(Some(config), &mut rng)`.
The `ServerKey` owns the CBS parameters and trace/scheme-switch keys, generated with
its ordinary PBS material from the same secrets and transform table. Use
`None` for PBS only: no CBS key material or CBS workspace is allocated.
Both `context.evaluator(&server)` and `context.circuit_bootstrap_evaluator(&server)`
use that server key; the latter returns `MissingCircuitBootstrapKey` when CBS is absent.
Only the selected evaluator allocates its workspace. For sparse CBS use
`generator.try_generate_sparse_server_key(&client, copies, buckets, Some(config), &mut rng)`.
Both server-key factories return `KeyGenerationError`.

For advanced composition, `try_generate_circuit_bootstrap_key` owns its prepared parameters,
and `CircuitBootstrapEvaluator::try_from_parts` accepts explicit parameters and material.
The caller must pair secrets and use the generating transform representation; layout checks
cannot verify identity. Bound parameters are available via
`server.circuit_bootstrap_key().unwrap().parameters()`.

`circuit_bootstrap_to` writes into an existing `FourierGgsw` containing
`parameters.output_size().fourier_ggsw_len()` complex values, without online allocations.
`circuit_bootstrap` allocates the output. The pipeline reuses the ordinary evaluator's
input KS/BR workspace, then projects each gadget level and performs scheme switching.
Input uses unsigned rounded LWE encoding in `0..ceil(t/2)`; its noise must fit the
coarser ManyLUT intervals. CMUX requires input 0 or 1. The result remains under the
accumulator secret with gadget scales; it does not pass through the ordinary PBS output KS.

Native reverse trace retains the low-level per-stage integer halving. Its rounding,
trace key switching, scheme-switch decomposition and FFT precision require a CBS
error budget; these parameter checks do not validate noise or security. Sparse CBS
also includes every bucket's zero selectors/dummies and aggregate FFT error. Budget
against the smallest output gadget scale; CMUX decoding alone does not establish
that margin. See the [validated parameter scope](../../docs/tfhe-cbs.md#7-b63-fourier-sparse-cbs).

Run the [CBS→CMUX example](examples/circuit_bootstrap.rs) to select between two
encrypted GLWE messages using an LWE bit, with reusable outputs in both orders.
Pass `--sparse` to select sparse keys:

```sh
cargo run --release -p primus_tfhe_glwe_fourier --example circuit_bootstrap
```

See the [CBS error budget and costs](../../docs/tfhe-cbs.md) for parameter-selection
considerations. Example parameters are not production recommendations.

Use `evaluator.allocate_output()` to allocate the raw CBS control, then
`evaluator.cmux_to(control, lhs, rhs, output)` or `external_product_to(control, input, output)`.
`context.accumulator_client(&client)` binds ring encryption/decryption and conversion scratch.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/circuit_bootstrap.rs).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Further reading

[Implementation and developer validation](../../docs/tfhe.md) · [Benchmarks and measurements](../../docs/benchmarks/tfhe.md)
