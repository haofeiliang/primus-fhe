# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over an explicit field modulus. Supports both PBS orders, ManyLUT,
Boolean gates and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

## Run the complete example

```sh
cargo run -p primus_tfhe_glwe_ntt --example ntt_basic
```

The [example source](examples/ntt_basic.rs) runs both orders with the same
workflow: parameters → context → paired keys → public-key encryptor/client decryptor
→ compiled LUT → reusable evaluator/output. It demonstrates single PBS, two-output
ManyLUT with `t_in=4 → t_out=8`, client `encrypt_padded_to`, Boolean gates, NOT and MUX.

For `BootstrapKeyswitch`, external ciphertexts have dimension `n`; for
`KeyswitchBootstrap`, they have dimension `kN`. The example prints and checks these
dimensions (4 and 256). Both inputs and outputs follow the chosen external key.
All fixture dimensions, noise and decomposition choices are functional examples,
not production security or failure-probability recommendations.

## Context and reuse

`TfheContext::try_new` checks the NTT length and modulus. NTT-domain keys and values
must use the supplied table's NTT representation. `boolean_parameters()` is a
development fixture, not a vetted default; the example selects its own small parameters.

Compile front-half LUTs with `compile_lookup_table_fn` / `compile_lookup_table_slice`,
or their `compile_interleaved_lookup_table_*` counterparts, passing an output
`RoundedCodec` first. Decode a different output scale using `decrypt_phase` and
that codec. Use unsigned padded input and
account for ManyLUT's coarser rotation resolution. The evaluator holds mutable
scratch; create it once and reuse `apply_lookup_table_to` / `apply_interleaved_lookup_table_to`.
These calls validate all output dimensions before writing.

For odd full domains, use the context's `compile_odd_full_domain_lookup_table_fn`
/ `_slice` with ordinary `encrypt` and the existing single-output evaluator.
See the [shared contract](../primus_tfhe/README.md#odd-full-domain-pbs).

Use `boolean_encryptor`, `boolean_decryptor` and `boolean_evaluator` for `t=4`.
The adapter handles the internal modulus-8 LUT scale. Use `evaluate_binary_to`,
`not_to` and `mux_to` for repeated Boolean evaluation.

Low-level `NttGlweBootstrappingKey<T, LM>` retains the input modulus type `LM`, independently
of the accumulator modulus. Key generation prepares the ordinary-PBS
quantizer. ManyLUT prepares the conversion for the rotation step before coefficient
processing; the high-level context keeps its existing parameter restrictions.

## Experimental sparse PBS

Set the **small-LWE** distribution to `SecretKeyDistr::fixed_hamming_weight_binary(n, h)`
and generate a sparse server key explicitly:

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client_key = generator.generate_client_key(&mut rng);
let server_key = generator.try_generate_sparse_server_key(&client_key, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server_key)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
// The same evaluator supports apply_interleaved_lookup_table_to.
```

Both orders use that small secret for blind rotation. External dimensions remain
`n` for `BootstrapKeyswitch` and `kN` for `KeyswitchBootstrap`. Ordinary and interleaved
PBS share the usual LUT compiler, output codec, key switch and extraction; `_to`
calls allocate nothing. The evaluator allocates only the selected algorithm's
scratch and dispatches once at the blind-rotation boundary. The existing key
factories generate classic keys. `ServerKey::bootstrapping_key()` now returns
`BootstrappingKey::{Classic, Sparse}` for callers needing the raw key.

Generation checks actual binary coefficients and weight, then tries at most eight
independent public bucket maps with the same secret. Errors return no partial key.
The experimental profiles use three copies and `2*h` buckets. Coefficient GGSWs
encode private selections and a dummy per bucket; unoccupied buckets encrypt one
in the dummy. Private matching buffers are erased on drop.

For raw ordinary blind rotation, `try_generate_sparse_bootstrapping_key` returns
`SparseGlweBootstrappingKey`; pair it with `SparseGlweBlindRotationContext::new(&key)`
and call `ntt_blind_rotate_lookup_table_to` with a small-LWE input and encoded
polynomial. This lower-level call outputs an accumulator GLWE at rotation step one.

Sparse aggregation and interleaved rotation steps require their own noise budget.
These parameters have no certified security level or full PBS failure bound; see
[the P3 contract and measurements](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收).

## Circuit bootstrapping

CBS requires a classic server key; sparse keys return
`CircuitBootstrapEvaluationError::UnsupportedSparseBootstrapping` because their
gadget-scale noise has not been validated. Optional CBS uses `CircuitBootstrapParameters::try_new(context.parameters(),
output_basis, trace, scheme_switch)`, `generate_circuit_bootstrap_key` and
`circuit_bootstrap_evaluator`. Ordinary and CBS keys must come from the same client
key and NTT representation. The output basis defines GGSW gadget scales; output
layout comes from the accumulator. The circuit key binds output layout and the
trace/scheme-switch bases. CBS preserves the accumulator secret and skips ordinary
PBS's postprocessing; see the [CBS integration test](tests/circuit_bootstrap.rs)
for projection and CMUX consumption. Trace/SS noise and key-dependent-message
assumptions need a separate assessment.

## Validation and performance

```sh
cargo test -p primus_tfhe_glwe_ntt
cargo clippy -p primus_tfhe_glwe_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_glwe_ntt --features simd
cargo bench -p primus_tfhe_glwe_ntt --bench pbs
cargo bench -p primus_tfhe_glwe_ntt --bench circuit_bootstrap
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs
```

`pbs` reuses output buffers and covers both orders, 3/4-output ManyLUT versus
separate PBS calls, and Boolean AND/MUX. BR and key-switch stages locate costs;
coefficient extraction is benchmarked in `primus_lattice`. `circuit_bootstrap` measures complete CBS for both orders and 2/3 output levels.

`sparse_pbs` compares classic and sparse complete PBS under one fixed-weight client
secret: both orders, ordinary and three-output interleaved LUTs, plus complete
server-key generation (10 cases, `n/h/N=728/32/1024`). Inputs, evaluator and outputs are
prepared outside PBS timing. Each iteration processes one of four encrypted
inputs. Memory, small-profile diagnostics and default/SIMD results are recorded
in the [P3 measurements](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收).
