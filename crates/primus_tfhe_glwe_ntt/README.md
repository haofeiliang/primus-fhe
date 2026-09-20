# primus_tfhe_glwe_ntt

English | [简体中文](README.zh_CN.md)

GLWE-based TFHE over an explicit field modulus. Supports both PBS orders, ManyLUT, factorized MVB,
Boolean gates and secret/public-key clients. See the [capability and encoding guide](../primus_tfhe/README.md)
and [GLWE parameter/key domains](../primus_tfhe_glwe/README.md).

`Encryptor`, `Decryptor`, `TfheConfig` and `TfheParameters` specialize the shared types to
`BarrettModulus`; `ClientKey`, `EncryptionKey` and `PbsOrder` are re-exported directly.

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
cargo run -p primus_tfhe_glwe_ntt --example ntt_basic
```

The [example source](examples/ntt_basic.rs) runs both orders with the same
workflow: parameters → context → paired keys → public-key encryptor/client decryptor
→ compiled LUT → reusable evaluator/output. It demonstrates single PBS, two-output
ManyLUT with `t_in=4 → t_out=8`, client `encrypt_padded_to`, Boolean gates, NOT and MUX.

For `BootstrapKeyswitch`, external ciphertexts have dimension `n`; for
`KeyswitchBootstrap`, they have dimension `kN`. Both inputs and outputs follow
the chosen external key. Example dimensions, noise and decomposition choices are
for functional demonstration, not production security or failure-probability recommendations.

## Context and reuse

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves NTT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext::try_new` checks the NTT length and modulus. NTT-domain keys and values
must use the supplied table's NTT representation. `boolean_parameters()` is a
development fixture, not a vetted default; the example selects its own small parameters.

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

Compile once with an unsigned `ScaledCodec`, then reuse a dedicated evaluator:

```rust,ignore
use primus_encoding::ScaledCodec;

let codec = ScaledCodec::new(2u32, context.parameters().accumulator_glwe().cipher_modulus());
// This example assumes t_in >= 8 and sufficient input/output noise margins.
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 4, 3, |m, i| u32::from(m > i),
)?;
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
let input = encryptor.encrypt_padded(2, &mut rng)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
assert_eq!(codec.decode_value(decryptor.decrypt_phase(&outputs[1])?), 1);
```

The arguments after the codec are the input prefix length and exact output count.
Compilation returns `NttFactorizedLookupTable`, borrowing this context; a different
context instance is rejected even with identical q and N. Lower-level callers
can compile `FactorizedLookupTable` and consume it through `NttFactorizedLookupTable::new`.

Classic and sparse keys work in both orders. BK runs BR once, then multiplies and
key-switches each output; KB switches the input once, then runs BR and the products.
Rotation step remains one for any positive output count. `_to` checks context,
input, output count and every output dimension before writing, and allocates nothing.
Extra workspace is one `(d+1)*N`-coefficient NTT GLWE, independent of output count.
The program stores `(output_count+1)*N` coefficients.

Use the output codec to decode phases. Factor norms amplify BR noise, and Scaled
centers can differ from Rounded centers when chaining PBS. See the
[shared contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Run the [threshold example](examples/mvb_thresholds.rs):

```sh
cargo run -p primus_tfhe_glwe_ntt --release --example mvb_thresholds
```

It turns one encrypted score in `0..64` into 17 numeric threshold flags, reusing
one compiled program and all ciphertext buffers. At N=1024 the interleaved
layout would leave only 32 positions for 64 inputs. Each threshold has a
two-term difference factor with L1 norm 2, limiting its noise amplification.
Prefer interleaving when it fits with enough input-noise margin; factorization
retains step-one resolution at a higher program/compilation cost. See the
[measurements and selection conditions](../../docs/tfhe-mvb.md#8-p43-测量与应用选择).

## Experimental sparse PBS

Set the **small-LWE** distribution to `SecretKeyDistr::fixed_hamming_weight_binary(n, h)`
and generate a sparse server key explicitly:

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client_key = ClientKey::generate(context.parameters(), &mut rng);
let server_key = generator.try_generate_sparse_server_key(&client_key, 3, 2 * h, None, &mut rng)?;
let mut evaluator = context.evaluator(&server_key)?;
evaluator.apply_lookup_table_to(&input, &lut, &mut output);
// The same evaluator supports apply_interleaved_lookup_table_to.
```

Both orders use that small secret for blind rotation. External dimensions remain
`n` for `BootstrapKeyswitch` and `kN` for `KeyswitchBootstrap`. Ordinary and interleaved
PBS share the usual LUT compiler, output codec, key switch and extraction; `_to`
calls allocate nothing. Ordinary key factories generate classic keys; use the
sparse factory above to select this algorithm. `ServerKey::bootstrapping_key()` returns
`BootstrappingKey::{Classic, Sparse}` for callers needing the raw key.

Sparse server keys also work with `context.boolean_evaluator(&server_key)` when
`t=4`, and with bounded bivariate or odd full-domain LUTs through the ordinary
evaluator. Account for gate preprocessing, packing error amplification and the
narrower odd full-domain input margin when choosing parameters.

Generation checks actual binary coefficients and weight, then tries at most eight
independent public bucket maps with the same secret. Errors return no partial key.
The example uses three copies and `2*h` buckets.

For raw ordinary blind rotation, `try_generate_sparse_bootstrapping_key` returns
`SparseGlweBootstrappingKey`; pair it with `SparseGlweBlindRotationContext::new(&key)`
and call `ntt_blind_rotate_lookup_table_to` with a small-LWE input and encoded
polynomial. This lower-level call outputs an accumulator GLWE at rotation step one.

Sparse aggregation and interleaved rotation steps require their own noise budget.
These parameters have no certified security level or full PBS failure bound; see
[sparse PBS design and measurements](../../docs/tfhe-sparse-pbs.md#p35-完整-pbs-接入与验收).

## Binary and ternary small secrets

Select `SecretKeyDistr::UniformTernary` or another ternary family in `LweParameters`;
the key-generation and evaluator APIs are unchanged. The basic example uses this
configuration. Both PBS orders, ordinary/interleaved LUTs and public-key inputs work.
Ternary keys require more key and workspace storage than binary keys; see the
[ternary design and costs](../../docs/tfhe-ternary.md).

NTT contexts/BR require `MonomialNttTable`, implemented by every built-in NTT table.
Classic ternary also supports CBS and factorized MVB. Bucketed sparse PBS still
requires fixed-weight binary; the `SparseTernary` distribution does not select it.

## Circuit bootstrapping

CBS supports classic binary/ternary and fixed-weight binary sparse server keys
in both orders. Both produce the same NTT GGSW layout and share trace/scheme-switch material.

Generate a paired client/server key with
`context.try_generate_keys(Some(config), &mut rng)`.
The `ServerKey` owns the CBS parameters and trace/scheme-switch keys, generated with
its ordinary PBS material from the same secrets and transform table. Use
`None` for PBS only: no CBS key material or CBS workspace is allocated.
Both `context.evaluator(&server)` and `context.circuit_bootstrap_evaluator(&server)`
use that server key; the latter returns `MissingCircuitBootstrapKey` when CBS is absent.
Only the selected evaluator allocates its workspace. For sparse CBS, use
`generator.try_generate_sparse_server_key(&client, copies, buckets, Some(config), &mut rng)`.
Both server-key factories return `KeyGenerationError`; `SparseBootstrapping` preserves
sparse generation failures, including their source errors.

For advanced composition, `try_generate_circuit_bootstrap_key` owns its prepared parameters,
and `CircuitBootstrapEvaluator::try_from_parts` accepts explicit parameters and material.
The caller must pair secrets and use the generating transform representation; layout checks
cannot verify identity. Bound parameters are available via
`server.circuit_bootstrap_key().unwrap().parameters()`.

The output basis defines GGSW gadget scales; output
layout comes from the accumulator. The circuit key binds output layout and the
trace/scheme-switch bases. CBS preserves the accumulator secret and skips ordinary
PBS's postprocessing. `CircuitBootstrapConfig` names output/trace/scheme-switch decompositions and independent
trace/SS noise; ring parameters come from the accumulator. `try_new` retains direct binding
of existing low-level parameters.
Trace/SS noise and key-dependent-message
assumptions need a separate assessment. Sparse CBS must also budget every bucket's
aggregation noise, including zero selectors and dummies, against the smallest output
gadget scale; successful ordinary PBS or CMUX decoding alone does not establish that margin.
See the [validated parameter scope](../../docs/tfhe-sparse-cbs.md#3-最小尺度与可用范围).

Use `evaluator.allocate_output()` to allocate the raw CBS control, then
`evaluator.cmux_to(control, lhs, rhs, output)` or `external_product_to(control, input, output)`.
`context.accumulator_client(&client)` binds coefficient-ring encryption/decryption
and reuses outputs and workspace without allocation.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/circuit_bootstrap.rs) (pass `--sparse` for sparse CBS).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Further reading

[Implementation and developer validation](../../docs/tfhe.md) · [Benchmarks and measurements](../../docs/benchmarks/tfhe.md)
