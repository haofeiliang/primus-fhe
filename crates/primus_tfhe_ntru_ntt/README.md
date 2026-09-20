# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

NTT backend for NTRU-based TFHE. Uses an explicit field modulus and the context's NTT representation.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

See the [shared capability and encoding guide](../primus_tfhe/README.md) and
[NTRU family/key domains](../primus_tfhe_ntru/README.md). Both NTRU backends support
PBS, ManyLUT, Boolean gates and CBS.
Both backends also support fixed-scale factorized MVB, with their respective modulus and scale requirements.
See the [shared Boolean contracts](../primus_tfhe/README.md#boolean-gates).

Custom NTT tables must implement `MonomialNttTable`; built-in `UintNttTable` supports it.

## Reusing evaluators

Move an existing `Evaluator` into `FactorizedEvaluator::try_from_bootstrapper` or
`CircuitBootstrapEvaluator::try_from_bootstrapper` to allocate only the additional MVB/CBS buffers.
Use `bootstrapper_mut()` to alternate ordinary single-output/interleaved PBS; import
`primus_tfhe::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved}` for those operations.
This borrow exposes PBS operations without allowing replacement of the bound evaluator.
`into_bootstrapper()` releases the extra buffers and recovers ordinary workspace; recovery
allocates nothing when the specialized evaluator was constructed from an ordinary one.

NTRU CBS shares initialization, BR and return-KS workspace with ordinary PBS. MVB/CBS still reject sparse server keys.

## Ordinary PBS and ManyLUT

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, U32NttTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves NTT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys with `context.try_generate_keys(circuit_bootstrap, rng)`, obtain an encryptor/evaluator/decryptor,
and compile LUTs through `context.parameters()`.
The [message/carry example](examples/ntru_ntt_basic.rs) demonstrates multiple outputs
sharing one BR and one ring key switch. Ordinary PBS returns LWE under the client
secret; its post-BR NTRU key switch maps f_acc to f_client.

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_basic
```

The example computes message, carry and parity (`x % 4`, `x / 4`, `x % 2`)
from one input with `t_in=16 → t_out=4`: three outputs occupy four interleaved slots. It is not a complete
encrypted-integer system.

LUT compilation takes an output `RoundedCodec` first; the example decodes
with `decrypt_phase` and that codec. Input geometry keeps the parameter encoding.

The same example also compares encrypted `x` in `0..3` and `y` in `0..2` with
`BivariateLookupTable`, packing `x+3*y` before one ordinary PBS. It reuses keys,
evaluator scratch and output buffers. The [shared two-input contract](../primus_tfhe/README.md#bounded-two-input-pbs)
explains the common input scale and amplified error.

The [shared encoding guide](../primus_tfhe/README.md#choosing-the-output-encoding)
and [NTRU client/LUT contract](../primus_tfhe_ntru/README.md#clients-and-luts)
cover input domains, output codecs, odd full-domain PBS and ManyLUT noise margins.

## Experimental sparse PBS

Select `SecretKeyDistr::fixed_hamming_weight_binary(n, h)` for `external_lwe`,
with `0<h<n`. Generate the invertible client once, then explicitly choose bucket
aggregation; selecting a low-weight distribution alone still uses classic BR.

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

The fixed-client factory also exists on `TfheContext`. It returns the usual
`ServerKey`, with coefficient NGSW selectors accessible through
`sparse_bootstrapping_key()`. Ordinary and interleaved LUT calls reuse the same
evaluator and buffers. CBS and factorized MVB return `UnsupportedSparseBootstrapping`,
including CBS binding with standalone material.

Map generation retries at most eight times without changing the client; errors
return through `KeyGenerationError::SparseBootstrapping`, preserving `BucketMap`
failures. NTRU conversion errors remain `KeyGenerationError::Ntru`.
Invertibility and successful matching condition the secret/map distribution.
Budget initialization, every bucket, coarser ManyLUT rotations and return KS;
this experimental path does not certify security or a failure probability.

Run the [sparse message/carry example](examples/ntru_ntt_sparse.rs):

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_sparse
```

## Public-key clients

`client_key.try_generate_public_key(context.parameters(), &mut rng)` generates an
`LwePublicKey` under the external binary/ternary prefix secret. Pass it to
`context.encryptor(&public_key)` for `encrypt`, `encrypt_padded` and
`encrypt_centered`. Their `_to(message, output, rng)` counterparts reuse existing
ciphertext storage without allocation for both public and secret keys. Message
and dimension errors leave output and RNG unchanged.

Public-key noise, storage and key-identity requirements are described in the
[NTRU client contract](../primus_tfhe_ntru/README.md#clients-and-luts).

## Boolean gates

Set `external_lwe` plaintext modulus to 4 and generate ordinary PBS keys with
`context.try_generate_keys(None, rng)`. Bind `boolean_encryptor` (private/public key),
`boolean_decryptor` and `boolean_evaluator` from that context. Reuse raw LWE outputs
with `evaluate_binary_to`, `not_to` and `mux_to`; no additional evaluation key is needed.
See the [shared example and contracts](../primus_tfhe/README.md#boolean-gates).

## Fixed-scale factorized MVB

`context.compile_factorized_lookup_table_fn` prepares a program bound to this
context; `context.factorized_evaluator(&server)` reuses ordinary PBS keys and
workspace plus one NTT polynomial. For a context with `t_in=16`:

```rust,ignore
let codec = ScaledCodec::new(4u32, context.parameters().accumulator_ntru().cipher_modulus());
let program = context.compile_factorized_lookup_table_fn(&codec, 8, 3, |m, i| {
    match i { 0 => (m % 4) as u32, 1 => (m / 4) as u32, _ => (m % 2) as u32 }
})?;
let input = context.encryptor(&client)?.encrypt_padded(6, &mut rng)?;
let decryptor = context.decryptor(&client)?;
let mut mvb = context.factorized_evaluator(&server)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
mvb.apply_lookup_table_to(&input, &program, &mut outputs);
for (output, expected) in outputs.iter().zip([2, 1, 0]) {
    assert_eq!(codec.decode_value(decryptor.decrypt_phase(output)?), expected);
}
```

Inputs use the context's Rounded front-half encoding; outputs share unsigned
Scaled encoding under the same odd ciphertext modulus. Keep the output codec
for decoding. Output count is unpadded and does not reduce rotation resolution.

One `NLev[1]` initialization and BR of the common polynomial are shared. Each
output multiplies its factor, performs an NTRU key switch and extracts compact
LWE under the external client secret. Factor norms amplify initialization and
BR error; key-switch error is added afterward.
Context identity, input dimension, exact output count and every output dimension
are checked before output writes; `_to` calls allocate nothing.

Algebra and encoding limits follow the [shared contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Run the [threshold example](examples/ntru_ntt_mvb_thresholds.rs) to turn one
encrypted score in `0..64` into 17 numeric flags beyond interleaved capacity:

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_mvb_thresholds
```

It reuses the program and ciphertext buffers, decoding with the retained Scaled
codec. These numeric flags use a different encoding from the Boolean evaluator.
See [NTRU MVB costs and noise](../../docs/tfhe-mvb-ntru.md) when comparing it with
repeated PBS or interleaved ManyLUT.

## Optional circuit bootstrapping

Choose a `CircuitBootstrapConfig` selecting output/trace/scheme-switch decompositions and
independent trace/SS noise. Length, modulus and accumulator secret distribution are
derived automatically. `CircuitBootstrapParameters::try_new` still accepts existing bases/NLev parameters.

Generate a paired client/server key with
`context.try_generate_keys(Some(config), &mut rng)`.
The `ServerKey` owns the CBS parameters and trace/scheme-switch keys, generated with
its ordinary PBS material from the same secrets and transform table. Use
`None` for PBS only: no CBS key material or CBS workspace is allocated.
Both `context.evaluator(&server)` and `context.circuit_bootstrap_evaluator(&server)`
use that server key; the latter returns `MissingCircuitBootstrapKey` when CBS is absent
from a classic key, and rejects sparse keys.
Only the selected evaluator allocates its workspace. Key generation returns `KeyGenerationError`;
NTRU sampling/conversion failures use its `Ntru` variant; `ClientKey` reports compatibility failures.

For advanced composition, `try_generate_circuit_bootstrap_key` owns its prepared parameters,
and `CircuitBootstrapEvaluator::try_from_parts(context, server, circuit_key)` uses the parameters
and complete output basis owned by the circuit key.
The caller must pair secrets and use the generating transform representation; layout checks
cannot verify identity. Bound parameters are available via
`server.circuit_bootstrap_key().unwrap().parameters()`.

NTT CBS outputs `NttNgswCiphertext` and requires odd q below `2^(T::BITS-1)`
for trace normalization.
The [shared CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples)
describes gadget scales, accumulator-key identity and independent noise/security budgets.

Run the [CBS → CMUX example](examples/ntru_ntt_circuit_bootstrap.rs):

```sh
cargo run -p primus_tfhe_ntru_ntt --example ntru_ntt_circuit_bootstrap
```

It builds paired ordinary/CBS keys, encrypts two NTRU candidates under `f_acc`,
and repeatedly turns an external LWE bit into a gadget-scaled NGSW control.
CMUX selects the first candidate for 0 and the second for 1. The example reuses
input, control, selected output and server scratch, then decrypts to check the result.

Use `evaluator.allocate_output()` to allocate the raw CBS control, then
`evaluator.cmux_to(control, lhs, rhs, output)` or `external_product_to(control, input, output)`.
`context.accumulator_client(&client)` binds ring encryption/decryption and conversion scratch;
construction failures return `TfheClientError`.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/ntru_ntt_circuit_bootstrap.rs).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Further reading

[Implementation and developer validation](../../docs/tfhe.md) · [Benchmarks and measurements](../../docs/benchmarks/tfhe.md)
