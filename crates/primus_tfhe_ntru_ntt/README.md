# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

NTT backend for NTRU-based TFHE. Uses an explicit field modulus and the context's NTT representation.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

See the [shared capability and encoding guide](../primus_tfhe/README.md) and
[NTRU family/key domains](../primus_tfhe_ntru/README.md). Both NTRU backends support
PBS, ManyLUT, Boolean gates and CBS.
The NTT backend additionally supports fixed-scale factorized MVB.
See the [shared Boolean contracts](../primus_tfhe/README.md#boolean-gates).

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

## Public-key clients

`client_key.try_generate_public_key(context.parameters(), &mut rng)` generates an
`LwePublicKey` under the external binary prefix secret. Pass it to
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
The [integration test](tests/boolean.rs) covers all six binary gates, NOT, MUX,
chained evaluation, dimension errors and zero-allocation reuse, plus a public-key NAND path.

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
The program consumes one contiguous coefficient-factor buffer and transforms it
in place; evaluation borrows each factor through `NttPolynomialIter`.

One `NLev[1]` initialization and BR of the common polynomial are shared. Each
output multiplies its factor, performs an NTRU key switch and extracts compact
LWE under the external client secret. Factor norms amplify initialization and
BR error; key-switch error is added afterward. Ordinary PBS workspace stays unchanged.
Context identity, input dimension, exact output count and every output dimension
are checked before output writes; `_to` calls allocate nothing.

The [integration test](tests/factorized_pbs.rs) covers 1/3/17 outputs, including
interleaved capacity overflow, and compares against identical Scaled single-output
PBS. Algebra and encoding limits follow the [shared contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb).

Run the [threshold example](examples/ntru_ntt_mvb_thresholds.rs) to turn one
encrypted score in `0..64` into 17 numeric flags beyond interleaved capacity:

```sh
cargo run -p primus_tfhe_ntru_ntt --release --example ntru_ntt_mvb_thresholds
```

It reuses the program and ciphertext buffers, decoding with the retained Scaled
codec. These numeric flags use a different encoding from the Boolean evaluator.
The [NTRU measurements](../../docs/tfhe-mvb-ntru.md) compare identical Scaled
outputs from repeated PBS, ManyLUT and MVB, including initializer/BR/KS error,
output correlations and memory. They use a fixed-weight binary secret with
classic BR and invertibility rejection; they are not production parameters.

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
use that server key; the latter returns `MissingCircuitBootstrapKey` when CBS is absent.
Only the selected evaluator allocates its workspace. Key generation returns `KeyGenerationError`;
NTRU sampling/conversion failures use its `Ntru` variant; `ClientKey` reports compatibility failures.

For advanced composition, `try_generate_circuit_bootstrap_key` owns its prepared parameters,
and `CircuitBootstrapEvaluator::try_from_parts` accepts explicit parameters and material.
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
`context.accumulator_client(&client)` binds ring encryption/decryption and conversion scratch.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/ntru_ntt_circuit_bootstrap.rs).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Validation and performance

```sh
cargo test -p primus_tfhe_ntru_ntt
cargo clippy -p primus_tfhe_ntru_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_ntt --features simd
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap
```

`pbs` reuses output buffers and measures complete PBS and 3/4-output ManyLUT
against separate PBS calls. Setup is outside timing.

CBS tests exercise LWE bits through NGSW and CMUX, non-power-of-two level counts, basis and
capacity errors, and zero online allocations from the first evaluator call.
`circuit_bootstrap` measures reused output/workspace at N=1024/4096, input dimension
N/16, B=2^3/2^10 for BR/trace/SS, and output B=2^8 with two levels. It reports live
requested heap bytes for the additional CBS key and evaluator; these exclude
allocator overhead, borrowed tables, ordinary server material and caller output.
Key generation and accounting are outside timed closures. Add `-- --test` to
smoke-test fixtures; smoke tests establish neither timing nor decryptability.
SIMD uses existing dependency kernels, with no public ISA-selection API.
