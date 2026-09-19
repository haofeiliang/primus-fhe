# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

Fourier backend for NTRU-based TFHE. Uses the native wrapping modulus. Every transformed key, value and evaluator
must use the same FFT table instance; matching lengths do not prove table identity.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

See the [shared capability and encoding guide](../primus_tfhe/README.md) and
[NTRU family/key domains](../primus_tfhe_ntru/README.md). Both NTRU backends support
PBS, ManyLUT, factorized MVB, Boolean gates and CBS.
See the [shared Boolean contracts](../primus_tfhe/README.md#boolean-gates).

## Ordinary PBS and ManyLUT

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves FFT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys with `context.try_generate_keys(circuit_bootstrap, rng)`, obtain an encryptor/evaluator/decryptor,
and compile ordinary/interleaved LUTs through `context.parameters()`.
The [message/carry example](examples/ntru_fourier_basic.rs) demonstrates multiple outputs
sharing one BR and one ring key switch. Ordinary PBS returns LWE under the client
secret; its post-BR NTRU key switch maps f_acc to f_client.

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_basic
```

The example computes message, carry and parity (`x % 4`, `x / 4`, `x % 2`)
from one input with `t_in=16 → t_out=4`: three outputs occupy four interleaved slots. It is not a complete
encrypted-integer system.

LUT compilation takes an output `RoundedCodec` first; the example decodes
with `decrypt_phase` and that codec. Input geometry keeps the parameter encoding.

The [shared encoding guide](../primus_tfhe/README.md#choosing-the-output-encoding)
and [NTRU client/LUT contract](../primus_tfhe_ntru/README.md#clients-and-luts)
cover input domains, output codecs, odd full-domain PBS and ManyLUT noise margins.

## Experimental sparse PBS

Select `SecretKeyDistr::fixed_hamming_weight_binary(n, h)` for `external_lwe`,
with **odd** `h` and `0<h<n`. Fix one accepted client before choosing bucket aggregation:

```rust,ignore
let mut generator = KeyGenerator::new(&context);
let client = generator.try_generate_client_key(&mut rng)?;
let server = generator.try_generate_sparse_server_key(&client, 3, 2 * h, &mut rng)?;
let mut evaluator = context.evaluator(&server)?;
```

The fixed-client factory is also available on `TfheContext`. Ordinary and
interleaved LUT calls reuse the existing `ServerKey`, evaluator and output buffers.
`server.sparse_bootstrapping_key()` exposes coefficient controls and the public map.
CBS and factorized MVB reject sparse keys with `UnsupportedSparseBootstrapping`,
including CBS binding with standalone material.

Even weight is noninvertible in the Native ring and returns
`KeyGenerationError::Ntru(NonInvertibleSecretKey)` before sampling. Odd weight
still requires a stable Fourier inverse. Mapping retries at most eight times
without changing the client; mapping and sparse validation errors use
`KeyGenerationError::SparseBootstrapping`. Acceptance conditions the secret/map
distribution and does not certify security or a failure probability.

Supports u32/u64 with RustFFT and TfheFFT. Keep all Fourier material on the same
FFT table instance. Stored selectors are recovered from Fourier to Native
coefficients, then aggregated exactly; recovery, each aggregate FFT, initialization,
external products and return KS all contribute to the numerical/noise budget.

Run the [sparse message/carry example](examples/ntru_fourier_sparse.rs), which uses both FFTs:

```sh
cargo run -p primus_tfhe_ntru_fourier --release --example ntru_fourier_sparse
```

## Fixed-scale factorized MVB

Use `context.compile_factorized_lookup_table_fn(&codec, input_domain_len,
output_count, function)` with an unsigned `ScaledCodec` and a nonempty front-half
input prefix. The actual Native scale must be even; odd scales return
`LookupTableError::OddFactorizationScale`. Both u32/u64 and RustFFT/TfheFFT are supported.
The plaintext modulus need not be a power of two: `t_out=10` works for both widths.

```rust,ignore
use primus_encoding::ScaledCodec;

let codec = ScaledCodec::new(10u32, NativeModulus::new());
let lut = context.compile_factorized_lookup_table_fn(
    &codec, 8, 3, |m, i| u32::from(m > i),
)?; // Assumes t_in >= 15 and sufficient noise margins.
let mut evaluator = context.factorized_evaluator(&server_key)?;
let mut outputs = vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
let value = codec.decode_value(decryptor.decrypt_phase(&outputs[0])?);
```

`FourierFactorizedLookupTable` prepares integer Fourier factors once and borrows
one context. A different context instance is rejected even with equal parameters;
explicit preparation uses `FourierFactorizedLookupTable::new(context, coefficient_lut)`.
The prepared program stores N torus coefficients and `output_count*N/2` complex
values, with no retained coefficient copy of the factors.

All outputs share encrypted `NLev[1]` initialization and one binary or ternary BR. Each
factor product is then key-switched from `f_acc` to `f_client` and compactly
extracted into the usual external LWE dimension. No additional key is needed.
The evaluator adds two Fourier polynomials (N complex values), independent of
output count, and `_to` checks all dimensions before writing with no online allocation.

Factors amplify **initialization and BR noise**. FFT products add phase error
`f_acc * delta_c`, followed by per-output key-switch error. Successful compilation
does not certify a noise budget; decode with the supplied Scaled codec and budget
center differences before another Rounded-input PBS. See the
[shared encoding contract](../primus_tfhe/README.md#fixed-scale-factorized-mvb) and
[NTRU precision evidence](../../docs/tfhe-mvb-fourier.md#b53ntru-接入与独立误差验收).
The [basic example](examples/ntru_fourier_basic.rs) reuses public-key inputs for
ManyLUT and MVB with explicit output codecs.

The [17-threshold example](examples/ntru_fourier_mvb_thresholds.rs) evaluates a score in
`0..64` beyond interleaved capacity. Its Scaled `t_out=2` numeric flags are not
Boolean gate ciphertexts or inputs at another plaintext modulus. See
[measured algorithm costs](../../docs/tfhe-mvb-fourier-costs.md) for the tradeoff
between repeated PBS, interleaving and MVB, including key/workspace sizes and noise.

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_mvb_thresholds
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
and `CircuitBootstrapEvaluator::try_from_parts` accepts explicit parameters and material.
The caller must pair secrets and use the generating transform representation; layout checks
cannot verify identity. Bound parameters are available via
`server.circuit_bootstrap_key().unwrap().parameters()`.

Fourier CBS outputs `FourierNgswCiphertext`. Budget native coefficient halving
and FFT errors, and use the same FFT table instance throughout.
The [shared CBS contract](../primus_tfhe_ntru/README.md#cbs-and-examples)
describes gadget scales, accumulator-key identity and independent noise/security budgets.

Run the [CBS → CMUX example](examples/ntru_fourier_circuit_bootstrap.rs):

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap
```

It builds paired ordinary/CBS keys, encrypts two NTRU candidates under `f_acc`,
and repeatedly turns an external LWE bit into a gadget-scaled NGSW control.
CMUX selects the first candidate for 0 and the second for 1. The example reuses
input, control, selected output and server scratch, then decrypts to check the result.

Use `evaluator.allocate_output()` to allocate the raw CBS control, then
`evaluator.cmux_to(control, lhs, rhs, output)` or `external_product_to(control, input, output)`.
`context.accumulator_client(&client)` binds ring encryption/decryption and conversion scratch.
See the [shared consumption contracts](../primus_tfhe/README.md#cbs-output-and-consumption)
and [complete example](examples/ntru_fourier_circuit_bootstrap.rs).

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Further reading

[Implementation and developer validation](../../docs/tfhe.md) · [Benchmarks and measurements](../../docs/benchmarks/tfhe.md)
