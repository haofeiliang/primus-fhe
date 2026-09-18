# primus_tfhe_ntru_fourier

English | [简体中文](README.zh_CN.md)

Fourier backend for NTRU-based TFHE. Uses the native wrapping modulus. Every transformed key, value and evaluator
must use the same FFT table instance; matching lengths do not prove table identity.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

See the [shared capability and encoding guide](../primus_tfhe/README.md) and
[NTRU family/key domains](../primus_tfhe_ntru/README.md). Both NTRU backends support
PBS, ManyLUT and CBS; NTRU Boolean adapters are not implemented.

## Ordinary PBS and ManyLUT

Declare mathematical choices with `TfheParameters::try_from_config(TfheConfig { .. })`,
then use `TfheContext::<_, RustFftTable>::try_from_parameters(parameters)` to build a
matching transform table. The caller still selects the table type; construction
preserves FFT failures in `TfheContextError::TransformTable`. Use
`try_new(parameters, table)` to inject an existing table.

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys with `context.try_generate_keys(circuit_bootstrap, rng)`, obtain an encryptor/evaluator/decryptor,
and compile LUTs through `context.parameters()`.
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

## Public-key clients

`client_key.try_generate_public_key(context.parameters(), &mut rng)` generates an
`LwePublicKey` under the external binary prefix secret. Pass it to
`context.encryptor(&public_key)` for `encrypt`, `encrypt_padded` and
`encrypt_centered`. Their `_to(message, output, rng)` counterparts reuse existing
ciphertext storage without allocation for both public and secret keys. Message
and dimension errors leave output and RNG unchanged.

Public-key noise, storage and key-identity requirements are described in the
[NTRU client contract](../primus_tfhe_ntru/README.md#clients-and-luts).

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

Error ownership and conversion rules follow the [shared TFHE error boundaries](../primus_tfhe/README.md#error-boundaries).

## Validation and performance

```sh
cargo test -p primus_tfhe_ntru_fourier
cargo clippy -p primus_tfhe_ntru_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_fourier --features simd
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
cargo bench -p primus_tfhe_ntru_fourier --bench circuit_bootstrap
```

`pbs` reuses output buffers and measures complete PBS and 3/4-output ManyLUT
against separate PBS calls. The Fourier cases use both RustFFT and TfheFFT.

CBS tests exercise LWE bits through NGSW and CMUX, non-power-of-two level counts, basis and
capacity errors, and zero online allocations from the first evaluator call.
`circuit_bootstrap` measures reused output/workspace at N=1024/4096, input dimension
N/16, B=2^3/2^10 for BR/trace/SS, and output B=2^8 with two levels. It reports live
requested heap bytes for the additional CBS key and evaluator; these exclude
allocator overhead, borrowed tables, ordinary server material and caller output.
Key generation and accounting are outside timed closures. Add `-- --test` to
smoke-test fixtures; smoke tests establish neither timing nor decryptability.
SIMD uses existing dependency kernels, with no public ISA-selection API.
