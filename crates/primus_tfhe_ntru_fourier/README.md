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

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys, obtain an encryptor/evaluator/decryptor, and compile LUTs through the context.
The [message/carry example](examples/ntru_fourier_basic.rs) demonstrates multiple outputs
sharing one BR and one ring key switch. Ordinary PBS returns LWE under the client
secret; its post-BR NTRU key switch maps f_acc to f_client.

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_basic
```

Message/carry here means two functions (`x % 4`, `x / 4`) of one input;
it is not a complete encrypted-integer system.

Public PBS validates LUT input domain, encoding moduli, ring length and all output
dimensions. Raw LWE input must use the context's external key, canonical residues
and unsigned rounded encoding. Independently programmable inputs are
`0..ceil(t/2)`; the remaining half follows negacyclic extension. ManyLUT output
count is a power of two and requires `ceil(t/2) <= N/count`, reducing rotation
resolution and thus the allowed input-noise margin. Boolean/CBS output scales
can differ from ordinary plaintext encoding.

## Public-key clients

`client_key.try_generate_public_key(context.parameters(), &mut rng)` generates an
`LwePublicKey` under the external binary prefix secret. Pass it to
`context.encryptor(&public_key)` for `encrypt`, `encrypt_padded` and
`encrypt_centered`. Their `_to(message, output, rng)` counterparts reuse existing
ciphertext storage without allocation for both public and secret keys. Message
and dimension errors leave output and RNG unchanged.

Generation and fresh encryption errors use the `external_lwe` noise sampler.
The total error is `e^T r + e2 - e1^T s`; that sampler does not describe the final
ciphertext noise. Parameters must satisfy the
[underlying public-key contract](../primus_lwe/README.md#public-key-encryption)
and the PBS/ManyLUT input margin. Dimension/modulus checks cannot verify secret
identity; use paired client/server keys. Public-key storage contains
`n * (n + 1)` coefficients, excluding the NTRU secret's zero padding.

## Optional circuit bootstrapping

`CircuitBootstrapParameters`, `CircuitBootstrapKey` and `CircuitBootstrapEvaluator`
add CBS without adding trace/SS material to ordinary server keys:

```text
external LWE -> gadget-scaled ManyLUT -> one BR under f_acc
             -> reverse-trace coefficient projections -> NLev_f_acc[m]
             -> scheme switch -> Fourier NGSW_f_acc[m]
```

CBS retains the BR ring accumulator. It does not perform ordinary PBS's ring key
switch or LWE extraction, and does not require packing. The general ManyLUT
accumulator has no guaranteed zero message tail, so prefix expansion is not a
valid substitute for its coefficient projections.

CBS takes an output basis and full trace/scheme-switch encryption parameters;
BR parameters and the output ring come from the TFHE context. Only the internal
ManyLUT pads the output level count to a power of two; the NGSW retains the
requested levels. Its scheme-switch key binds the complete output basis.

Run the [CBS → CMUX example](examples/ntru_fourier_circuit_bootstrap.rs):

```sh
cargo run -p primus_tfhe_ntru_fourier --example ntru_fourier_circuit_bootstrap
```

It builds paired ordinary/CBS keys, encrypts two NTRU candidates under `f_acc`,
and repeatedly turns an external LWE bit into a gadget-scaled NGSW control.
CMUX selects the first candidate for 0 and the second for 1. The example reuses
input, control, selected output and server scratch, then decrypts to check the result.

The input still uses unsigned rounded LWE encoding, including for bits. CBS output
uses the selected gadget scalars; it is not an ordinary encoded NTRU plaintext.
Use the output as CMUX control only when the input message is 0/1. The two key
objects must originate from the same accumulator secret and transform table.

Trace and scheme-switch error budgets differ from ordinary PBS. Scheme switching
multiplies input error by f and decomposition error by f². Its evaluation key
contains `NGSW_f[f]`, requiring a justified key-dependent-message/circular-security
assumption. See [NTRU numerical contracts](../primus_ntru/README.md) for modular
versus native normalization and Fourier precision. These implementations do not
supply a security proof, failure-probability estimate or recommended CBS parameters.

## Validation and performance

```sh
cargo test -p primus_tfhe_ntru_fourier
cargo clippy -p primus_tfhe_ntru_fourier --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_fourier --features simd
cargo bench -p primus_tfhe_ntru_fourier --bench pbs
cargo bench -p primus_tfhe_ntru_fourier --bench circuit_bootstrap
```

`pbs` measures complete PBS and 2/4-output ManyLUT, with allocating and
reused-output cases separated. The Fourier cases use both RustFFT and TfheFFT.

CBS tests exercise LWE bits through NGSW and CMUX, padded output counts, basis and
capacity errors, and zero online allocations from the first evaluator call.
`circuit_bootstrap` measures reused output/workspace at N=1024/4096, input dimension
N/16, B=2^3/2^10 for BR/trace/SS, and output B=2^8 with two levels. It reports live
requested heap bytes for the additional CBS key and evaluator; these exclude
allocator overhead, borrowed tables, ordinary server material and caller output.
Key generation and accounting are outside timed closures. Add `-- --test` to
smoke-test fixtures; smoke tests establish neither timing nor decryptability.
SIMD uses existing dependency kernels, with no public ISA-selection API.
