# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

NTT backend for NTRU-based TFHE. Uses an explicit field modulus and the context's NTT representation.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

## Ordinary PBS and ManyLUT

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys, obtain an encryptor/evaluator/decryptor, and compile LUTs through the context.
The [message/carry example](examples/ntru_ntt_basic.rs) demonstrates multiple outputs
sharing one BR and one ring key switch. Ordinary PBS returns LWE under the client
secret; its post-BR NTRU key switch maps f_acc to f_client.

Public PBS validates LUT input domain, encoding moduli, ring length and all output
dimensions. Raw LWE input must use the context's external key, canonical residues
and unsigned rounded encoding. Independently programmable inputs are
`0..ceil(t/2)`; the remaining half follows negacyclic extension. ManyLUT output
count is a power of two and requires `ceil(t/2) <= N/count`, reducing rotation
resolution and thus the allowed input-noise margin. Boolean/CBS output scales
can differ from ordinary plaintext encoding.

## Optional circuit bootstrapping

`CircuitBootstrapParameters`, `CircuitBootstrapKey` and `CircuitBootstrapEvaluator`
add CBS without adding trace/SS material to ordinary server keys:

```text
external LWE -> gadget-scaled ManyLUT -> one BR under f_acc
             -> reverse-trace coefficient projections -> NLev_f_acc[m]
             -> scheme switch -> NTT NGSW_f_acc[m]
```

CBS retains the BR ring accumulator. It does not perform ordinary PBS's ring key
switch or LWE extraction, and does not require packing. The general ManyLUT
accumulator has no guaranteed zero message tail, so prefix expansion is not a
valid substitute for its coefficient projections.

The context supplies the BR basis. CBS parameters independently specify trace,
scheme-switch and output bases; the output parameters' noise distribution is not
used for generation. The output layer count is padded to a power of two only for
the internal ManyLUT. The returned NGSW has the original, unpadded output levels.
Matching dimensions alone do not establish basis or secret identity.

Given an existing context/client/server and application-selected `output_basis`,
`trace_parameters` and `scheme_switch_parameters`, setup and evaluation are:

```rust,ignore
let output_parameters = NlevParameters::try_with_basis(
    context.parameters().bootstrapping().ntru(), output_basis,
)?;
let parameters = CircuitBootstrapParameters::try_new(
    context.parameters(), output_parameters, trace_parameters, scheme_switch_parameters,
)?;
let key = context.generate_circuit_bootstrap_key(&client, &parameters, &mut rng)?;
let mut evaluator = context.circuit_bootstrap_evaluator(&server, &parameters, &key)?;
let control = evaluator.circuit_bootstrap(&input);
// Repeated calls reuse a caller-owned output:
evaluator.circuit_bootstrap_to(&input, &mut output);
```

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
cargo test -p primus_tfhe_ntru_ntt
cargo clippy -p primus_tfhe_ntru_ntt --all-targets -- -D warnings
cargo +nightly test -p primus_tfhe_ntru_ntt --features simd
cargo bench -p primus_tfhe_ntru_ntt --bench pbs
cargo bench -p primus_tfhe_ntru_ntt --bench circuit_bootstrap
```

CBS tests exercise LWE bits through NGSW and CMUX, padded output counts, basis and
capacity errors, and zero online allocations from the first evaluator call.
`circuit_bootstrap` measures reused output/workspace at N=1024/4096, input dimension
N/16, B=2^3/2^10 for BR/trace/SS, and output B=2^8 with two levels. It reports live
requested heap bytes for the additional CBS key and evaluator; these exclude
allocator overhead, borrowed tables, ordinary server material and caller output.
Key generation and accounting are outside timed closures. Add `-- --test` to
smoke-test fixtures; smoke tests establish neither timing nor decryptability.
SIMD uses existing dependency kernels, with no public ISA-selection API.
