# primus_tfhe_ntru_ntt

English | [简体中文](README.zh_CN.md)

NTT backend for NTRU-based TFHE. Uses an explicit field modulus and the context's NTT representation.
APIs and parameters are experimental; examples and benchmarks are functional
workloads, not security parameter recommendations.

See the [shared capability and encoding guide](../primus_tfhe/README.md) and
[NTRU family/key domains](../primus_tfhe_ntru/README.md). Both NTRU backends support
PBS, ManyLUT and CBS; NTRU Boolean adapters are not implemented.

## Ordinary PBS and ManyLUT

`TfheContext` binds parameters and a transform table. Generate paired client/server
keys with `context.try_generate_keys`, obtain an encryptor/evaluator/decryptor,
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

## Optional circuit bootstrapping

`CircuitBootstrapParameters`, `CircuitBootstrapKey` and `CircuitBootstrapEvaluator`
provide optional CBS material. Use `context.try_generate_circuit_bootstrap_key`
and `context.circuit_bootstrap_evaluator`; ordinary server keys remain independent.
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
