# primus_ntru

English | [简体中文](README.zh_CN.md)

Scalar secret-key NTRU encryption and evaluation over `Z_q[X]/(X^N + 1)`.
NTT uses an explicit field modulus; Fourier uses the native wrapping modulus
`2^T::BITS`. These representations retain separate numerical contracts.
This is an experimental workspace crate, without stable APIs or recommended
security parameters.

## Ciphertext semantics

Let `f` be the invertible secret, `mu` an encoded message and `g_l` a gadget scalar.
The following phases omit any application-specific plaintext codec:

| Type | Phase of coefficient row `c_l` |
| --- | --- |
| NTRU | `f*c = mu + e` |
| NLev of `m` | `f*c_l = g_l*m + e_l` |
| NGSW of `m` | `f*c_l = g_l*f*m + e_l` |

NLev and NGSW have the same number of stored rows but different mathematical
roles. `NLev[1]` can lift a coefficient polynomial to encrypted NTRU through
an external product. `NGSW[1]` preserves an already encrypted NTRU message.
There is no general trivial NTRU encryption formed by copying a message to `c`.

## Keys and recommended workflow

Use `NttNtruSecretKey::generate_pair` or `FourierNtruSecretKey::generate_pair`
to retain both the signed coefficient secret and its transform representation.
The coefficient secret generates evaluation keys; the transformed key and
its cached inverse support encryption and phase extraction.

NTT generation rejects keys with a zero evaluation. Fourier generation checks
native-ring invertibility (odd coefficient sum) and the stability of the complex
inverse. These conditions differ. Bounded rejection sampling can fail, and its
attempt count and inversion routines are not promised constant time.
General NTRU supports nonbinary secrets. The NTRU TFHE layer separately validates
the binary, zero-padded control-secret requirement for blind rotation.

Secret keys and private encryption/generation/decryption workspaces erase owned
buffers on drop. Explicit workspace zeroization preserves reusable storage;
explicit secret-key zeroization destroys the key. The built-in FFT backends also
erase scratch on drop, and `FftEngine::zeroize_scratch()` supports a phase boundary
for long-lived engines. Caller-owned plaintext and phase outputs retain their own
lifetimes.

The [automorphism example](examples/automorphism.rs) shows paired key generation,
evaluation-key setup and reusable NTT evaluation under the original secret:

```sh
cargo run -p primus_ntru --example automorphism
```

## Operations and representations

| Operation | Inputs and outputs |
| --- | --- |
| `encrypt_to`, `encrypt_centered_to` | Plaintext coefficients to transformed NTRU, with codec scaling |
| `encrypt_encoded_to`, `encrypt_zeros_to` | Encoded ring coefficients or zero to transformed NTRU |
| `phase_to`, `decrypt_to` | Transformed NTRU to coefficient phase or decoded plaintext |
| `encrypt_nlev_to`, `encrypt_ngsw_to` | Encoded polynomial to transformed gadget rows, without plaintext codec scaling |
| `encrypt_nlev_constant_to` | Constant ring element to transformed NLev |
| `encrypt_ngsw_signed_constant_batch_to` | Signed constants to contiguous transformed NGSWs |
| `NttNtruKeySwitchingKey`, `FourierNtruKeySwitchingKey` | Coefficient NTRU under an input secret to coefficient NTRU under the output secret |
| `NttNtruAutomorphismKey::apply_to`, `FourierNtruAutomorphismKey::apply_to` | Coefficient NTRU to coefficient NTRU under the same secret |
| `apply_ntt_to`, `apply_fourier_to` | Transformed NTRU to the corresponding transformed output under the same secret |

Decryption returns coefficient polynomials with the ciphertext coefficient type
`T`; applications handle any output type conversion.

Evaluation keys own their decomposition basis. Reusable evaluation contexts
contain only work buffers. Owning public operations validate all supplied sizes,
moduli and transform/workspace lengths before output writes; the corresponding
low-level lattice kernels rely on those contracts. Actual secret-key identity,
canonical input residues and sufficient noise budgets remain caller obligations.

Automorphism uses odd `d` in `[1, 2N)`. It stores `NLev_f[f(X^d)]` to switch
the permuted secret back to `f`. No inverse of `f(X^d)` is generated. Signed
secrets are encoded before modular permutation. Transformed inputs still need
coefficient recovery for decomposition; transformed outputs avoid the final
inverse transform. NLev rows can each use scalar automorphism, but applying
it row-wise to NGSW does **not** preserve the NGSW message/key relation.

Fourier values, evaluation keys and maps are bound to the exact FFT table
instance used during generation, including its backend-specific order. Use
that table for every subsequent operation. Fourier output paths omit an output
torus rounding step, so they need not be bit-identical to a coefficient
roundtrip. The caller must budget floating-point, decomposition and encryption
errors. Examples and benchmarks are functional workloads, not security estimates.

Sample extraction, NLev/NGSW external products and CMUX live in
[`primus_lattice`](../primus_lattice/README.md). PBS, ManyLUT and optional CBS live in
[`primus_tfhe_ntru_ntt`](../primus_tfhe_ntru_ntt) and
[`primus_tfhe_ntru_fourier`](../primus_tfhe_ntru_fourier); their message/carry
examples demonstrate sharing a blind rotation across multiple outputs.

## Trace, projection and expansion

`NttNtruTraceKey` and `FourierNtruTraceKey` bind `log2(N)` automorphism keys.
All endpoints use coefficient ciphertexts under the original secret; the ring
length stays N. Ordinary partial trace with r retained coefficients targets
`(N/r) * sum_j M[j*N/r] X^(j*N/r)`. Reverse trace preserves that message scale.
NTT normalizes with inverse powers of two modulo q. Fourier instead divides
unsigned coefficient representatives, rounding down before each reverse step;
the resulting phase rounding error is multiplied by f. These numerical paths
have different error distributions and are not interchangeable.

`project_coefficient(s)_to` moves each requested coefficient to the constant
position, then applies reverse trace. Indices may repeat or arrive out of order.
`expand_coefficients_to` expands the whole message in natural order using a tree.
`expand_partial_coefficients_to(input, count, ...)` requires a power-of-two
count <= N and a target message supported on the first count positions. It uses
count-1 automorphisms and caller output as tree storage. A general input instead
produces residue-class polynomials, not constant messages. Ciphertext/noise tails
need not vanish, and non-target output positions can still contain noise.

## Same-secret scheme switching

`NttNtruSchemeSwitchKey` / `FourierNtruSchemeSwitchKey` convert coefficient
`NLev_f[m]` to transformed `NGSW_f[m]`. Their `key_basis` decomposes each input
polynomial; their independent `output_basis` specifies the input/output scalars
and level count. Reuse the existing external-product context. Inputs must already
use that output basis; matching lengths alone cannot establish it.

The stored evaluation key is `NGSW_f[f]`. It is generated by encrypting f,
without explicitly forming a signed polynomial square. Input errors are
multiplied by f, decomposition errors by f², and evaluation-key/FFT errors also
contribute. Publishing this secret-dependent key needs a justified
key-dependent-message/circular-security assumption and suitable parameters.
The algebra and functional tests provide neither a security proof nor a CBS
parameter recommendation. The output can control CMUX when m is a bit.

## Tests and benchmarks

```sh
cargo test -p primus_ntru
cargo clippy -p primus_ntru --all-targets -- -D warnings
cargo +nightly test -p primus_ntru --features simd
cargo bench -p primus_ntru --bench encryption
cargo bench -p primus_ntru --bench primitives -- 'ntt/n4096/logb3'
cargo bench -p primus_ntru --bench constant_gadget
```

`encryption` measures ordinary encryption and undecoded phase extraction.
`primitives` measures key switching, automorphism, trace/reverse trace, three
coefficient projections, expansion of an eight-coefficient prefix and scheme
switching (output B=2^8, L=3) at
`N = 1024/4096/8192`, with `B = 2^3/2^10` and the maximum supported level count. Both use `u64`,
sparse ternary secrets and sigma 3.2; NTT uses `q = 1_125_899_906_826_241`, and
Fourier covers both FFT backends. `constant_gadget` retains constant NLev and
eight-control NGSW generation. Setup, tables, key generation and allocations
stay outside timed closures. Add `-- --test` for fixture smoke checks; those
checks do not measure performance or establish decryptability.

NTT scalar products use the existing CPU dispatch and optional dependency SIMD
support. No ISA choice is added to the public NTRU API. Compare timings only
within matched workloads; these backends do not share equal-security parameters.

## License

Licensed under either [Apache-2.0](../../LICENSE-APACHE-2.0) or
[MIT](../../LICENSE-MIT), at your option.
