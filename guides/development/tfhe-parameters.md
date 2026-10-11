# TFHE experimental parameter directory

These configurations are arithmetic examples and benchmark fixtures. **Security and decryption-failure probability are unassessed for every entry.** Successful construction, known-result checks and a complete noise/security analysis are different forms of evidence. Equal dimensions across backends do not establish equivalent security, precision or work.

The current sources below own the numerical choices. Operation contracts belong to the [bootstrapping guide](bootstrapping-contracts.md); execution commands belong to the [testing guide](testing.md). This directory does not prescribe ordinary-test sizes.

## Scope of paired parameter entries

Start from the concrete backend's `experimental` operation config. Examples fix `Word=u64`; the config supplies key domains and default messages, while the example supplies the function and its consumers.

| Backend | Config source | Complete workflows |
| --- | --- | --- |
| GLWE NTT | [experimental.rs](../../crates/primus_tfhe_glwe_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_ntt/README.md#operation-examples) |
| GLWE Fourier | [experimental.rs](../../crates/primus_tfhe_glwe_fourier/src/experimental.rs) | [Examples](../../crates/primus_tfhe_glwe_fourier/README.md#operation-examples) |
| NTRU NTT | [experimental.rs](../../crates/primus_tfhe_ntru_ntt/src/experimental.rs) | [Examples](../../crates/primus_tfhe_ntru_ntt/README.md#operation-examples) |
| NTRU Fourier | [experimental.rs](../../crates/primus_tfhe_ntru_fourier/src/experimental.rs) | [Examples](../../crates/primus_tfhe_ntru_fourier/README.md#operation-examples) |
| NTRU high-precision lookup | [experimental.rs](../../crates/primus_tfhe_ntru_lut/src/experimental.rs) | [NTT](../../crates/primus_tfhe_ntru_lut/examples/ntt_lookup.rs), [Fourier](../../crates/primus_tfhe_ntru_lut/examples/fourier_lookup.rs) |

Here t is the message modulus, not the number of padded inputs: a front-half input at t=32 has 16 values. Input and output message moduli may differ. PBS/ManyLUT outputs are Rounded, MVB outputs are Scaled, and CBS outputs use gadget scaling rather than an ordinary output codec.

| Config | Teaching workload and message domains |
| --- | --- |
| `CLASSIC_PBS_U64` | All four backends: Rounded 32→32, classic binary. Form z=2x+y, apply score=min(z,6), then price=2*score+[score>=4]. |
| `CLASSIC_PBS_U64` with `messages=PbsMessageConfig::new(4)` | Boolean access rule: admin OR (member AND NOT revoked), Rounded 4→4. |
| `SPARSE_PBS_U64` | Same scoring pipeline and 32→32 messages, fixed-weight binary sparse BR with three copies and 64 buckets. |
| `CLASSIC_MANY_LUT_U64` | Rounded 16→8, inputs 0..8, two lanes/stride two: grade=x/2 and flag=[x>=5], then code=2*grade+flag. |
| `CLASSIC_THRESHOLD_MVB_U64` | Rounded t_in=128, inputs 0..64; 17 threshold flags with Scaled t_out=2. |
| `CLASSIC_CBS_U64` | Rounded t_in=8, inputs 0..4; predicate F=[m>=2] selects an encrypted fee vector, then encrypted extras are added. Candidates use Scaled t_ring=8. |
| `SPARSE_CBS_U64` | GLWE only: the same CBS fee-vector workflow with fixed-weight sparse BR. |
| `CLASSIC_ONE_HOT_U64` | NTRU only: t_in=8/M=4; generate the three nonzero NGSW selectors and perform four-way CMux over encrypted records at t_ring=8, with C0 as default. |
| `NTT_CLASSIC_LOOKUP_U64` / `FOURIER_CLASSIC_LOOKUP_U64` | NTRU lookup: M=4, c=8 input chunks, d=5 coefficient chunks, o=8 output chunks. A piecewise fee maps 16-bit inputs to 16-bit outputs. |

Classic is the default for every entry except the two explicitly sparse configs. NTRU's fixed-weight one-hot config can also support sparse BR with corresponding material; this is a separate choice, not the default teaching or lookup benchmark path. See the [backend support guide](../../crates/primus_tfhe/README.md#selecting-blind-rotation).

The lookup examples use N=1024, 64 polynomials per output and three complete selection layers, retaining 4 MiB of public u64 coefficients. Input/output chunk counts are independent; the examples happen to make them equal. The N4096 random-function benchmark below has different geometry and decomposition.

## Moduli, geometry and secret domains

| Symbol | Representation and value | Current use |
| --- | --- | --- |
| Q50 | `BarrettModulus<u64>`, 1125899906826241 | u64 NTT examples and benchmarks |
| Q27 | `BarrettModulus<u32>`, 132120577 | u32 NTT dense PBS benchmark |
| Native32 / Native64 | `NativeModulus<u32/u64>`, implicit 2^32 / 2^64 | Fourier accumulator; also GLWE external modulus |
| q24 | `PowOf2Modulus<u32/u64>`, 2^24 | Independent NTRU external LWE and return KS |

These Barrett values fit `Q<2^(BITS-2)` and support the NTT lengths used here. Explicit powers of two use `PowOf2Modulus`; native moduli are implicit. Fourier TFHE uses Native accumulator moduli, including when NTRU's external LWE uses q24.

For the u64 configs, n denotes the small BR-control dimension in GLWE and the independent external dimension in NTRU. All GLWE entries have k=1. GLWE uses q=Q; NTRU uses independent q24 and Q secrets.

| Family / configs | n / N | Small or external secret | Ring secret |
| --- | --- | --- | --- |
| GLWE classic PBS / Boolean | 866 / 2048 | Uniform binary | Uniform binary |
| GLWE sparse PBS / ManyLUT / MVB / sparse CBS | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| GLWE classic CBS | 800 / 1024 | Uniform binary | Uniform ternary |
| NTRU classic PBS / Boolean | 866 / 2048 | Uniform binary | Sparse ternary |
| NTRU sparse PBS / ManyLUT / MVB | 728 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |
| NTRU classic CBS | 800 / 1024 | Uniform binary | Sparse ternary |
| NTRU one-hot / teaching lookup | 800 / 1024 | Fixed-weight binary, h=32 | Sparse ternary |

GLWE teaching configs use `BootstrapKeyswitch` (BR→KS), except MVB, which uses `KeyswitchBootstrap` (KS→BR). The external LWE dimension is n in BR→KS and kN in KS→BR. Both orders return under their external secret. NTRU returns by coefficient Q→q24 switching, phase extraction and LWE KS. See [domain and return contracts](bootstrapping-contracts.md#ciphertext-domains-and-return).

`SparseTernary` has probabilities (-1,0,+1)=(1/4,1/2,1/4), not an exact Hamming weight. NTRU samples f from this signed distribution and screens for backend invertibility/stability; it is not a `1+2F` distribution. The independent external fixed-weight secret and the conditioned ring secret have different roles. Sparse public-map conditioning is covered in the [numerical guide](bootstrapping-contracts.md#ternary-and-sparse-rotation).

## Noise by key role

All deviations are in **coefficient units under the role's own modulus**. Define α=2.046151696979124e−6 and β=2.845267479601915e−15. The following values belong to the u64 configs above; the random-LUT fixture retains NTRU's n800/h32 noise choices.

| Config family | Small/external LWE σ | Ring encryption / BR σ | KS rows σ |
| --- | --- | --- | --- |
| GLWE classic PBS / Boolean | αQ | max(βQ,6.4) | max(βQ,6.4) |
| GLWE classic CBS | αQ | 6.4 | 6.4 |
| GLWE fixed-weight entries | 3.2Q/16384 | 6.4 | 6.4 |
| NTRU classic PBS / CBS / one-hot / teaching lookup | αq24 ≈34.329 | 0.7 | 3.2 at q24 |
| NTRU n728/h32 entries | 3276.8 | 0.7 | 3.2 at q24 |

GLWE BR and KS noises are separately configurable; their equal values here are fixture choices. For KS→BR, fresh external LWE encryption uses the ring/BR noise, not the small-LWE or KS-row noise. CBS trace and scheme-switch rows inherit the ring encryption noise, with independently sampled keys and separately chosen decompositions. Public-key encryption adds further error sources; these sampler deviations are not the total noise of public or evaluated ciphertexts.

The default [discrete Gaussian sampler](../../crates/primus_distr/README.md) is centered and truncated, with inclusive magnitude bound `max(1,floor(12σ))`. Its σ is a sampler parameter, not a measured standard deviation of a returned ciphertext. Noise/security models must account for the actual sampler and accepted-key distributions; copying α or β does not transfer another implementation's claims.

## Decomposition by operation

Write a basis as `(log2 radix, levels; discarded bits)`. Q27/Q50 use `value_bits=bit_width(Q)`; q24 uses 24 and native uses the word width. Discarded bits are `value_bits-log_basis*levels`. A configured `level_count: None` selects `floor(value_bits/log_basis)` levels and can still discard low bits. See [decomposition precision](../../crates/primus_decompose/README.md).

| u64 configs | NTT BR | Fourier BR | NTT KS | Fourier KS |
| --- | --- | --- | --- | --- |
| GLWE classic PBS / Boolean | (23,1;27) | (23,1;41) | (3,5;35) | (3,5;49) |
| Other GLWE entries | (8,6;2) | (8,8;0) | (8,6;2) | (8,8;0) |
| NTRU entries, including teaching lookup | (8,6;2) | (8,8;0) | (3,8;0) at q24 | (3,8;0) at q24 |

CBS trace and scheme switch use the full base-256 internal basis: `(8,6;2)` at Q50 or `(8,8;0)` at Native64. Their output basis is separate:

| u64 CBS output | NTT | Fourier | Padded width W |
| --- | --- | --- | --- |
| GLWE | (8,2;34), smallest scalar 2^34 | (8,2;48), smallest scalar 2^48 | 2 |
| NTRU CBS / one-hot / teaching lookup | (8,3;26), smallest scalar 2^26 | (8,3;40), smallest scalar 2^40 | 4 |

For teaching one-hot and lookup, M=4/N=1024/W=4 gives guard radius `A=N/(2MW)=32`. The actual quantized phase must stay in `-A<=e<A` in W units; capacity alone does not establish this. Trace, scheme switching and gadget consumption need further error budgets. See [one-hot contracts](bootstrapping-contracts.md#one-hot-cbs).

## Current backend benchmarks

The crate-local benchmarks consume the operation configs but measure the following specific work. They are not timings of every step in a teaching example.

| Target | Configuration and timed request |
| --- | --- |
| `pbs` | Dense classic u32/u64, fixed-weight classic u64 and fixed-weight sparse u64; one PBS of `F(x)=(3x+1) mod 16` at Rounded 32→32. The fixed pair shares the sparse config's numerical choices and changes only BR method. |
| `many_lut` | `CLASSIC_MANY_LUT_U64`: one two-output PBS returning grade and flag; no subsequent code-combining addition. |
| `mvb` | `CLASSIC_THRESHOLD_MVB_U64`: one factorized request returning all 17 threshold flags. |
| `cbs` | `CLASSIC_CBS_U64`: predicate [m>=2] and CMux over two nonconstant encrypted candidates at t_ring=8; no extra ring addition. |
| `one_hot` | NTRU `CLASSIC_ONE_HOT_U64`: three nonzero NGSWs and four-way CMux at t_ring=8. |

Fourier benches select RustFFT, TFHE-FFT or both, using the same numerical config but engine-compatible material. Sources and commands: [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/README.md#benchmarks), [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/README.md#benchmarks), [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/README.md#benchmarks), [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/README.md#benchmarks).

Only the PBS benchmarks add u32 fixtures; other current operation benchmarks are u64. The local `dense_u32()` functions use n866/N2048, uniform-binary external/small secrets and Rounded 32→32. GLWE has k=1, a uniform-binary ring secret and BR→KS; NTRU has a sparse-ternary ring secret and q24 return.

| u32 PBS | Accumulator Q | BR basis | KS basis | Fresh input σ | BR / KS row σ |
| --- | --- | --- | --- | --- | --- |
| [GLWE NTT](../../crates/primus_tfhe_glwe_ntt/benches/pbs.rs) | Q27 | (5,5;2) | (2,13;1) | αQ27 | 6.4 / 6.4 |
| [GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/benches/pbs.rs) | Native32 | (8,3;8) | (2,13;6) | α·2^32 | 6.4 / 6.4 |
| [NTRU NTT](../../crates/primus_tfhe_ntru_ntt/benches/pbs.rs) | Q27 | (2,13;1) | (3,8;0) at q24 | αq24 | 0.7 / 3.2 |
| [NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/benches/pbs.rs) | Native32 | (2,16;0) | (3,8;0) at q24 | αq24 | 0.7 / 3.2 |

These are explicit word-specific choices, not casts of the u64 config. Dense versus fixed-weight timings change geometry, secrets and noise, and for GLWE also decomposition. Only the fixed classic/sparse pair isolates the BR method within a backend. Historical [paper comparisons](../performance/sparse-paper-comparison.md) have their own profiles and evidence limits.

## Random high-precision LUT benchmark

The [creation](../../crates/primus_tfhe_ntru_lut/benches/lookup_create.rs) and [evaluation](../../crates/primus_tfhe_ntru_lut/benches/lookup_evaluate.rs) benchmarks share a fully enumerated seeded random u16 function, with u64 coefficients, M=16, d=3, N=4096, c∈{4,5,6} and independently fixed o=4. Inputs are 16/20/24 bits; outputs stay 16 bits. Repeated polynomials are retained and every output executes the complete selection tree. Public coefficient storage is 2/32/512 MiB, excluding the clear function, keys and workspace.

| Role | NTT | Fourier |
| --- | --- | --- |
| External LWE | n800, fixed-weight binary h32, q24 | Same |
| Fresh input σ | αq24 ≈34.329 | Same |
| Accumulator | Q50, N4096, sparse ternary | Native64, N4096, sparse ternary |
| BR / trace / scheme-switch | σ=0.7, (6,8;2) | σ=0.7, (6,10;4) |
| CBS output | (6,4;26) | (6,4;40) |
| Return KS | q24, σ=3.2, (3,8;0) | Same |
| Messages and BR | Rounded t=32, digits 0..16, classic | Same |

The internal base is 64, whereas teaching lookup uses 256. The output retains 24 bits through four base-64 levels instead of three base-256 levels. NTT and Fourier still differ in internal level count, trace and rounding; the same dimensions do not imply equal noise or security. Creation measures allocation, enumeration, encoding, full storage and drop. Evaluation measures one complete request with keys, LUT and workspace already prepared. See [benchmark commands](testing.md#high-precision-lut-benchmarks).

Here L=W=4 and `A=N/(2MW)=32`. Encoding at q24 is exact for t=32; the fresh-noise support is bounded by `floor(12αq24)=411`. With h=32, coordinate quantization contributes at most `(h+1)/2` in W units, so the pre-BR bound is

```text
|e| <= (h+1)/2 + 2N*411/(q24*W)
     = 16.5 + 411/8192 < 32.
```

This establishes the [input selection guard](bootstrapping-contracts.md#one-hot-cbs) under these sampler/secret assumptions, not the BR/CBS, product-chain or return budget. Returned chunks have decoding half spacing 2^18 at q24. Each chunk's complete correlated error must fit that spacing; finite successful decryptions do not establish a failure probability.

## Evidence and changes to a workload

| Evidence | What it establishes |
| --- | --- |
| Config and constructor checks | Representable parameters, supported samplers, encoding/layout and applicable table/binding conditions; not actual secret identity or complete noise margins |
| Known-result checks in examples and benches | Sampled functional behavior when those workloads are run; not a coverage claim for every word, engine, secret or operation |
| Input guard above | A deterministic pre-BR bound for the named random-LUT fixture; not a complete failure bound |
| Security / decryption-failure assessment | Neither has been established for these entries |

Changing message moduli, lane count, function, candidate range or chunk partition changes the error requirements even when existing keys remain compatible. Scaled MVB output is not automatically a valid Rounded PBS input. CBS predicates must be bit-valued for CMux, and arbitrary MVB factors can amplify noise far more than the threshold workload. Check the [operation's numerical contracts](bootstrapping-contracts.md) and [material pairing](composition.md#bind-material-before-evaluation).

A future security/DFR claim must specify its model and version, exact secret/sampler and conditioning assumptions, applicable functions, and complete error propagation including correlations. Finite historical diagnostics are not current validation; current checks and commands are described in the [testing guide](testing.md).
