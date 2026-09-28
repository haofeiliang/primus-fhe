# TFHE arithmetic parameter matrix

These profiles are reproducible functional and performance fixtures. They have no security or failure-probability assessment. Two fixed seeds establish observations, not a probabilistic guarantee. Shared geometry does not make NTT, Fourier, GLWE and NTRU equally secure or their costs directly comparable.

Validation and benchmark constructors live in [test-support parameters](../../test-support/tfhe/src/parameters/mod.rs), split into [GLWE](../../test-support/tfhe/src/parameters/glwe.rs) and [NTRU](../../test-support/tfhe/src/parameters/ntru.rs). They use the existing family parameter types; no backend abstraction or production preset registry is added. Ordinary integration tests keep small parameters. The [validation executable](../../test-support/tfhe/examples/validate_parameters.rs) is an explicitly invoked numerical diagnostic.

## Moduli, geometry and secret domains

| Symbol | Representation and value | Use |
| --- | --- | --- |
| Q27 | `BarrettModulus<u32>`, 132120577 | NTT ordinary PBS, sparse PBS and MVB |
| Q30 | `BarrettModulus<u32>`, 998244353 | NTT CBS, one-hot and high-precision lookup |
| Q50 | `BarrettModulus<u64>`, 1125899906826241 | All u64 NTT profiles |
| Native32 / Native64 | `NativeModulus<u32/u64>`, implicit 2^32 / 2^64 | Fourier accumulator; also GLWE external modulus |
| q24 | `PowOf2Modulus<u32/u64>`, 2^24 | Independent NTRU external LWE and return key |

All three NTT primes satisfy Q mod 4096 = 1 and the existing NTT table constructors accept N=1024/2048. Each fits the Barrett bound Q<2^(BITS−2). `NativeModulus` never constructs an unrepresentable `1 << BITS`. Explicit powers of two use `PowOf2Modulus`; all NTRU examples use independent external q=2^24.

All geometries below run with u32 and u64. Fourier validation includes both RustFFT and TFHE-FFT. GLWE always has k=1 and validates both `BootstrapKeyswitch` and `KeyswitchBootstrap`. Here n is the small LWE dimension: in `KeyswitchBootstrap`, the external client domain has kN coefficients, not n. GLWE uses q=Q. NTRU has independent external LWE and ring secrets and returns Q→q24→LWE KS.

| Profile | n / N | t (includes padding) | External/small secret | Ring secret |
| --- | --- | --- | --- | --- |
| GLWE dense Boolean PBS | 800 / 1024 | 4 | uniform binary | uniform binary |
| GLWE dense 2+2 bit PBS | 866 / 2048 | 32 | uniform binary | uniform binary |
| GLWE circuit / ternary PBS | 800 / 1024 | 4 | uniform binary or uniform ternary | uniform ternary |
| GLWE fixed-weight / sparse | 728 / 1024 | 8 for single-output PBS; 16 for ManyLUT; 4 for CBS | fixed-weight binary, h=32 | sparse ternary |
| GLWE MVB | 728 / 1024 | 128 | fixed-weight binary, h=32 | sparse ternary |
| NTRU dense Boolean / 2+2 bit PBS | 800 / 1024; 866 / 2048 | 4; 32 | uniform binary or uniform ternary | sparse ternary |
| NTRU fixed-weight / sparse / MVB | 728 / 1024 | 16 for PBS; 128 for MVB | fixed-weight binary, h=32 | sparse ternary |
| NTRU ordinary CBS | 800 / 1024 | 4 | uniform binary or uniform ternary | sparse ternary |
| NTRU one-hot / lookup | 800 / 1024 | 8, radix M=4 | uniform binary or uniform ternary | sparse ternary |

`SparseTernary` is the existing distribution with probabilities (−1,0,+1)=(1/4,1/2,1/4), not an exact-weight ring key. NTRU still screens f for the backend's invertibility requirements. The 728/h32 geometry is retained specifically to exercise fixed-weight/sparse algorithms and narrow MVB input cells. Sparse keys use copy_count=3 and bucket_count=64. Their map-generation retry does not replace the client secret or search for successful numerical seeds.

## Noise by key role

All constructor arguments are **coefficient-domain standard deviations under the role's own modulus**. Let α=2.046151696979124e−6 and β=2.845267479601915e−15, the constants already used by the dense GLWE PBS fixtures. Keeping these constants does not import a security claim from another parameter set.

| Profile | Small/external LWE σ | Ring encryption / BR σ | Return KS σ | Trace / scheme-switch σ |
| --- | --- | --- | --- | --- |
| GLWE dense PBS | αQ | max(βQ,6.4) | max(βQ,6.4), the shared GLWE KS key noise | not used |
| GLWE circuit / ternary | αQ | 6.4 | 6.4, the shared GLWE KS key noise | 6.4 / 6.4 |
| GLWE fixed-weight / sparse / MVB | 3.2Q/16384 | 6.4 | 6.4, the shared GLWE KS key noise | 6.4 / 6.4 when CBS is requested |
| NTRU dense / circuit / lookup | α·2^24 ≈34.328 | 0.7 | 3.2 at q24 | 0.7 / 0.7 when CBS is requested |
| NTRU fixed-weight / sparse / MVB | 3.2·2^24/16384 =3276.8 | 0.7 | 3.2 at q24 | not used |

Both GLWE orders use the same GLWE KS key and accumulator-derived noise; order changes where it is applied. The small-LWE σ is the input-encryption noise for PBS→KS; KS→PBS external inputs use the accumulator-derived LWE parameters. See the [domain and return-path guide](tfhe-parameters-and-boundaries.md). The fixed-weight NTRU diagnostic retains the existing MVB normalized input noise after changing the external modulus to q24. NTRU retains its previous ring/CBS σ=0.7; it does not reuse that value for independent LWE and return-key noise. The NTRU ring budget is small because CBS and NGSW products amplify errors through f and f². Increasing dimensions or noise calls for revalidation of the entire chain, not just a key constructor.

## Decomposition by operation

Notation is `(log2 radix, level count; discarded bits)`. With explicit non-power-of-two Q, `value_bits=bit_width(Q)`; native uses BITS. Discarded bits are `value_bits − log_basis × levels`. `None` in a config means `floor(value_bits/log_basis)` levels; it does **not** generally mean an exact decomposition.

### Dense GLWE PBS

| Word / backend | BR | KS |
| --- | --- | --- |
| u32 NTT Q27 | (5,5;2) | (2,13;1) |
| u64 NTT Q50 | (23,1;27) | (3,5;35) |
| u32 Fourier | (8,3;8) | (2,13;6) |
| u64 Fourier | (23,1;41) | (3,5;49) |

These are the unchanged numerical profiles extracted from the two existing GLWE PBS benchmarks. Both benchmarks now call these constructors directly. Other workload migrations use the explicit profiles below.

### GLWE circuit, ternary and fixed-weight diagnostics

BR and KS use full-length base 2^2 for u32 and base 2^8 for u64. Trace and scheme-switch use the same respective full bases, with independent keys/noise. Q27 remains appropriate for fixed-weight PBS/MVB; **u32 CBS uses Q30**.

| Word / modulus | Full internal basis | CBS output basis | Smallest CBS scalar |
| --- | --- | --- | --- |
| u32 Q27, PBS/MVB only | (2,13;1) | — | — |
| u32 Q30, CBS | (2,15;0) | (3,3;21) | 2^21 |
| u32 native | (2,16;0) | (3,3;23) | 2^23 |
| u64 Q50 | (8,6;2) | (8,2;34) | 2^34 |
| u64 native | (8,8;0) | (8,2;48) | 2^48 |

CBS output widths are padded to W=4 for u32 and W=2 for u64. Large-parameter validation checks every GGSW row and level, not just a decoded CMux result.

### NTRU PBS, CBS and lookup

BR, trace and scheme-switch use full-length base 2^2 for u32 and base 2^8 for u64. Return KS is always at q24 with `(3,8;0)`. Ordinary PBS/sparse/MVB use Q27 for u32 NTT; **CBS/one-hot/lookup use Q30**.

| Word / accumulator modulus | BR / trace / scheme-switch basis | CBS / one-hot output | Smallest output scalar |
| --- | --- | --- | --- |
| u32 Q27, PBS/MVB only | (2,13;1) | — | — |
| u32 Q30 | (2,15;0) | (3,4;18) | 2^18 |
| u32 native | (2,16;0) | (3,4;20) | 2^20 |
| u64 Q50 | (8,6;2) | (8,3;26) | 2^26 |
| u64 native | (8,8;0) | (8,3;40) | 2^40 |

The standalone parameter diagnostic uses M=4, c=7 input chunks, d=5 coefficient chunks, o=3 output chunks. Thus M^d=N=1024 and the 14-bit input selects among 16 public polynomials per output. This exercises public lifting, a further encrypted CMux layer, five aggregate rotations, and Q→q24 return. Output width is independent of input width. The evaluator has no new algorithmic restrictions; these are the dimensions that were numerically validated.

For one-hot, L=4 (u32) or 3 (u64), so W=4 and A=N/(2MW)=32. With R_W the existing coefficient quantizer, validation computes

`e = centered(R_W(b) − Σ R_W(a_i)s_i − m·N/M) / W`

and checks the actual left-closed guard `−A ≤ e < A`. This includes rounding of every mask coefficient; it is not a modulus switch of the already decrypted phase. Fourier uses the existing coefficient-halving reverse trace and includes its rounding/FFT error in the observed output residuals.

The 27-bit u32 candidate did not provide a sufficient joint CBS/product budget at n=800. Q30 alone with a coarse three-level output also failed. Small internal digits and four output levels balance selector error against product decomposition error. The selected profiles retain the existing NTRU secret distribution, dimensions and ring noise, without seed selection or relaxed acceptance thresholds. Intermediate trials with larger ring noise are not supported presets.

## Validation and observations

Run the full matrix explicitly:

```sh
cargo run --release -p primus_tfhe_test_support --example validate_parameters
cargo +nightly run --release -p primus_tfhe_test_support --example validate_parameters --features simd
```

A substring selects before any keys are generated, for example `-- ntru/ntt/u32`, `-- glwe/rustfft/u64`, or `-- lut/compile`. Unknown filters fail. This entry is not a Criterion timing target and is not run by ordinary `nextest --lib --tests`.

The fixed seeds are 42 and 4242. Validation covers:

- PBS/ManyLUT at zero, interior and final messages, then zero again to reuse workspace; Boolean truth tables and an output-reconsumption chain reuse the existing shared oracle.
- Uniform binary/ternary and fixed-weight classic/sparse keys, both GLWE orders, both word widths and both FFT engines.
- Ordinary CBS at t=4, every gadget coefficient/level/row, and nonconstant CMux candidates; NTRU one-hot at t=8 for every selector, including the default zero selector.
- MVB thresholds with 64 inputs and 17 outputs, including a threshold transition and the endpoint. The returned flags use Scaled encoding under the external modulus.
- Complete lookup at 0, 1, 1023, 1024, 0x1234, 16383, 0; every chunk also passes the quantized-phase guard. The public function is nonlinear and checks all three output chunks.
- Public LUT constructor geometry at N=1024/2048, u32/u64, native/q24/Barrett, including odd t=255 and non-power-of-two output counts. Existing small tests retain the polynomial-content oracles.

The acceptance thresholds were fixed before parameter experiments. Decoded outputs require circular phase error < q/(4t), half the decoding radius; raw gadget coefficients require error < scalar/8; lookup outputs require error < q24/32=524288. Reports show the largest fraction of the corresponding budget, not a noise standard deviation or a failure-rate estimate. CMux coefficients are checked individually. Samples with errors are rejected rather than counted as successful because another seed works.

Validated on 2026-09-28, AMD Ryzen 9 9955HX3D, x86_64 Linux, repository `target-cpu=native`: stable rustc 1.98.0 (88d9e12ae), and nightly 1.100.0 (bff8e12ff) with SIMD. Both configurations passed the entire supported matrix. After restoring the fixed-weight NTRU profile's original normalized input noise, all NTRU profiles were rerun in both configurations. The table is the maximum over both seeds, applicable secrets/orders and the two configurations.

| Family / backend / word | Max decoded budget fraction | Max gadget budget fraction | Max lookup error at q24 |
| --- | ---: | ---: | ---: |
| GLWE NTT u32 | 0.633509 | 0.801792 | — |
| GLWE NTT u64 | 0.100912 | 0.004819 | — |
| GLWE RustFFT u32 | 0.134934 | 0.215996 | — |
| GLWE RustFFT u64 | 0.078182 | 0.002620 | — |
| GLWE TFHE-FFT u32 | 0.120102 | 0.215996 | — |
| GLWE TFHE-FFT u64 | 0.079641 | 0.002767 | — |
| NTRU NTT u32 | 0.020416 | 0.717468 | 304964 |
| NTRU NTT u64 | 0.013039 | 0.105438 | 1720 |
| NTRU RustFFT u32 | 0.016991 | 0.177925 | 128544 |
| NTRU RustFFT u64 | 0.014793 | 0.000301 | 1600 |
| NTRU TFHE-FFT u32 | 0.016991 | 0.177925 | 128544 |
| NTRU TFHE-FFT u64 | 0.014793 | 0.000290 | 1595 |

These are maxima of finite observations under explicitly selected bounds. They do not establish worst-case noise, a target decryption-failure probability, or security. The changed GLWE PBS benchmark constructors also passed Criterion smoke; the corrected NTRU basic examples ran successfully. Existing default/all-feature numerical tests remained at 380/393, with no large profile added to ordinary CI execution. No latency or memory improvement is claimed by this parameter change.

## Existing asset inventory and migration

This matrix covers all 20 declared TFHE benchmark targets and 22 top-level product examples. The examples spell out these profiles locally with `TfheConfig` and `CircuitBootstrapConfig`. The benchmark table below distinguishes already migrated targets from destinations for the remaining benchmark cleanup.

| Benchmark target | Current geometry/width | Validated destination |
| --- | --- | --- |
| [primus_tfhe/lookup_table](../../crates/primus_tfhe/benches/lookup_table.rs) | u32, N1024, native/Q27 | Public compilation; add u64/q24 during benchmark cleanup |
| [primus_tfhe_glwe_ntt/pbs](../../crates/primus_tfhe_glwe_ntt/benches/pbs.rs) | u32/u64, 800/1024 and 866/2048 | Dense GLWE PBS; **shared constructor wired** |
| [primus_tfhe_glwe_ntt/ternary_pbs](../../crates/primus_tfhe_glwe_ntt/benches/ternary_pbs.rs) | u32, 728/1024, binary/ternary | Circuit/ternary profile, 800/1024, both widths |
| [primus_tfhe_glwe_ntt/circuit_bootstrap](../../crates/primus_tfhe_glwe_ntt/benches/circuit_bootstrap.rs) | u64, 728/h32/1024, classic/sparse | GLWE circuit + fixed-weight CBS, both widths |
| [primus_tfhe_glwe_ntt/sparse_pbs](../../crates/primus_tfhe_glwe_ntt/benches/sparse_pbs.rs) | u32, 728/h32/1024 | GLWE fixed-weight PBS, both widths |
| [primus_tfhe_glwe_ntt/mvb](../../crates/primus_tfhe_glwe_ntt/benches/mvb.rs) | u32, 728/h32/1024 | GLWE MVB, both widths |
| [primus_tfhe_glwe_fourier/pbs](../../crates/primus_tfhe_glwe_fourier/benches/pbs.rs) | u32/u64, 800/1024 and 866/2048 | Dense GLWE PBS; **shared constructor wired** |
| [primus_tfhe_glwe_fourier/ternary_pbs](../../crates/primus_tfhe_glwe_fourier/benches/ternary_pbs.rs) | u32, 728/1024, binary/ternary | Circuit/ternary profile, 800/1024, both widths |
| [primus_tfhe_glwe_fourier/circuit_bootstrap](../../crates/primus_tfhe_glwe_fourier/benches/circuit_bootstrap.rs) | u64, 728/h32/1024, classic/sparse | GLWE circuit + fixed-weight CBS, both widths |
| [primus_tfhe_glwe_fourier/sparse_pbs](../../crates/primus_tfhe_glwe_fourier/benches/sparse_pbs.rs) | u32, 728/h32/1024 | GLWE fixed-weight PBS, both widths |
| [primus_tfhe_glwe_fourier/mvb](../../crates/primus_tfhe_glwe_fourier/benches/mvb.rs) | u32/u64, 728/h32/1024 | GLWE MVB, both widths |
| [primus_tfhe_ntru_ntt/pbs](../../crates/primus_tfhe_ntru_ntt/benches/pbs.rs) | u32/u64, 800/1024 and 866/2048 | NTRU dense PBS, independent q24 return |
| [primus_tfhe_ntru_ntt/circuit_bootstrap](../../crates/primus_tfhe_ntru_ntt/benches/circuit_bootstrap.rs) | u32/u64, 728/1024 | NTRU circuit, 800/1024 |
| [primus_tfhe_ntru_ntt/sparse_pbs](../../crates/primus_tfhe_ntru_ntt/benches/sparse_pbs.rs) | u32/u64, 728/1024, h32 | NTRU fixed-weight PBS, h32 |
| [primus_tfhe_ntru_ntt/mvb](../../crates/primus_tfhe_ntru_ntt/benches/mvb.rs) | u32, 728/h32/1024 | NTRU MVB, both widths |
| [primus_tfhe_ntru_fourier/pbs](../../crates/primus_tfhe_ntru_fourier/benches/pbs.rs) | u32/u64, 800/1024 and 866/2048 | NTRU dense PBS, independent q24 return |
| [primus_tfhe_ntru_fourier/circuit_bootstrap](../../crates/primus_tfhe_ntru_fourier/benches/circuit_bootstrap.rs) | u32/u64, 728/1024 | NTRU circuit, 800/1024 |
| [primus_tfhe_ntru_fourier/sparse_pbs](../../crates/primus_tfhe_ntru_fourier/benches/sparse_pbs.rs) | u32/u64, 728/1024, h33 | NTRU fixed-weight PBS, h32 |
| [primus_tfhe_ntru_fourier/mvb](../../crates/primus_tfhe_ntru_fourier/benches/mvb.rs) | u32/u64, 728/h33/1024 | NTRU MVB, both widths |
| [primus_tfhe_ntru_lut/pipeline](../../crates/primus_tfhe_ntru_lut/benches/pipeline.rs) | u64, 64/1024, c7/d5/o3 | NTRU lookup, 800/1024, both widths; retime after migration |

## Teaching examples

Each example has a concrete `Word = u32` and a concrete `Table` import. To run u64, change `Word` to u64 and, for NTT, import `U64NttTable as Table`. Fourier defaults to `RustFftTable`; change its import to `TfheFftTable as Table` for the other FFT implementation. Each file contains its own explicit `parameters()` function, with word-specific modulus, decomposition and coefficient-noise choices; CBS adds a local `circuit_config()`. GLWE's `ORDER` constant selects one order per run. These choices keep the main function readable without generic or CLI matrix dispatch.

Examples do not import the test-support factories. Their local configuration functions make every numerical choice inspectable without leaving the file. Keys, codecs, encrypted inputs, evaluators, outputs and client/server handoffs remain in each example's main function. Each workload makes two requests with reused buffers. No example imports code from `benches/` or `tests/`; the old Fourier CBS support is now owned by [its sole benchmark consumer](../../crates/primus_tfhe_glwe_fourier/benches/support/circuit_bootstrap.rs).

| Workflow | Geometry and encoding | Complete examples |
| --- | --- | --- |
| Basic PBS | n=866/N=2048/t32; `x % 4`, padded input 0..16 and default output codec | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_basic.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_basic.rs) |
| CBS → CMux | n=800/N=1024/t4; client encrypts the two ring candidates, server derives the gadget control | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_circuit_bootstrap.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_circuit_bootstrap.rs) |
| MVB thresholds | n=728/h32/N=1024/t128; 64 inputs, 17 outputs with Scaled t_out=2. NTRU compiles at Q and decodes at q24 with separate codecs | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_mvb_thresholds.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_mvb_thresholds.rs) |
| Sparse / classic ManyLUT | n=728/h32/N=1024/t16; three Rounded t_out=8 outputs. `SPARSE=true` selects three copies/64 buckets; false uses classic keys. NTRU has separate Q/q24 codecs | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_sparse.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_sparse.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_sparse.rs) |
| Sparse CBS → CMux | n=728/h32/N=1024/t4; explicit sparse key generation with CBS material | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_sparse_circuit_bootstrap.rs) |
| One-hot CBS → CMux | n=800/N=1024/t8; four NGSWs for delta_r=[m=r], select public r=2 using a semantic ciphertext iterator | NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_one_hot.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_one_hot.rs) |
| High-precision lookup | n=800/N=1024/t8; c8/d5/o8, two-bit chunks, `(x*x+3*x+7) mod 65536`; 16-bit input/output, all coefficient slots filled and 64 polynomials per output | [NTT](../../crates/primus_tfhe_ntru_lut/examples/ntt_lookup.rs) / [Fourier](../../crates/primus_tfhe_ntru_lut/examples/fourier_lookup.rs) |

All examples are arithmetic demonstrations, not assessed security presets. NTRU consistently uses independent LWE q24 and a separate ring Q; its ordinary return path and MVB scaled-output distinction are visible in the code. The explicit local configurations mirror the validated profiles above; their noise and decomposition choices remain specific to the workflow.

All four backends have classic PBS, sparse/interleaved ManyLUT, ordinary CBS and factorized MVB entries. GLWE MVB examples can switch `SPARSE` to true; GLWE sparse CBS has a separate entry because its secret and parameter choices differ from dense CBS. NTRU sparse supports only ordinary/interleaved PBS; its CBS, one-hot and MVB require classic keys. One-hot and the full high-precision pipeline are NTRU extensions. ManyLUT and factorized MVB are distinct multi-output algorithms.

Boolean gates, bivariate LUTs and odd full-domain LUTs are derived encoding/composition APIs, not additional blind-rotation algorithms. They retain their [user guide](../../crates/primus_tfhe/README.md#choosing-an-operation) and test coverage; this list does not claim a standalone example for every public wrapper or secret distribution. Classic binary/ternary validation remains in the numerical diagnostic above.

### Choosing the lookup example width

The two teaching examples use eight two-bit input chunks and eight output chunks (16 bits each), with d=5 and N=1024. Their polynomial function `(x*x+3*x+7) mod 65536` depends on high input chunks as well as low ones. The cleartext intermediate uses u64 to avoid overflowing u32. These examples are separate from the c7/d5/o3 parameter-diagnostic fixture above.

With output count equal to input count, the complete data table costs `c * 4^c * sizeof(Word)` bytes. This is the public coefficient table only, excluding keys, evaluators and outputs:

| Input/output chunks | Input/output bits | Table-selection chunks | Polynomials per output | Data LUT, u32 / u64 |
| ---: | ---: | ---: | ---: | ---: |
| 6 / 6 | 12 / 12 | 1 | 4 | 96 / 192 KiB |
| **8 / 8** | **16 / 16** | **3** | **64** | **2 / 4 MiB** |
| 10 / 10 | 20 / 20 | 5 | 1024 | 40 / 80 MiB |

Eight chunks demonstrate a 16-bit lookup and multiple encrypted table-selection layers at a modest table size. Ten chunks work in the sampled trials but raise table storage by 20 times over eight; use them for an explicitly larger workload. Counts remain independent in the API. This is an example-size choice, not an algorithmic precision limit.

The 6/8/10 comparison used NTT and RustFFT, u32/u64, seeds 42 and 4242, and inputs `4^c-1`, `floor(2*4^c/3)`, `floor(4^c/3)`, 1 and 0, with output reduced modulo `4^c`; all 120 evaluations decoded correctly. The selected eight-chunk profile was additionally checked with both FFT engines, both words, default and nightly SIMD: two seeds, inputs 0b10_10_10_11_11_00_11_01, 0, 1, 1023, 1024, 65535, 0, and each returned chunk's circular phase error below q24/32. These finite checks do not establish a failure probability.

### Example smoke checklist

Run from the repository root, using release for the representative dimensions:

```bash
for package in primus_tfhe_glwe_ntt primus_tfhe_glwe_fourier primus_tfhe_ntru_ntt primus_tfhe_ntru_fourier primus_tfhe_ntru_lut; do
    for source in crates/"$package"/examples/*.rs; do
        example=${source##*/}
        cargo run --release -p "$package" --example "${example%.rs}" || exit
    done
done
```

When modifying workflows or profiles, exercise these concrete choices, restoring the documented defaults afterward:

- All 22 examples with their u32/default table/order.
- All 22 with u64 and its matching NTT table.
- The ten GLWE examples with the other `ORDER`; the eleven Fourier examples with `TfheFftTable`. These checks may share runs for the five GLWE Fourier examples.
- All four `*_sparse` ManyLUT examples with `SPARSE=false`, and both GLWE MVB examples with `SPARSE=true`, for both word widths.
- Compile/lint all targets with default features and nightly SIMD. Run selected examples with `cargo +nightly run --release -p <package> --example <name> --features simd` when validating that configuration; do not put an extra backend/order loop in the teaching main function.

The public examples retain distinct GLWE/NTRU parameter, key and return contracts and distinct NTT/Fourier table types. Within a crate there is one entry per task. Configuration is intentionally local to each file so that users can read and change it directly; there is no example support layer hiding parameters or the workflow.

Benchmark migration remains separate: only the two GLWE PBS targets currently use the shared constructors. The old pipeline benchmark still uses n=64/N=1024 until its parameter migration; its historical memory/latency results must not be compared directly with these n=800 examples.
