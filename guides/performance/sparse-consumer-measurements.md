# Sparse parameter candidates in complete consumers

> Archive note (2026-10-10): the TFHE benchmark suite and report tools were removed. Commands and source paths below refer to historical revisions; the last complete suite is available at `8d7c4b1a`. Measurements remain evidence for their recorded versions, not current validation.

[Performance decisions and measurement method](README.md)

Measured on 2026-10-05 with numerical source `55de85cb`, following the
[copy/bucket](sparse-parameter-measurements.md) and
[decomposition](sparse-decomposition-measurements.md) studies. This step validates
GLWE NTT consumers at their actual input resolution and output scale. It changes
no production arithmetic, default configuration or noise sampler.

The retained choices are deliberately consumer-specific:

| Candidate | Accepted numerical workloads | Boundary |
| --- | --- | --- |
| STD128 geometry, u32/u64, r2/B86, BR b7/L3 | Ordinary PBS, feedback NAND, three-output ManyLUT and factorized MVB, including feedback | The tested b3/L3 CBS output fails; do not reuse this PBS profile for that CBS consumer |
| 54-bit Q function geometry, u64, r2/B140, BR b27/L1 | Ordinary PBS, three-output ManyLUT and factorized MVB, including feedback | The input domain is three bits, not a high-precision LUT |
| The same 54-bit Q BR, CBS output b2/L5 | Five gadget levels followed by encrypted-ring CMux, with fresh and PBS-produced inputs | Requires this independent CBS output basis; directly using b8/L2 fails |

The original BR decompositions are retimed at the same r2/B=2h. The new
`sparse_candidate_r2` benchmark IDs separately retain the accepted **PBS** choices
alongside the original paper-shaped r3 controls. They do not overwrite the paper
configuration or imply that its security labels transfer to these choices.
STD128 b10/L2, the MEDIUM alternatives, other backends and other output scales are
not promoted by this step.

## Fixed domains and workloads

| Geometry | n / h / N | q / Q | Original BR → candidate | Ring KS |
| --- | --- | --- | --- | --- |
| STD128 | 1024 / 43 / 1024 | 512 / 268369921 | b7/L4 → b7/L3 | b7/L4 |
| Three-bit function | 2048 / 70 / 2048 | 4096 / 18014398509404161 | b27/L2 → b27/L1 | b5/L10 |

Both use fixed-weight binary external secrets, uniform ternary accumulator
secrets and sigma=3.19 for input, BR and ring KS. Inputs are actually encrypted
at q; the context's description rescales the small-LWE sigma to Q. Complete PBS,
ManyLUT and MVB include q→Q lifting, BR, ring KS at Q, sample extraction and Q→q
return. This is the same return adaptation as the [paper comparison](sparse-paper-comparison.md).
Only BR→KS order is measured here; existing small tests cover both orders.

Three-output requests compute:

| Input domain | f0(m) | f1(m) | f2(m) | Input/output plaintext modulus |
| --- | --- | --- | --- | --- |
| m in 0..2 | m xor 1 | m | 1 | 4 |
| m in 0..8 | (m*m+3*m+1) mod 8 | (m+1) mod 8 | m xor 3 | 16 |

All three algorithms use the same functions and fixed-scale output encoding.
`independent3` executes three ordinary PBSes; `many3` returns three interleaved
outputs with padded width four; `factorized3` evaluates three public difference
factors after one BR. `single` evaluates only f0. Its STD128 timing is unary NOT,
not the previous study's two-input NAND, so historical NAND timings are not the
adjacent baseline. NAND is additionally validated as a feedback workload.

CBS inputs use plaintext modulus 4. Its result stays at Q as an NTT GGSW under
the accumulator secret. CMux chooses between two independently encrypted ring
polynomials with coefficients `i mod 4` and `(3*i+1) mod 4`, using a Scaled codec
with plaintext modulus 4. There is no Q→q return after CBS or CMux.

## Resolution and error checks

### ManyLUT and feedback

For padded width s, the effective phase exponent is computed from each public
ciphertext coefficient separately:

```text
R_s(x) = s * round(x * (2N/s) / Q),
exponent = -R_s(b) + sum_i s_i*R_s(a_i) mod 2N.
```

An independent i128 oracle computes this exponent and the signed LUT coefficient
for every fresh input/output. It checks the actual q→Q lift; rounding the decrypted
phase once would miss the ManyLUT error. At STD128 s=4, `2N/s=q=512`, so the lifted
coefficients retain their exact original q-grid. At function s=4, rounding adds
at most 2 q-units per public coefficient. The worst phase allowance is
`2*(h+1)=142`, before input noise; this exceeds the three-bit half interval 128.
Consequently the finite successful corpus below is not a worst-case input guarantee.

Output errors are checked against the selected message's q encoding, with radius
64 or 128. Repeated calls exercise the same evaluator through ordinary, interleaved
and factorized paths. Feedback inputs are previous returned ciphertexts under the
same key, without fresh encryption between rounds. These runs exercise dependencies
excluded from the prior fresh-key Hoeffding argument, but do not establish a
decryption-failure probability for arbitrary circuits.

### Factorized MVB

The common public polynomial and difference factors satisfy
`V*W_i = delta*p_i`. Only the noiseless public V uses modular division by two.
The error after public multiplication is `W_i*e_BR`, followed by that output's
ring KS and modulus-switch terms. Its deterministic amplification is bounded by
`||W_i||_1 * ||e_BR||_infinity`; shared BR errors must not be treated as independent
across outputs. The report records factor norms and checks actual returned phases,
including inputs produced by earlier MVB calls.

### CBS projection and consumption

CBS has a separate budget from ordinary output decoding. For output scalar g_l,
the body row must encrypt `g_l*m`, and mask row r must encrypt `-g_l*m*S_r`,
including the intended zero tails. All coefficients of every row and level are
checked, not just whether a bit can be decoded at the ordinary PBS scale.

The diagnostic first reproduces the coarser public exponents through the raw BR
entry, then projects the prefix with the public trace key. The resulting GLev,
transformed to NTT, must equal the CBS output's entire body row exactly. This
separates BR error at each requested coefficient from projection/scheme-switch
effects without adding production instrumentation.

For the current full reverse trace, automorphisms run in ascending exponent
order `3,5,9,...,N+1`. Over the odd-Q ring, a suffix of normalized operators
`(Id + Auto_(1+2^j))/2` is an exact projection onto a coefficient subset: its
expanded automorphisms cover the subgroup `a=1 mod 2^j` once each. Thus the full
suffix removes other coefficients and preserves the selected error coefficients;
it does not simply shrink retained noise by integer division. The identity was
also checked independently on every monomial at N=32 and N=64. It applies to this
ordered full projection, not arbitrary modular halving or a torus noise formula.

If A_j is the phase error injected by an automorphism key switch, the projected
error is the selected BR coefficient plus the sum of the remaining suffix
projections of A_j. Scheme switching adds its decomposition/key error and multiplies
the projected phase by `-S_r` for each mask row. The same trace and scheme-switch
keys serve multiple levels and requests; their errors cannot be assumed independent.

For CMux, let D reconstruct the candidate difference with residual R. Its phase is

```text
phi(selected) = (1-m)*phi(lhs) + m*phi(rhs)
                - m*phi(R) + sum_{row,level} D_row,level * E_CBS,row,level.
```

The residual allowance is `epsilon_output*(1+||S||_1)`, while the final sum is
bounded by `sum(||D_row,level||_1 * ||E_CBS,row,level||_infinity)` without independence
assumptions. A small per-level ratio alone does not certify this consumer. CMux
therefore also checks every decoded coefficient and its phase distance from the
selected polynomial. The displayed eighth-of-scalar diagnostic is a functional
margin check, not a universal CMux theorem or security claim.

The tested CBS choices are:

| Geometry | Output b/L/d | Smallest scalar | Trace / scheme-switch basis | Key noise |
| --- | --- | ---: | --- | --- |
| 28-bit Q, rejected | 3/3/19 | 524288 | Both 2/14/0 | sigma=6.4 |
| 54-bit Q, rejected screen | 8/2/38 | 274877906944 | Both 8/6/6 | sigma=6.4 |
| 54-bit Q, retained | 2/5/44 | 17592186044416 | Both 8/6/6 | sigma=6.4 |

The retained output uses smaller digits and more levels, raising its smallest
scale while leaving enough decomposition precision for the observed CMux errors.
Its five levels pad to s=8. CBS has a one-bit input here: its q-space half interval
is 512, exceeding the fresh input support plus worst rounding allowance,
`38 + 4*(70+1) = 322`. This does not assert the same support bound for a
key-dependent PBS-produced input; those inputs are checked separately.

Neither BR nor KS noise is reduced to obtain these results. Trace and
scheme-switch sigma=6.4 match the existing circuit fixtures' role noise, and stay
fixed across old/new BR and both 54-bit output-basis trials. Existing parameter
fields already express this separation; no new noise API is needed.

## Numerical results

The main corpus has **24 evaluation-key bundles**, four trials for each of six
configurations. All 14,464 complete PBS/ManyLUT/MVB workloads pass their 22,912
returned-output phase/decoding checks. This count treats an independent-three-PBS
request as one three-output workload and excludes setup, the extra allocation
probes and the identity PBSes used to prepare CBS inputs. All direct LUT-selection
checks pass. The maximum fresh ManyLUT phase displacement at q is 7 for STD128
u32, 5 for STD128 u64 and 36 for the function.

There are **480 zero-allocation probes**: four ordinary/multi-output workloads per
key and 384 CBS→CMux calls. The latter includes the rejected 28-bit configurations;
allocation success does not imply numerical success. No key generation fails in
this corpus; prior matching-frequency results are not replaced by these 24 keys.

Fresh outputs below show maximum absolute error / RMS, in q units. Each STD128
row checks 96 outputs per algorithm; each function row checks 384.

| Geometry / word / BR b/L | Independent PBS | ManyLUT | Factorized MVB |
| --- | ---: | ---: | ---: |
| STD128 / u32 / 7/4 | 6 / 2.179 | 5 / 1.931 | 8 / 2.550 |
| STD128 / u32 / 7/3 | 5 / 1.976 | 5 / 2.255 | 6 / 2.208 |
| STD128 / u64 / 7/4 | 6 / 2.099 | 5 / 1.990 | 6 / 2.229 |
| STD128 / u64 / 7/3 | 5 / 1.934 | 6 / 2.023 | 6 / 2.051 |
| Function / u64 / 27/2 | 7 / 2.464 | 7 / 2.389 | 10 / 2.846 |
| Function / u64 / 27/1 | 9 / 2.327 | 8 / 2.331 | 9 / 2.781 |

The three factors' integer `(L1, squared L2)` norms are `(2,2), (2,2), (2,4)`
for STD128 and `(26,140), (14,56), (20,104)` for the function. The larger factors
raise the function's measured MVB error, even though output decoding still passes.

Feedback checks show the following maximum absolute errors at q, with zero
incorrect returned values. Each STD128 row checks 512 ordinary outputs, 384 each
for ManyLUT/MVB and 1,024 NAND outputs. Function rows check 2,048 ordinary outputs
and 1,536 each for ManyLUT/MVB.

| Geometry / word / BR b/L | Ordinary feedback | ManyLUT feedback | MVB feedback | NAND feedback |
| --- | ---: | ---: | ---: | ---: |
| STD128 / u32 / 7/4 | 7 | 7 | 8 | 7 |
| STD128 / u32 / 7/3 | 8 | 6 | 9 | 7 |
| STD128 / u64 / 7/4 | 7 | 6 | 7 | 7 |
| STD128 / u64 / 7/3 | 6 | 6 | 8 | 8 |
| Function / u64 / 27/2 | 8 | 8 | 12 | — |
| Function / u64 / 27/1 | 8 | 9 | 9 | — |

### Rejected CBS scales

The 28-bit output b3/L3 corpus checks 64 CBS→CMux calls per row, including
fresh and PBS-produced bits. The comparison includes the original BR basis,
which fails too. Entries count wrong CMux **coefficients**, not an estimate of
request failure probability.

| Word / BR b/L | Largest raw-BR error / its scalar | Largest output-row error / its scalar | Wrong CMux coefficients / checked |
| --- | ---: | ---: | ---: |
| u32 / 7/4 | 2.181 | 2.388 | 30,153 / 65,536 |
| u32 / 7/3 | 2.122 | 2.338 | 26,325 / 65,536 |
| u64 / 7/4 | 2.170 | 2.406 | 29,069 / 65,536 |
| u64 / 7/3 | 2.008 | 2.212 | 26,683 / 65,536 |

The initial 54-bit b8/L2 screen similarly fails: four calls on trial zero give
3,169/8,192 wrong CMux coefficients with BR b27/L2, and 1,422/8,192 with b27/L1.
The candidate's raw error reaches 2.111 times the smallest scalar before projection.
All input/LUT selections are correct. These are unsuitable parameter combinations,
not missing sparse CBS support or evidence that the BR algorithm is incorrect.

### Retained 54-bit CBS output b2/L5

Both old/new BR use the same five output scales, trace/scheme-switch bases and
role noise. All **128 CBS→CMux requests** pass, checking 262,144 selected-ring
coefficients and 2,621,440 GGSW row/level coefficients. Every row/level error stays
below one eighth of its scalar, including non-target coefficients. The table takes
the maximum across both rows, all coefficients, four keys and 16 calls per key.

| Output scalar | BR b27/L2 maximum error / scalar | BR b27/L1 maximum error / scalar |
| ---: | ---: | ---: |
| 17592186044416 | 0.100958 | 0.071242 |
| 70368744177664 | 0.0278794 | 0.0186419 |
| 281474976710656 | 0.00536722 | 0.00397493 |
| 1125899906842624 | 0.00103935 | 0.00122085 |
| 4503599627370496 | 0.000453247 | 0.000318675 |

| BR | CMux maximum error / Q | CMux RMS / Q | Decoding radius / Q |
| --- | ---: | ---: | ---: |
| 27/2 | 0.046215 | 0.008222 | 0.125 |
| 27/1 | 0.044403 | 0.007932 | 0.125 |

## Complete-request latency and resources

AMD Ryzen 9 9955HX3D, rustc/cargo 1.98.1, stable/default features, release and
the repository's `target-cpu=native`. CPU 4 and CPU 8 use the 96/32 MiB L3 groups.
Criterion uses 40 flat samples, 0.5 s warmup and a 2 s target. Each iteration is
one complete workload named above. Key generation, input preparation, table
compilation, diagnostics and reusable allocations are outside both registration
callbacks and timed iterations. Online input lifting and required return stages
are inside timing.

Six configurations run in separate processes, first forward then reverse on CPU 4,
and reverse then forward on CPU 8. Within each process the order is single,
independent3, many3, factorized3, then eligible CBS and CBS→CMux. The compared CBS
rows both use output b2/L5. Rejected CBS configurations are not timed as successful
consumers. Encrypted validation and compilation finish before this timing matrix.
Cells show two-run mean ranges; the accompanying interval envelopes are unions
of individual 95% intervals, not newly estimated cross-run confidence intervals.

| Geometry / word / BR b/L | Complete workload | CPU 4 ms | CPU 8 ms |
| --- | --- | ---: | ---: |
| STD128 / u32 / 7/4 | single | 5.792–6.219 [5.754–6.292] | 6.549–6.555 [6.508–6.618] |
| STD128 / u32 / 7/4 | independent3 | 17.279–18.525 [17.159–18.705] | 19.671–19.769 [19.539–20.002] |
| STD128 / u32 / 7/4 | many3 | 5.806–6.465 [5.767–6.519] | 6.572–6.578 [6.527–6.645] |
| STD128 / u32 / 7/4 | factorized3 | 5.793–5.793 [5.745–5.857] | 6.572–6.586 [6.527–6.638] |
| STD128 / u32 / 7/3 | single | 3.585–3.693 [3.564–3.726] | 4.857–4.871 [4.822–4.933] |
| STD128 / u32 / 7/3 | independent3 | 10.795–11.004 [10.718–11.097] | 14.558–14.630 [14.467–14.779] |
| STD128 / u32 / 7/3 | many3 | 3.589–3.679 [3.568–3.712] | 4.887–4.891 [4.837–4.957] |
| STD128 / u32 / 7/3 | factorized3 | 3.606–3.690 [3.584–3.721] | 4.883–4.890 [4.849–4.935] |
| STD128 / u64 / 7/4 | single | 9.634–9.696 [9.590–9.763] | 10.272–10.292 [10.207–10.384] |
| STD128 / u64 / 7/4 | independent3 | 28.920–29.028 [28.782–29.227] | 30.910–30.929 [30.689–31.240] |
| STD128 / u64 / 7/4 | many3 | 9.659–9.689 [9.617–9.754] | 10.275–10.314 [10.214–10.412] |
| STD128 / u64 / 7/4 | factorized3 | 9.696–9.713 [9.640–9.775] | 10.314–10.328 [10.248–10.420] |
| STD128 / u64 / 7/3 | single | 7.051–7.125 [7.017–7.182] | 7.646–7.825 [7.603–7.888] |
| STD128 / u64 / 7/3 | independent3 | 21.170–21.315 [21.080–21.483] | 22.940–23.510 [22.789–23.715] |
| STD128 / u64 / 7/3 | many3 | 7.087–7.100 [7.040–7.146] | 7.644–7.732 [7.600–7.798] |
| STD128 / u64 / 7/3 | factorized3 | 7.104–7.115 [7.066–7.162] | 7.703–7.730 [7.636–7.802] |
| Function / u64 / 27/2 | single | 21.159–21.480 [21.071–21.596] | 21.394–21.396 [21.238–21.598] |
| Function / u64 / 27/2 | independent3 | 63.499–64.555 [63.135–65.041] | 64.086–64.204 [63.651–64.763] |
| Function / u64 / 27/2 | many3 | 21.429–21.446 [21.319–21.573] | 21.263–21.449 [21.163–21.620] |
| Function / u64 / 27/2 | factorized3 | 21.253–22.087 [21.162–22.322] | 21.304–21.529 [21.207–21.658] |
| Function / u64 / 27/2 | cbs | 23.322–23.492 [23.163–23.613] | 23.019–23.330 [22.882–23.511] |
| Function / u64 / 27/2 | cbs_cmux | 23.255–23.562 [23.156–23.700] | 23.021–23.355 [22.922–23.495] |
| Function / u64 / 27/1 | single | 10.848–10.856 [10.801–10.925] | 10.903–11.010 [10.846–11.088] |
| Function / u64 / 27/1 | independent3 | 32.531–32.684 [32.403–32.874] | 32.684–33.044 [32.469–33.245] |
| Function / u64 / 27/1 | many3 | 10.839–10.841 [10.773–10.924] | 10.842–10.995 [10.781–11.074] |
| Function / u64 / 27/1 | factorized3 | 11.034–11.197 [10.971–11.266] | 11.112–11.223 [11.022–11.295] |
| Function / u64 / 27/1 | cbs | 12.550–12.561 [12.494–12.641] | 12.748–12.939 [12.672–13.044] |
| Function / u64 / 27/1 | cbs_cmux | 12.597–12.624 [12.542–12.700] | 12.756–12.960 [12.685–13.066] |

Latency reductions below compare each candidate with its matched r2 original BR
basis, averaging the two means on each CPU. They do not compare with r3 or with
classic BR, and they are not kernel changes at fixed parameters.
STD128 u32 varies more on CPU 4, particularly the original `many3` measurement
(5.806–6.465 ms); both passes are retained. The larger reduction on that CPU is
an observation, not evidence for a particular cache mechanism or a portable
40% improvement.

| Geometry / word | Complete workload | CPU 4 reduction | CPU 8 reduction |
| --- | --- | ---: | ---: |
| STD128 / u32 | single | 39.40% | 25.77% |
| STD128 / u32 | independent3 | 39.12% | 25.99% |
| STD128 / u32 | many3 | 40.77% | 25.64% |
| STD128 / u32 | factorized3 | 37.04% | 25.73% |
| STD128 / u64 | single | 26.67% | 24.77% |
| STD128 / u64 | independent3 | 26.69% | 24.89% |
| STD128 / u64 | many3 | 26.68% | 25.32% |
| STD128 / u64 | factorized3 | 26.74% | 25.24% |
| Function / u64 | single | 49.10% | 48.79% |
| Function / u64 | independent3 | 49.07% | 48.77% |
| Function / u64 | many3 | 49.43% | 48.87% |
| Function / u64 | factorized3 | 48.71% | 47.85% |
| Function / u64 | cbs | 46.36% | 44.58% |
| Function / u64 | cbs_cmux | 46.13% | 44.55% |

Heap measurements count incremental requested live and peak bytes, not RSS,
memory traffic or stack. Context/client, caller ciphertexts and diagnostic buffers
are excluded. PBS workspace serves independent and ManyLUT paths; factorized
MVB adds its own shared-rotation buffer. Standalone CBS excludes ordinary return
workspace. Additional circuit material includes trace and scheme-switch keys.

| Geometry / word / BR b/L | PBS server retained / peak bytes | PBS workspace retained / peak bytes | Extra MVB retained / peak bytes |
| --- | ---: | ---: | ---: |
| STD128 / u32 / 7/4 | 139,903,768 / 139,936,536 | 133,120 / 133,120 | 8,192 / 8,192 |
| STD128 / u32 / 7/3 | 104,940,300 / 104,981,260 | 116,736 / 116,736 | 8,192 / 8,192 |
| STD128 / u64 / 7/4 | 279,790,456 / 279,855,992 | 256,000 / 256,000 | 16,384 / 16,384 |
| STD128 / u64 / 7/3 | 209,863,520 / 209,945,440 | 223,232 / 223,232 | 16,384 / 16,384 |
| Function / u64 / 27/2 | 555,582,856 / 555,812,232 | 380,928 / 380,928 | 32,768 / 32,768 |
| Function / u64 / 27/1 | 277,972,336 / 278,201,712 | 315,392 / 315,392 | 32,768 / 32,768 |

| 54-bit BR | Additional circuit key retained / peak bytes | Standalone CBS resources + operation retained / construction peak bytes |
| --- | ---: | ---: |
| 27/2 | 2,733,552 / 2,881,008 | 610,304 / 610,304 |
| 27/1 | 2,733,552 / 2,881,008 | 544,768 / 544,768 |

The BR coefficient payload falls by 25% for STD128 and 50% for the function,
as in the previous study. The five-level CBS output buffer itself occupies
327,680 bytes; it is caller-owned and identical for the two compared BR bases.
The lower BR level count does not reduce trace or scheme-switch material.

## Reproduction and maintained scope

Use the geometry/bases above with the public APIs in the GLWE NTT
[sparse](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse.rs),
[MVB](../../crates/primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) and
[CBS](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse_circuit_bootstrap.rs)
examples, and the existing q/Q request adapter (`../../benchmarks/tfhe/benches/sparse_paper/request.rs`, historical source).
Those examples retain their original geometries; do not change only a BR base
and assume the remaining parameters match this study.

For numerical trial t=0..3, use rand 0.10.3 StdRng seeds: client `42+t`,
BR `4242+100*t`, independent ring KS `84242+100*t`, circuit material
`924242+100*t`, and encrypted ring candidates `564242+t`. Generate the sparse BR
and ring KS with the existing separate public generators, then combine them using
`ServerKey::new`. Circuit keys are generated separately from the same accumulator
secret. Public matching retries remain in key generation; no client is replaced
after a failure.

Fresh input seeds are `43,4343,43002,43003`, covering every input message. Ordinary
feedback uses seeds 43/4343, every starting message and 32 rounds. ManyLUT and MVB
feedback use seed 4343, every start and 16 rounds; output index `round mod 3` feeds
the next call. NAND uses seeds 43/4343, all four initial pairs and 32 rounds, with
the previous input and previous result supplying the next pair. CBS checks both
bits for every seed, first freshly encrypted and then after identity PBS/return;
its input encoding always has t=4.

Timing uses trial zero, then restores a fresh encrypted message one with seed 43.
Use `taskset -c 4` / `taskset -c 8` and the Criterion settings above. The paired
research fixture uses independent KS randomness, as in the decomposition study.
The maintained paper benchmark retains its original sequential server RNG
convention; its new candidate IDs reproduce the configuration, not identical key
bytes or all consumer workloads from this experiment.

```sh
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- 'paper_2026_1730/.*/sparse_candidate_r2/'
```

This adds only three candidate parameter instances (STD128 u32/u64 and function
u64), each with the existing complete/raw-BR stages. Original paper controls,
MEDIUM, other backend benchmarks, examples and production defaults stay as they
were. No ordinary CI parameter grid or new benchmark target is added.

Existing focused tests pass for sparse PBS/ManyLUT, CBS/CMux and factorized MVB;
the benchmark's six new stage IDs also pass Criterion smoke. Package all-targets
check, strict clippy and formatting pass. No full-workspace or nightly SIMD run
is implied. The focused validation commands are:

```sh
cargo fmt --all -- --check
cargo check -p primus_tfhe_glwe_ntt --all-targets
cargo test -p primus_tfhe_glwe_ntt --test sparse_pbs --test circuit_bootstrap --test factorized_pbs
cargo clippy -p primus_tfhe_glwe_ntt --all-targets -- -D warnings
cargo bench -p primus_tfhe_glwe_ntt --bench sparse_paper -- 'paper_2026_1730/.*/sparse_candidate_r2/' --test
```

The temporary consumer and diagnostic/timing assets are removed after recording
these results.

These finite, paired requests are not independent failure-probability trials.
The preceding matching/security conditioning limits still apply. NTRU's
one-hot/MVB/high-precision pipeline needs its own NTRU noise and return budget;
the three-bit GLWE function is not evidence for that pipeline. Sparse BR support
in a consumer and suitability of a particular parameter set are separate facts.
