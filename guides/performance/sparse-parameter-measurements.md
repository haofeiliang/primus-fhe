# Sparse copy and bucket selection at fixed decomposition

> Archive note (2026-10-10): the TFHE benchmark suite and report tools were removed. Commands and source paths below refer to historical revisions; the last complete suite is available at `8d7c4b1a`. Measurements remain evidence for their recorded versions, not current validation.

[Performance decisions and measurement method](README.md)

Measured on 2026-10-05. This experiment starts at `55de85cb` and changes only
the sparse copy count r and bucket count B. It uses the existing GLWE NTT NAND / padded-function
[paper profiles](sparse-paper-comparison.md#parameters-and-comparison-boundary),
with identical n, h, N, q, Q, secret distribution, decomposition, coefficient
noise and ring-key-switch return. The production parameters, kernels, public
APIs and benchmark registrations are unchanged. This is parameter research,
not a new security preset or a reproduction of the authors' executable.

At fixed decomposition and noise, **r=2, B=2h is the fastest measured choice**
for every tested profile/word on both CPU groups. Complete-request latency falls
by 15.7–45.1% relative to r=3, B=h+3, coefficient-key payload by 31–32%, and
observed key-generation time by a similar fraction; evaluator size is unchanged.
Keep it as the primary research candidate, with r=2, B=ceil(2.5h) as a slower
alternative with fewer map retries. Neither is promoted to default parameters:
matching/security conditioning and a complete consumer error budget still matter.
Classic is not retimed here, so no new sparse/classic speedup is claimed.

## Matching screen and admitted candidates

The production [bucket-map sampler](../../crates/primus_tfhe/src/sparse.rs)
chooses r **distinct** buckets uniformly for each of all n inputs. Only the
public map is resampled on failure, up to eight attempts, preserving the secret.
`B >= max(r,h)` is necessary; it does not guarantee matching. All r*n encrypted
selectors and B dummies remain in the online calculation.

Each row below uses 128 independently sampled fixed-weight supports and 64 map
seeds per support: 8,192 generation attempts, including every eight-map failure.
A temporary copy reuses the production sampler and BFS matcher, instrumenting
attempts and bucket occupancy. Sixteen cases per configuration agree with the
public `BucketMap::try_generate`, including the public map, assignment, outcome
and next RNG word. A separate 8-support / 32-map screen checks all attempted
maps against an independent recursive augmenting-path matcher: 5,888 retry
sequences across the 23 configurations, with no disagreement.

The two rejected compact grids demonstrate why h alone is insufficient: r3/B=h
and r2/B=h+3 frequently exhaust retries. The remaining rows distinguish reducing
copies from merely increasing buckets. The h32 diagnostic is retained separately.
Mean attempts include failed sequences as eight; p95 maximum counts public
selector entries per bucket, excluding its dummy, among successful generations.

| Profile | r / B | First-map failures / 8192 | Eight-map failures / 8192 | Mean attempts | p95 max bucket |
| --- | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND | 3 / 43 | 7703 (94.031%) | 4872 | 6.479 | 97 |
| STD128 NAND | 3 / 46 | 3318 (40.503%) | 5 | 1.669 | 92 |
| STD128 NAND | 3 / 54 | 22 (0.269%) | 0 | 1.003 | 81 |
| STD128 NAND | 2 / 46 | 8179 (99.841%) | 8109 | 7.964 | 67 |
| STD128 NAND | 2 / 65 | 3902 (47.632%) | 27 | 1.940 | 50 |
| STD128 NAND | 2 / 86 | 627 (7.654%) | 0 | 1.081 | 41 |
| STD128 NAND | 2 / 108 | 124 (1.514%) | 0 | 1.016 | 35 |
| MEDIUM NAND | 3 / 31 | 6920 (84.473%) | 2170 | 4.791 | 127 |
| MEDIUM NAND | 3 / 34 | 1750 (21.362%) | 0 | 1.266 | 118 |
| MEDIUM NAND | 3 / 39 | 36 (0.439%) | 0 | 1.004 | 105 |
| MEDIUM NAND | 2 / 34 | 8040 (98.145%) | 7093 | 7.505 | 83 |
| MEDIUM NAND | 2 / 47 | 3143 (38.367%) | 3 | 1.645 | 64 |
| MEDIUM NAND | 2 / 62 | 567 (6.921%) | 0 | 1.075 | 52 |
| MEDIUM NAND | 2 / 78 | 96 (1.172%) | 0 | 1.012 | 44 |
| Padded function | 3 / 70 | 8113 (99.036%) | 7631 | 7.745 | 119 |
| Padded function | 3 / 73 | 6261 (76.428%) | 983 | 3.752 | 114 |
| Padded function | 3 / 88 | 4 (0.049%) | 0 | 1.000 | 98 |
| Padded function | 2 / 73 | 8192 (100.000%) | 8192 | 8.000 | — |
| Padded function | 2 / 105 | 5328 (65.039%) | 255 | 2.772 | 61 |
| Padded function | 2 / 140 | 740 (9.033%) | 0 | 1.099 | 49 |
| Padded function | 2 / 175 | 107 (1.306%) | 0 | 1.013 | 42 |
| n728/h32 | 3 / 64 | 0 (0.000%) | 0 | 1.000 | 53 |
| n728/h32 | 2 / 64 | 598 (7.300%) | 0 | 1.079 | 39 |

The h70/B73 paper-shaped profile has 76.43% first-map failure and 983/8192
(12.00%) failure after eight maps under this sampler. An approximate 95% Wilson
interval for the first probability is 75.50–77.34%. This is **key-generation
failure**, not a decryption failure of an accepted key. The independent matching
oracle agrees. Section 7.1 of the [paper](https://eprint.iacr.org/2026/1730.pdf)
describes success above one half with r3/B=h+3; that claim is not reproduced by
this implementation at h70. The authors' exact graph-generation code is
unavailable, so the cause of the difference remains unresolved.

For r2/B=2h the observed first failures are 6.92–9.03%; for r2/B=ceil(2.5h)
they are 1.17–1.51%. No eight-map failures occurred in these rows. Zero out of
8,192 is not a cryptographic tail bound: its one-sided 95% binomial upper bound
is about 0.0366%. Retry histograms are consistent with the independent-map
model, whose eight-map failure is epsilon^8; substituting an observed epsilon
is an estimate, not a proven parameter bound.

Only four configurations per primary profile advance to expensive measurements:
r3/B=h+3, r3/B=ceil(1.25h), r2/B=2h and r2/B=ceil(2.5h). Gates use u32;
u64 gates repeat the original and r2/B=2h configurations as word-width controls.
The 54-bit function uses u64. The n728/h32 screen has no new timing run.

### What resampling reveals

Let H be an initially sampled public graph, S a fixed-weight secret support,
and A(S,H) the existence of a matching. Under the ideal independent uniform
sampler, input-index symmetry makes p=Pr[A(S,H)] depend on n,h,r,B, not the
particular support. Conditional on returning a key within eight attempts,

```text
P(H | S, accepted) = P(H) * 1[A(S,H)] / p.
```

Bounding retries changes the probability of returning an error, not this
conditional distribution. Uniform fixed-weight S remains uniform marginally,
but S and the published H are correlated: incompatible supports are ruled out.
For the full (S,H) joint distribution the conditional/unconditional likelihood
ratio is 1/p on the accepted set. Its log2 factor is about 0.749 / 0.347 / 2.085
for the three original profiles, 0.104–0.137 for r2/B=2h and 0.017–0.022 for
r2/B=ceil(2.5h), using the observed p. These are conditioning diagnostics;
they are **not** certified losses in computational security or a posterior
entropy guarantee for every published graph. No new LWE estimator or reduction
for these adapted profiles has been established.

As a coarse public-graph check, the mean maximum bucket length before/after
acceptance is 106.56/106.48 for h70/r3/B73, versus 44.31/44.31 for h70/r2/B140.
Similar unlabeled occupancy statistics do not demonstrate independence from S.
The explicit conditioning formula, not a bucket histogram, describes the issue.

## Complete request and blind-rotation timing

AMD Ryzen 9 9955HX3D, Rust 1.98.1, stable/default features, existing
`target-cpu=native`, and the automatically selected NTT backend are unchanged.
CPU 4 (96 MiB L3 group) and CPU 8 (32 MiB L3 group) run sequentially.
Each configuration runs in a fresh process with one cached context/key/request,
and both complete and raw-BR stages reuse that fixture. Setup, allocation and
validation are outside `b.iter`; one iteration executes one operation.
Criterion uses 40 flat samples, 0.5 s warmup and a 2 s target per stage.

There are two opposite-order passes per CPU: CPU 4 uses the configuration order
below then its reverse; CPU 8 reverses that sequence. Complete requests run
before raw BR within each process. Compilation finishes before timing, and
there is no concurrent benchmark or compiler. Each cell reports the range of
the two run means in milliseconds, followed by the envelope of their individual
95% confidence intervals in brackets. The envelope describes the observed runs;
it is not a newly estimated cross-run confidence interval.

### One complete q-to-q request

| Profile / word | r / B | CPU 4 ms | CPU 8 ms |
| --- | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 8.181–8.260 [8.110–8.351] | 8.632–8.738 [8.574–8.826] |
| STD128 NAND / u32 | 3 / 54 | 8.276–8.319 [8.231–8.406] | 8.742–8.854 [8.676–8.939] |
| STD128 NAND / u32 | 2 / 86 | 5.613–5.747 [5.571–5.807] | 6.383–6.396 [6.342–6.459] |
| STD128 NAND / u32 | 2 / 108 | 5.921–6.020 [5.872–6.076] | 6.609–6.636 [6.568–6.691] |
| STD128 NAND / u64 | 3 / 46 | 12.398–12.409 [12.314–12.541] | 13.179–13.358 [13.098–13.498] |
| STD128 NAND / u64 | 2 / 86 | 9.621–9.654 [9.571–9.730] | 10.324–10.348 [10.264–10.432] |
| MEDIUM NAND / u32 | 3 / 34 | 2.868–2.920 [2.850–2.966] | 4.284–4.293 [4.254–4.333] |
| MEDIUM NAND / u32 | 3 / 39 | 2.935–2.955 [2.911–2.996] | 4.307–4.320 [4.269–4.356] |
| MEDIUM NAND / u32 | 2 / 62 | 1.563–1.615 [1.557–1.627] | 2.938–2.939 [2.919–2.965] |
| MEDIUM NAND / u32 | 2 / 78 | 1.669–1.763 [1.662–1.770] | 3.067–3.082 [3.047–3.110] |
| MEDIUM NAND / u64 | 3 / 34 | 5.520–5.696 [5.486–5.758] | 6.175–6.273 [6.144–6.322] |
| MEDIUM NAND / u64 | 2 / 62 | 4.098–4.192 [4.070–4.228] | 4.722–4.752 [4.696–4.801] |
| Padded function / u64 | 3 / 73 | 25.581–25.621 [25.426–25.848] | 25.070–25.360 [24.941–25.754] |
| Padded function / u64 | 3 / 88 | 26.231–26.323 [26.073–26.553] | 25.740–26.047 [25.608–26.274] |
| Padded function / u64 | 2 / 140 | 21.055–21.448 [20.940–21.581] | 21.243–21.256 [21.127–21.423] |
| Padded function / u64 | 2 / 175 | 23.191–23.224 [23.073–23.357] | 22.553–22.591 [22.434–22.728] |

### One raw blind rotation

| Profile / word | r / B | CPU 4 ms | CPU 8 ms |
| --- | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 8.177–8.190 [8.108–8.266] | 8.658–8.733 [8.575–8.796] |
| STD128 NAND / u32 | 3 / 54 | 8.262–8.284 [8.217–8.353] | 8.692–8.852 [8.637–8.936] |
| STD128 NAND / u32 | 2 / 86 | 5.611–5.703 [5.565–5.760] | 6.362–6.393 [6.322–6.455] |
| STD128 NAND / u32 | 2 / 108 | 5.884–6.025 [5.839–6.078] | 6.615–6.629 [6.575–6.690] |
| STD128 NAND / u64 | 3 / 46 | 12.361–12.372 [12.294–12.474] | 13.171–13.340 [13.058–13.458] |
| STD128 NAND / u64 | 2 / 86 | 9.581–9.616 [9.534–9.682] | 10.315–10.351 [10.256–10.428] |
| MEDIUM NAND / u32 | 3 / 34 | 2.867–2.886 [2.847–2.921] | 4.280–4.492 [4.249–4.535] |
| MEDIUM NAND / u32 | 3 / 39 | 2.916–2.918 [2.885–2.959] | 4.295–4.319 [4.265–4.365] |
| MEDIUM NAND / u32 | 2 / 62 | 1.555–1.605 [1.549–1.614] | 2.930–2.939 [2.910–2.964] |
| MEDIUM NAND / u32 | 2 / 78 | 1.665–1.763 [1.659–1.774] | 3.083–3.085 [3.053–3.124] |
| MEDIUM NAND / u64 | 3 / 34 | 5.497–5.711 [5.465–5.762] | 6.134–6.275 [6.102–6.344] |
| MEDIUM NAND / u64 | 2 / 62 | 4.073–4.112 [4.050–4.146] | 4.710–5.287 [4.687–5.502] |
| Padded function / u64 | 3 / 73 | 25.541–25.694 [25.392–25.954] | 24.975–25.207 [24.865–25.426] |
| Padded function / u64 | 3 / 88 | 26.269–26.409 [26.067–26.701] | 25.681–26.009 [25.554–26.246] |
| Padded function / u64 | 2 / 140 | 20.948–21.369 [20.851–21.505] | 21.189–21.223 [21.099–21.370] |
| Padded function / u64 | 2 / 175 | 23.136–23.213 [23.014–23.437] | 22.454–22.732 [22.329–23.011] |

Using the average of the two complete-request run means per CPU, r2/B=2h
reduces latency by 26.4–30.9% for STD128/u32, 22.1–22.3% for STD128/u64,
31.5–45.1% for MEDIUM/u32, 23.9–26.1% for MEDIUM/u64, and 15.7–17.0% for
the function. Raising B to ceil(2.5h) trades some of that gain for fewer matching
retries. Keeping r=3 and increasing B to ceil(1.25h) substantially improves
matching but provides no repeatable complete-request speedup in these runs.

The MEDIUM/u64 CPU 8 raw-BR candidate has wider run variation (4.710–5.287 ms);
its two complete-request measurements remain 4.722–4.752 ms. Separately timed
stages may drift, so their difference is not an estimate of return-path cost.
L3 capacities identify the measured cores; these timings alone do not establish
a cache mechanism or explain differences between cores.

## Key generation, memory and numerical checks

Keygen timings below are medians of eight complete server-key constructions per
configuration on CPU 4, including all internal map retries and temporary keygen
workspaces, excluding context/client setup and returned-key drop. These are
untimed-setup observations from the validation run, not Criterion confidence
estimates. All 128 seeds in this smaller key corpus succeeded; that does not
supersede the failures counted in the large graph screen.

A separate temporary allocator records **incremental requested live bytes**
and peak during construction, not allocation traffic or RSS. The already
prepared context, client and map diagnostic are excluded. The evaluator has
its own measured retained/peak bytes; caller input/output/LUT buffers are excluded.
The reported retained and peak bytes are maxima across the eight keys in each
configuration; coefficient payload sizes are fixed by its layout.

| Profile / word | r / B | BR coefficient MiB | Server retained bytes | Construction peak bytes | Keygen median ms | Output error max / RMS at q |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 194.875 | 204399064 | 204431832 | 255.52 | 6 / 2.018 |
| STD128 NAND / u32 | 3 / 54 | 195.375 | 204923416 | 204956184 | 255.83 | 6 / 2.205 |
| STD128 NAND / u32 | 2 / 86 | 133.375 | 139903768 | 139936536 | 174.00 | 7 / 2.337 |
| STD128 NAND / u32 | 2 / 108 | 134.750 | 141345736 | 141378504 | 176.61 | 7 / 2.090 |
| STD128 NAND / u64 | 3 / 46 | 389.750 | 408773176 | 408838712 | 348.60 | 6 / 2.267 |
| STD128 NAND / u64 | 2 / 86 | 266.750 | 279790456 | 279855992 | 237.96 | 6 / 2.186 |
| MEDIUM NAND / u32 | 3 / 34 | 97.062 | 101835104 | 101867872 | 125.76 | 20 / 6.972 |
| MEDIUM NAND / u32 | 3 / 39 | 97.219 | 101998984 | 102031752 | 125.49 | 23 / 6.487 |
| MEDIUM NAND / u32 | 2 / 62 | 65.938 | 69190208 | 69222976 | 85.05 | 18 / 5.430 |
| MEDIUM NAND / u32 | 2 / 78 | 66.438 | 69714624 | 69747392 | 86.08 | 15 / 5.234 |
| MEDIUM NAND / u64 | 3 / 34 | 194.125 | 203645352 | 203710888 | 172.82 | 19 / 6.514 |
| MEDIUM NAND / u64 | 2 / 62 | 131.875 | 138363528 | 138429064 | 117.90 | 17 / 5.996 |
| Padded function / u64 | 3 / 73 | 777.125 | 815252336 | 815481712 | 744.02 | 10 / 2.320 |
| Padded function / u64 | 3 / 88 | 779.000 | 817218536 | 817447912 | 748.05 | 8 / 2.423 |
| Padded function / u64 | 2 / 140 | 529.500 | 555582856 | 555812232 | 508.85 | 8 / 2.431 |
| Padded function / u64 | 2 / 175 | 533.875 | 560170656 | 560400032 | 512.02 | 9 / 2.460 |

For every r/B in a given profile, evaluator retained heap equals its construction
peak and is unchanged: STD128 u32/u64 133120/256000 bytes, MEDIUM u32/u64
100352/190464 bytes, function u64 380928 bytes. At r2/B=2h the coefficient
payload falls by about 31–32%, with similar observed keygen reductions. Larger
B adds dummy keys and more bucket external products; it does not eliminate
additional source selectors when r remains fixed.

The corpus comprises 128 generated server keys and 5,120 complete requests:
all four NAND pairs or all eight padded-function messages, with eight independent
input seeds for each key. Every result decodes correctly, and the lifted
mask/body exponents equal the direct q-to-2N exponents. Each key also passes
one separately counted zero-allocation request. The q/4 and q/16 output
spacings are 128 and 256, respectively; observed residuals do not establish a
tail probability. Ordinary small-parameter tests and their CI matrix are unchanged.

### Noise accounting with fixed basis

Let m_j be the number of public selectors in bucket j. In the independent,
centered fresh-key error model, before modular wrap, every row of its aggregate
has coefficient variance `(m_j+1)*v`, where v is one fresh row's noise variance.
The `+1` accounts for the independently encrypted dummy. Monomial rotations
are signed permutations, so they do not amplify individual coefficient variance.
The sampler parameter remains sigma=3.19; its exact discrete/truncated variance
is not assumed to be exactly sigma squared.

Given the current accumulator decomposition D, the newly injected external
product variance in this model is `(m_j+1)*v*sum(||D_row,level||_2^2)`.
A deterministic fresh-error bound is instead
`(m_j+1)*E_key*sum(||D_row,level||_1)`, if each fresh coefficient is bounded by
E_key. Summing bucket counts yields `sum(m_j+1)=r*n+B`. This explains why fewer
copies reduce that part of the budget, including the dummy contributions.
It does not fix the actual digits across configurations or prove total PBS noise.

More buckets also mean more approximate decompositions and external products.
Their remainder terms must be accumulated separately, especially for MEDIUM's
eight dropped bits. Input/return modulus-switch error and ring-KS noise are
unchanged in configuration but still contribute to output error. Thus a lower
r*n+B cannot substitute for the complete error budget needed to recommend a
parameter set. The measured residuals above support keeping candidates for
further research, not automatically changing PBS/CBS/one-hot/LUT parameters.

## Retry distributions

Each row records successes on attempts 1 through 8; the final column records
sequences that failed all eight. Counts sum to 8,192. This retains failures and
retry tails rather than reporting only the first successful graph.

| Profile | r / B | Success counts on attempts 1, 2, 3, 4, 5, 6, 7, 8 | Eight failures |
| --- | ---: | --- | ---: |
| STD128 NAND | 3 / 43 | 489, 446, 461, 442, 388, 385, 356, 353 | 4872 |
| STD128 NAND | 3 / 46 | 4874, 1993, 816, 306, 127, 41, 22, 8 | 5 |
| STD128 NAND | 3 / 54 | 8170, 22, 0, 0, 0, 0, 0, 0 | 0 |
| STD128 NAND | 2 / 46 | 13, 11, 7, 7, 14, 9, 14, 8 | 8109 |
| STD128 NAND | 2 / 65 | 4290, 1970, 950, 512, 241, 112, 52, 38 | 27 |
| STD128 NAND | 2 / 86 | 7565, 591, 32, 4, 0, 0, 0, 0 | 0 |
| STD128 NAND | 2 / 108 | 8068, 121, 3, 0, 0, 0, 0, 0 | 0 |
| MEDIUM NAND | 3 / 31 | 1272, 1054, 923, 762, 607, 555, 469, 380 | 2170 |
| MEDIUM NAND | 3 / 34 | 6442, 1411, 275, 46, 11, 7, 0, 0 | 0 |
| MEDIUM NAND | 3 / 39 | 8156, 36, 0, 0, 0, 0, 0, 0 | 0 |
| MEDIUM NAND | 2 / 34 | 152, 139, 143, 167, 140, 127, 103, 128 | 7093 |
| MEDIUM NAND | 2 / 47 | 5049, 1852, 771, 312, 126, 52, 17, 10 | 3 |
| MEDIUM NAND | 2 / 62 | 7625, 526, 36, 4, 1, 0, 0, 0 | 0 |
| MEDIUM NAND | 2 / 78 | 8096, 95, 1, 0, 0, 0, 0, 0 | 0 |
| Padded function | 3 / 70 | 79, 71, 82, 81, 61, 69, 59, 59 | 7631 |
| Padded function | 3 / 73 | 1931, 1478, 1127, 878, 647, 473, 380, 295 | 983 |
| Padded function | 3 / 88 | 8188, 4, 0, 0, 0, 0, 0, 0 | 0 |
| Padded function | 2 / 73 | 0, 0, 0, 0, 0, 0, 0, 0 | 8192 |
| Padded function | 2 / 105 | 2864, 1856, 1215, 783, 507, 344, 230, 138 | 255 |
| Padded function | 2 / 140 | 7452, 669, 69, 2, 0, 0, 0, 0 | 0 |
| Padded function | 2 / 175 | 8085, 106, 1, 0, 0, 0, 0, 0 | 0 |
| n728/h32 | 3 / 64 | 8192, 0, 0, 0, 0, 0, 0, 0 | 0 |
| n728/h32 | 2 / 64 | 7594, 548, 47, 3, 0, 0, 0, 0 | 0 |

## Reproduction and retained scope

Use source `55de85cb`, the exact cases in
`paper/parameters.rs` (`../../benchmarks/tfhe/benches/sparse_paper/parameters.rs`, historical source)
and the q-to-Q-to-q adapter in
`paper/request.rs` (`../../benchmarks/tfhe/benches/sparse_paper/request.rs`, historical source).
The temporary consumer uses their unchanged numerical operations and the
existing public generator:

```rust
let choice = BlindRotationConfig::Sparse {
    copy_count: r,
    bucket_count: buckets,
};
let server = KeyGenerator::new(&context)
    .try_generate_server_key(&client, choice, None, &mut server_rng)?;
let mut evaluator = context.evaluator(&server)?;
```

For the matching screen, support seed is `0x4b31_0000 + support_index` and map
seed is `0x4b32_0000 + support_index*maps_per_support + map_index`, using
`rand 0.10.3` / `StdRng`. Sample exactly h indices with `rand::seq::index::sample`
and sort them. Instrument the existing eight-attempt sampler in a temporary
copy to count all attempts and verify against the unchanged public API; do not
resample the support when a graph fails. The independent oracle uses recursive
augmenting paths with a bucket-visited array. The screen and oracle use the
128x64 and 8x32 grids stated above, including all configurations in the table.

For timing, use client seed 42, server seed 4242 and input seed 43, as in the
existing paper benchmark. Use the full configuration table's order on CPU 4
and reverse it for the second pass; CPU 8 starts with the reverse order. Cache
the fixture across Criterion callbacks, then allocate the chosen evaluator or
raw BR workspace before `b.iter`. Keep `complete_ring_return` and
`blind_rotation` separate, with the unchanged public BR kernel; only fix the
diagnostic control count to `r*n+B`. Criterion 0.8 uses the settings above.

For the eight-key validation/resource corpus, key trial t uses client seed
`42+t` and server seed `4242+100*t`. The eight input seeds are
`43, 4343, 43002, 43003, 43004, 43005, 43006, 43007`. Record failures as well
as successful keys; check the actual public map against the traced matcher.
Error maxima and pooled RMS come from all messages, not just timed input one.
The temporary live-byte allocator and online allocation counter are enabled
only for the corresponding untimed diagnostics.

Existing focused checks also pass on this source: the two private matcher/retry
tests, the public invalid-map boundary test, the direct-phase/classic BR oracle,
and three sparse PBS tests covering both orders and zero-allocation composition.
These seven tests are unchanged; no complete workspace test run or nightly SIMD
run is implied by this experiment.

```sh
cargo test -p primus_tfhe --lib sparse
cargo test -p primus_tfhe --test sparse
cargo test -p primus_tfhe_glwe_ntt --test sparse_blind_rotation --test sparse_pbs
```

The experimental consumer, copied matcher, allocator, scan and measurement
artifacts are removed after recording these results. There is no new production
strategy/API, dependency, ordinary test, benchmark target or CI parameter grid.
Unmeasured scope includes other machines, nightly SIMD performance, Fourier,
NTRU and CBS/one-hot/LUT with the candidate parameters. Changes to decomposition
or noise belong to a separate experiment; complete consumer acceptance follows
only after the mathematical and numerical conditions for that consumer hold.

The subsequent [decomposition study](sparse-decomposition-measurements.md) fixes
the retained r2/B=2h candidate, derives the complete phase-error budget and
compares explicit BR/KS level counts at unchanged noise. It records latency,
memory and separated phase errors without promoting default parameters.
