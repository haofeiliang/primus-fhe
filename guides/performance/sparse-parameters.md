# Sparse parameters: matching, decomposition and consumers

[Performance guide](README.md) · [Arithmetic choices](sparse-arithmetic.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks)

These GLWE NTT studies were measured on 2026-10-05 using numerical source
`55de85cb`. They change parameters, not arithmetic kernels. Their useful result
is a set of **consumer-specific research candidates**, not current security or
decryption-failure-rate (DFR) recommendations. Historical STD128/MEDIUM names
identify workloads; their security labels do not transfer to the adaptations.

| Historical candidate | Evidence and limit |
| --- | --- |
| Two replicas, B=2h | Faster and smaller than r3/B=h+3 at fixed decomposition in the measured profiles; matching and public-graph conditioning still need attention. |
| STD128 BR b7/L3, r2/B86 | Lower BR cost with similar measured output RMS; passed PBS, ManyLUT, MVB and feedback checks. The tested 28-bit CBS output still failed. |
| Function BR b27/L1, r2/B140 | Half the BR payload; passed the tested three-bit function consumers. This is not high-precision lookup evidence. |
| Same function BR with CBS output b2/L5 | Passed the tested CBS→CMux corpus; b8/L2 output failed. Its output basis, trace and scheme-switch budget are part of the result. |

The detailed historical tables are available in Git at `a00d6faf`. This report
retains the conditions, principal comparisons and counterexamples; raw probes,
per-request captures and temporary candidate binaries are not preserved here.
No new performance experiment or parameter change accompanies this consolidation.

## Fixed domains and measurement scope

Here n is the external secret dimension, h its fixed binary weight, N the ring
length, q the external modulus and Q the ring modulus. All profiles use GLWE k=1
and a uniform ternary ring secret. `b/L/d` denotes base log, retained levels and
dropped bits. Explicit q uses `PowOf2Modulus`; Q uses `BarrettModulus`.

| Historical workload | n / h / N | q / Q | Original r / B | Original BR b/L/d | Ring KS b/L/d |
| --- | --- | --- | --- | --- | --- |
| STD128 NAND | 1024 / 43 / 1024 | 512 / 268369921 | 3 / 46 | 7/4/0 | 7/4/0 |
| MEDIUM NAND | 1024 / 31 / 1024 | 512 / 268369921 | 3 / 34 | 10/2/8 | 7/4/0 |
| Padded three-bit function | 2048 / 70 / 2048 | 4096 / 18014398509404161 | 3 / 73 | 27/2/0 | 5/10/4 |

Input, BR-key and ring-KS samplers each use sigma=3.19 in their own coefficient
domain. Input encryption happens at q; the context's rescaled Q-domain sigma
is not used to sample those inputs. Complete requests include q→Q lifting, BR,
ring KS at Q, extraction and Q→q return. This is a historical adapter around
the GLWE backend, not its ordinary same-modulus workflow. See the
[paper comparison](sparse-paper-comparison.md#parameters-and-comparison-boundary)
for the adaptation boundary. Gates were tested with u32/u64; Q54 requires u64.

Timing used a Ryzen 9 9955HX3D, Rust 1.98.1, release/default features and repository
native CPU flags. CPU 4/8 belong to the 96/32 MiB L3 groups. Each configuration
ran in fresh processes, forward then reverse on CPU 4 and the opposite order on
CPU 8. Criterion used 40 Flat samples, 0.5 s warmup and a 2 s target. One iteration
was one complete request; setup, validation and reusable allocations were outside
timing. CPU results are compared within each core. Neither cross-core latency
nor separately timed BR/complete differences establish a cache or KS-cost cause.

## Matching and conditional distribution

The [bucket sampler](../../crates/primus_tfhe/src/sparse.rs) gives each of all n
input indices r distinct uniformly selected buckets. Only the public map is
resampled after failure, at most eight times; the secret is unchanged.
`B >= max(r,h)` is necessary, not sufficient, for matching. Online evaluation
still processes all r*n selectors and B dummies, including encrypted zeros.

The graph screen used 128 independently sampled fixed-weight supports and 64 map
seeds per support: 8,192 retry sequences for each configuration, with failures
included. A smaller independent augmenting-path oracle agreed with the production
BFS matcher on the sampled retry sequences. The main alternatives were:

| Profile | r / B | First-map failures / 8192 | All-eight failures / 8192 | Mean attempts |
| --- | --- | ---: | ---: | ---: |
| STD128 | 3 / 46 | 3318 | 5 | 1.669 |
| STD128 | 3 / 54 | 22 | 0 | 1.003 |
| STD128 | 2 / 86 | 627 | 0 | 1.081 |
| STD128 | 2 / 108 | 124 | 0 | 1.016 |
| MEDIUM | 3 / 34 | 1750 | 0 | 1.266 |
| MEDIUM | 3 / 39 | 36 | 0 | 1.004 |
| MEDIUM | 2 / 62 | 567 | 0 | 1.075 |
| MEDIUM | 2 / 78 | 96 | 0 | 1.012 |
| Function | 3 / 73 | 6261 | 983 | 3.752 |
| Function | 3 / 88 | 4 | 0 | 1.000 |
| Function | 2 / 140 | 740 | 0 | 1.099 |
| Function | 2 / 175 | 107 | 0 | 1.013 |
| n728/h32 diagnostic | 3 / 64 | 0 | 0 | 1.000 |
| n728/h32 diagnostic | 2 / 64 | 598 | 0 | 1.079 |

Failed sequences count as eight attempts in the mean. Smaller grids were rejected:
r3/B=h exhausted retries in 4872/2170/7631 sequences for STD128/MEDIUM/function;
r2/B=h+3 failed in 8109/7093/8192. Intermediate r2/B=ceil(1.5h) also failed in
27/3/255 sequences. Weight h alone therefore does not specify a usable map.

Function r3/B73 had 76.43% first-map failure and 12.00% all-eight failure under
this sampler. These are **key-generation failures**, not decryption failures of
accepted keys. At r2/B=2h, observed first-map failure was 6.92%–9.03%; increasing
B to ceil(2.5h) reduced it to 1.17%–1.51%. Zero all-eight failures in 8,192 trials
has a one-sided 95% binomial upper bound of about 0.0366%, not a cryptographic
tail bound. Under independent maps the failure probability is epsilon^8;
substituting observed epsilon supplies an estimate, not a proof.

### What acceptance conditions on

Let S be a fixed-weight support, H an initially sampled public graph and A(S,H)
the existence of a matching. Under ideal independent uniform sampling,
input-index symmetry makes p=Pr[A(S,H)] depend on n,h,r,B rather than which
support S was chosen. Conditional on returning a graph within eight attempts:

```text
P(H | S, accepted) = P(H) * 1[A(S,H)] / p.
```

The retry cap changes the error probability, not this returned distribution.
S remains uniform marginally, but S and published H are correlated: incompatible
supports are excluded. The accepted joint distribution has likelihood ratio 1/p
relative to independent (S,H), on its accepted set. Using observed p, log2(1/p)
is about 0.749/0.347/2.085 for the original profiles, 0.104–0.137 for r2/B=2h,
and 0.017–0.022 for r2/B=ceil(2.5h). These are conditioning diagnostics, not
certified computational-security losses or per-graph entropy guarantees.
Similar bucket occupancy histograms do not establish independence from S.

### Fixed-basis cost tradeoff

At unchanged BR/KS bases and noise, r2/B=2h was fastest among the tested choices.
The table gives complete-request reductions relative to r3/B=h+3, comparing the
average of two process means on each CPU; ranges span the two CPUs.

| Profile / word | Latency reduction |
| --- | ---: |
| STD128 / u32 | 26.4%–30.9% |
| STD128 / u64 | 22.1%–22.3% |
| MEDIUM / u32 | 31.5%–45.1% |
| MEDIUM / u64 | 23.9%–26.1% |
| Function / u64 | 15.7%–17.0% |

The coefficient-key payload is `(r*n+B)*(k+1)^2*L_BR*N*sizeof(T)`. It fell by
31%–32%, with similar observed keygen reductions and unchanged evaluator size
at fixed basis. Keygen observations were medians of eight constructions,
including map retries; they were not Criterion confidence estimates. More
buckets add dummy keys and external products. r2/B=ceil(2.5h) traded some speed
for fewer retries; r3/B=ceil(1.25h) improved matching without a repeatable latency
gain. Classic was not retimed, so this is not a sparse/classic speedup result.

## Decomposition and error budget

The next study held r2/B=2h, domains, secrets and sampler settings fixed while
changing explicit BR/KS bases. Write beta=2^b, L for retained levels and
`d=bit_width(Q)-b*L` for these odd Q values. The
[approximate signed basis](../../crates/primus_decompose/src/primitive/basis.rs)
uses at most floor(bit_width(Q)/b) levels. Balanced digits are in
`[-beta/2,beta/2)`; circular reconstruction error is bounded by
`epsilon(d)=0` for d=0, otherwise `2^(d-1)`. Keep BR and KS bases independent.

All following error terms use integer lifts in Q units before modular reduction,
unless scaled by rho=q/Q. The fixed sigma=3.19 sampler has support at most 38 in
magnitude; its actual discrete variance v is not assumed to equal sigma squared.

### Input selection, bucket errors and return

For these ordinary PBS adapters, q divides 2N and q→Q lifting preserved every
mask/body q→2N exponent; the historical input corpus checked this equality.
Input noise can still select the wrong LUT interval. The q-space half intervals
are 64 for NAND and 128 for the function. Function input support 38 fits; NAND
adds two encrypted inputs, whose worst support sum 76 does not fit. An ideal
Gaussian approximation with deviation sqrt(2)*3.19 is not a CDT tail proof.
Once selection is correct, input noise is not a further additive output error.
The fixed-prime NTT contributes no Fourier approximation term.

For ring secret S, define `phi_S(a,b)=b-a*S`, `S1=sum(abs(S_i))` and decomposition
residual R by `C=Reconstruct(D)+R`. Bucket j encrypts monomial M_j or 1 and has
m_j selectors plus a dummy. Its phase identity is:

```text
phi_S(C_j) = M_j*phi_S(C_{j-1}) - M_j*phi_S(R_j)
             + sum_{row,level} D_j,row,level * E_j,row,level.
```

M_j is a signed coefficient permutation. In the centered independent fresh-row
model, aggregate error variance is `(m_j+1)*v`; conditional on the prior
accumulator and public exponents, the fresh contribution has variance
`(m_j+1)*v*sum(||D_j,row,level||_2^2)`. Digits depend on prior errors, so this is
not independence conditional on the whole future decomposition sequence.
With fresh coefficient bound Emax=38, conservative deterministic bounds are:

```text
E_BR <= B*epsilon_BR*(1+S1)
        + (r*n+B)*Emax*(k+1)*L_BR*N*beta_BR/2.
E_KS <= epsilon_KS*S1 + Emax*k*L_KS*N*beta_KS/2.
```

Here `sum_j(m_j+1)=r*n+B`, including all dummies. Fewer copies reduce one noise
term; more buckets add residual terms and approximate external products. Neither
count fixes actual digit energy. For uniform ternary S, S1<=kN is deterministic,
whereas E[S1]=2kN/3 is only an average. The initially trivial accumulator can
have lower digit energy than this bound assumes.

Ring KS decomposes only the mask, preserving the body. Its phase change is
`R_a*S_in - sum D_KS*E_KS`. Extraction adds no arithmetic error. Nearest Q→q
rounding under the returned weight-h binary secret gives:

```text
E_out = rho*(E_BR + E_KS) + delta_encoding + eta_b - sum_i s_i*eta_a_i,
|eta_b - sum_i s_i*eta_a_i| <= (h+1)/2.
```

In this identity E_BR/E_KS are signed errors; the earlier inequalities bound
their magnitudes. `delta_encoding` includes LUT encoding and NAND bias, using
actual odd Q rather than a power-of-two substitute. Correctness requires both
correct input selection and total error below the output radius 64 or 128 at q.
The worst fresh-error bound above is too loose to certify even the originals.
Measured stage RMS values can correlate and need not add in quadrature.

### Conditional fresh-key bound

A stronger historical bound fixes an input **independent of evaluation-key
noise** and models RNG words as independent uniform words. For the
[CDT sampler](../../crates/primus_distr/src/discrete_gaussian/cdt.rs), magnitude
and sign share a u64 word. Their tiny possible mean satisfies
`|mu| <= sum(1..=38)/2^64`, since each magnitude's word interval has at most
one odd/even imbalance. Account for this mean as drift.

Bucket digits depend only on earlier buckets. Hoeffding's bounded-variable mgf
bound can therefore compose across fresh bucket errors and independent KS rows,
with fixed monomial transport to the final coefficient. In q units:

```text
Vmax = rho^2 * 38^2 * [
  (r*n+B)*(k+1)*L_BR*N*(beta_BR/2)^2 + k*L_KS*N*(beta_KS/2)^2
].
drift <= rho*|mu| * [
  (r*n+B)*(k+1)*L_BR*N*beta_BR/2 + k*L_KS*N*beta_KS/2
].
```

Let a be the output radius minus decomposition, encoding, final-rounding and
drift allowances. Conditional on correct selection and a>0, the bound is
`min(1, 2*exp(-a^2/(2*Vmax)))`. The tested LUTs allow conservative encoding error
`2*rho`. For function r2/B140, BR b27/L1 and original KS, sqrt(Vmax)=2.41525 and
a=88.1229 at q; drift is below 1.1e-14, and input support 38<128 covers selection.
This is a conditional fresh-randomness argument, not a guarantee for every fixed
key, finite-seed RNG security, or adaptive/feedback requests reusing row errors.
The gate bounds remain too loose and require separate input-selection analysis.

### Ranking model and candidate tradeoffs

The finite screen also used a heuristic: uniform balanced digits, centered
uniform residuals and v≈3.19^2. Its Q-unit fresh variances are:

```text
V_BR ≈ (r*n+B)*(k+1)*L_BR*N*beta_BR^2*v/12,
V_KS ≈ k*L_KS*N*beta_KS^2*v/12.
```

Add residual estimates `B*(1+2kN/3)*2^(2d_BR)/12` and
`(2kN/3)*2^(2d_KS)/12` only where d>0. Scale by rho^2, then add `(h+1)/12` for
final rounding. These independence/uniformity assumptions rank candidates;
small measured RMS does not validate their tails.

The following comparisons use the **retimed r2 baseline with original BR basis**,
not r3. KS remains at its original basis. Latency reductions span measured CPUs
and words; residual bounds use S1<=N and include BR+KS decomposition only.

| Profile / candidate BR b/L/d | Full-request result | Error/storage tradeoff |
| --- | --- | --- |
| STD128 7/3/7 | 25.6%–35.3% lower latency | 25% less BR payload; output RMS 2.031–2.037 at q; residual allowance 10.763 |
| STD128 10/2/8 | 50.5%–69.9% lower latency | Half BR payload; RMS 5.359–5.922; residual allowance 21.526 |
| STD128 9/3/1 | Similar payload to 7/3, variable timing | RMS 3.928–3.988 but residual allowance only 0.16817; not the primary candidate |
| MEDIUM 9/2/10 | No consistent gain across CPUs | Same payload; RMS falls from 5.370–5.652 to 3.067–3.267, but residual allowance rises from 15.519 to 62.076 against radius 64 |
| MEDIUM 7/3/7 | Slower, lower-error control | 50% more BR payload; RMS 1.746–1.785; residual allowance 7.7595 |
| Function 27/1/27 | 48.3%–49.9% lower latency | Half BR payload and 64 KiB less evaluator space; RMS 2.402; residual allowance 4.3771 |
| Function 25/1/29 | Similar timing to 27/1 | Lower fresh BR error, larger residual allowance 17.509; final rounding still dominates RMS 2.480 |

A one-level Q28 gate b14/L1 was screened out before key generation: modeled SD
near 60 approached radius 64. Smaller KS controls saved only 8 KiB (u32 gate)
or 128 KiB (function), with larger but still small KS error; they did not justify
changing the main KS choice. Separately measured raw BR also shifted in the
function's KS-only control, so small total changes were not attributed to KS
arithmetic. Original KS randomness differed from the first r/B study; the
adjacent r2 baselines above were regenerated and retimed rather than borrowed.

## Complete consumers and output scales

Consumer comparisons kept r2/B86 or r2/B140 and changed only original versus
candidate BR decomposition. They measured BR→KS order. STD128 inputs m=0,1 use
plaintext modulus 4 and functions `(m xor 1, m, 1)`; function inputs m=0..7 use
plaintext modulus 16 and `((m*m+3*m+1) mod 8, (m+1) mod 8, m xor 3)`.
All outputs use the same fixed-scale encoding. The complete workloads are:

| Historical workload ID | Timed work |
| --- | --- |
| `single` | One ordinary PBS for f0; STD128 is unary NOT, not the earlier NAND workload |
| `independent3` | Three ordinary PBSes |
| `many3` | One interleaved BR and three returns, padded width four |
| `factorized3` | One BR, three public factor products and their returns |
| `cbs` / `cbs_cmux` | Gadget generation alone / generation plus encrypted-ring CMux; results stay at Q |

CBS has one-bit input with plaintext modulus 4. The two independently encrypted
CMux candidates use Scaled modulus 4, with coefficients `i mod 4` and
`(3*i+1) mod 4`. No Q→q return follows CBS or CMux.

### Resolution, factor norms and feedback

For interleaving step s, coefficient-wise quantization determines the phase:

```text
R_s(x) = s * round(x * (2N/s) / Q),
exponent = -R_s(b) + sum_i secret_i*R_s(a_i) mod 2N.
```

Rounding the decrypted phase once misses this error. An integer oracle checked
the actual lift and signed LUT coefficient for each fresh input/output. With
STD128 s=4, `2N/s=q=512`, so lifted coefficients preserve the original q-grid.
For function s=4, quantization contributes at most 2 q-units per public
coefficient; worst phase allowance `2*(h+1)=142` already exceeds the three-bit
half interval 128 before input noise. Finite successful ManyLUT requests are
therefore not a worst-case selection guarantee.

Factorized MVB satisfies `V*W_i=delta*p_i`; only the noiseless public V uses
modular division by two. Its BR error becomes `W_i*e_BR`, then each output adds
its KS/return errors. Deterministic amplification is at most
`||W_i||_1*||e_BR||_infinity`; outputs share BR error rather than independent
noise. The factors' `(L1, squared L2)` norms were `(2,2),(2,2),(2,4)` for STD128
and `(26,140),(14,56),(20,104)` for the function.

Feedback fed returned ciphertexts into the next operation under the same key,
without fresh encryption: ordinary and NAND chains ran 32 rounds; ManyLUT/MVB
ran 16, feeding output `round mod 3` forward. This exercises key-dependent inputs
outside the fresh-key bound above, but does not certify arbitrary circuits.

### CBS projection and CMux budget

For output scalar g_l, the body row targets `g_l*m` and mask row r targets
`-g_l*m*S_r`, including zero tails. Every coefficient and level matters. Checking
only ordinary PBS decoding does not resolve the smallest gadget scale.

In the tested odd-Q full reverse trace, automorphisms run in ascending order
`3,5,9,...,N+1`. A suffix of normalized `(Id+Auto_(1+2^j))/2` operators expands
over its subgroup once, projecting onto a coefficient subset. It preserves the
selected BR error coefficients; it does not shrink them by ordinary division.
The independent monomial check used N=32/64. This property concerns the ordered
full projection, not arbitrary modular halving or Fourier/torus rounding.

If A_j is an automorphism-KS error, projected error includes the selected BR
coefficient plus remaining suffix projections of A_j. Scheme switching adds
its own decomposition/key errors and multiplies the projected phase by `-S_r`
for mask rows. Shared trace/scheme-switch keys do not supply independent errors
across levels or requests. The diagnostic checked that projected raw BR matched
the complete CBS body row, separating these effects.

For CMux with bit m, decompose the candidate difference with residual R:

```text
phi(selected) = (1-m)*phi(lhs) + m*phi(rhs) - m*phi(R)
                + sum_{row,level} D_row,level * E_CBS,row,level.
```

The residual allowance is `epsilon_output*(1+||S||_1)`; the last term is bounded
by `sum(||D_row,level||_1*||E_CBS,row,level||_infinity)` without independence.
An error/scalar threshold alone is not a CMux theorem, so the study also checked
all selected polynomial coefficients and their phase distance.

| Geometry / result | Output b/L/d | Smallest scalar | Trace and scheme-switch b/L/d | Their sigma |
| --- | --- | ---: | --- | ---: |
| Q28, rejected | 3/3/19 | 524288 | 2/14/0 | 6.4 |
| Q54, rejected screen | 8/2/38 | 274877906944 | 8/6/6 | 6.4 |
| Q54, passed finite corpus | 2/5/44 | 17592186044416 | 8/6/6 | 6.4 |

The five-level output pads to s=8. Its one-bit input half interval is 512 q-units,
exceeding fresh support plus quantization allowance `38+4*(70+1)=322`. This does
not give the same support bound for PBS-produced inputs; those were checked
separately. BR/KS sigma remained 3.19, and trace/scheme-switch sigma remained
6.4 across the comparisons; no noise reduction produced the positive result.

### Numerical outcomes and failures

The copy/bucket corpus covered 128 keys and 5,120 complete requests; decomposition
covered 192 keys and 7,424 requests. All decoded correctly. Consumer validation
used 24 evaluation-key bundles (four trials per configuration): 14,464 complete
PBS/ManyLUT/MVB workloads passed 22,912 returned-output checks, including feedback.
These are fixed, paired inputs, not independent DFR trials. No key generation
failed in these smaller corpora; that does not erase graph-screen failures.

The largest absolute errors at q across original/candidate bases were:

| Geometry | Fresh independent PBS | Fresh ManyLUT | Fresh MVB | Feedback, all tested paths |
| --- | ---: | ---: | ---: | ---: |
| STD128 | 6 | 6 | 8 | 9 |
| Function | 9 | 8 | 10 | 12 |

These observations stay below output radii 64/128 in this corpus. Larger function
factor norms raised MVB error even while decoding passed.

**The tested Q28 CBS failed with both original and candidate BR bases.** Counts
below are wrong CMux coefficients, not request-failure probabilities. Every
input/LUT selection was correct.

| Word / BR b/L | Maximum raw-BR error / scalar | Maximum CBS-row error / scalar | Wrong CMux coefficients / checked |
| --- | ---: | ---: | ---: |
| u32 / 7/4 | 2.181 | 2.388 | 30153 / 65536 |
| u32 / 7/3 | 2.122 | 2.338 | 26325 / 65536 |
| u64 / 7/4 | 2.170 | 2.406 | 29069 / 65536 |
| u64 / 7/3 | 2.008 | 2.212 | 26683 / 65536 |

Q54 b8/L2 output also failed: four calls at trial zero gave 3169/8192 wrong
CMux coefficients with BR b27/L2, and 1422/8192 with b27/L1. The candidate's raw
error reached 2.111 times the smallest scalar before projection. These are
unsuitable parameter combinations, not missing sparse CBS support.

With Q54 output b2/L5, all 128 CBS→CMux requests passed: 262,144 selected-ring
coefficients and 2,621,440 GGSW coefficients were checked. Every row/level error
was below one eighth of its scalar in this corpus. For BR b27/L2 versus b27/L1,
maximum CMux error/Q was 0.046215 versus 0.044403, below radius/Q=0.125;
RMS/Q was 0.008222 versus 0.007932. These observed margins do not certify a
universal bound for another output basis or consumer.

### Complete-request benefit and storage

The consumer study retimed original/candidate bases at the same r2 configuration.
Each cell below gives CPU 4 / CPU 8 latency reductions from the average of two
process means. These are parameter changes, not arithmetic gains at fixed keys.

| Geometry / word | single | independent3 | many3 | factorized3 | CBS→CMux |
| --- | ---: | ---: | ---: | ---: | ---: |
| STD128 / u32 | 39.40% / 25.77% | 39.12% / 25.99% | 40.77% / 25.64% | 37.04% / 25.73% | Rejected |
| STD128 / u64 | 26.67% / 24.77% | 26.69% / 24.89% | 26.68% / 25.32% | 26.74% / 25.24% | Rejected |
| Function / u64 | 49.10% / 48.79% | 49.07% / 48.77% | 49.43% / 48.87% | 48.71% / 47.85% | 46.13% / 44.55% |

STD128/u32 CPU 4 varied more: original many3 means were 5.806/6.465 ms. Both
runs are included; the larger apparent gain is not a portable 40% claim. The
successful CBS→CMux pair used output b2/L5 on both sides: original means ranged
23.255–23.562 ms on CPU 4 and 23.021–23.355 on CPU 8; candidate means were
12.597–12.624 and 12.756–12.960. Rejected CBS outputs were not timed as successes.

Reducing BR levels cuts its coefficient payload by 25% for STD128 and 50% for
the function. In the historical allocation measurements, evaluator storage
fell by 16/32 KiB for STD128 u32/u64 and 64 KiB for the function. The function's
five-level GGSW output alone was 327,680 caller-owned bytes; trace/scheme-switch
material did not shrink. These are requested storage sizes, not RSS or current
workspace measurements. The lower-cost BR does not remove the rest of the
consumer's memory and error budget.

## Evidence and reuse limits

All studies used rand 0.10.3 `StdRng`. The graph screen held each support fixed
while trying new maps, including failures. Its support/map seeds were
`0x4b31_0000+t` and `0x4b32_0000+t*64+j`. Cryptographic trial t used client
seed `42+t` and BR/server seed `4242+100*t`. Decomposition and consumer studies
used independent ring-KS seed `84242+100*t`; consumer circuit/candidate seeds
were `924242+100*t` / `564242+t`. The initial r/B study used the sequential server
RNG convention. Timing restored trial-zero input seed 43 after validation.

Each r/B or decomposition configuration checked eight key trials and eight input
seeds, over all four NAND pairs or eight function inputs. Consumers used four
key trials and fresh input seeds `43,4343,43002,43003`, plus the feedback chains
above; CBS checked both bits freshly encrypted and after identity PBS/return.
These conditions explain the finite evidence. Reconstructing an old comparison
requires the recorded revision and its complete fixture, not only these seeds.

Historical `sparse_candidate_r2` IDs identified the selected r2 PBS parameter
instances, not another blind-rotation algorithm or a universal CBS/LUT preset.
They are not current executable targets. Current workloads are documented in
the [benchmark guide](../development/testing.md#tfhe-benchmarks); current user
flows and encoding contracts are in the [operation guide](../../crates/primus_tfhe/README.md)
and [numerical guide](../development/bootstrapping-contracts.md).

The consumer study did not promote STD128 b10/L2, MEDIUM alternatives, other
backends, other output scales or high-precision lookup. NTRU one-hot and lookup
need their own secret, trace, factor, quantization and return budgets. Sparse
support and suitability of a parameter set are separate facts; the fresh-key
bound above does not certify repeated adaptive requests under a fixed key.
