# Sparse decomposition choices at fixed copies, buckets and noise

Measured on 2026-10-05, using numerical source `55de85cb`. This follows the
[fixed-decomposition r/B screen](sparse-parameter-measurements.md): r=2, B=2h
is the working candidate, with the original r=3, B=h+3 retained as a control.
There is no new graph scan, layout or kernel change. Q/q, n/h/N, secret families,
LUTs, the q-to-Q-to-q adapter and sigma=3.19 for every role stay fixed. NAND and
the padded three-bit function still use the distinct complete workloads in the
[paper comparison](sparse-paper-comparison.md#parameters-and-comparison-boundary).

Production APIs, default parameters, benchmark registrations and CI cases are
unchanged. This is a cost/error tradeoff study, not a security parameter preset.
Existing parameter fields already express every tested basis; independent BR/KS
noise configuration is not needed for this experiment.

The function's 54-bit width refers to its ciphertext modulus Q; its programmable
input domain remains three bits. All latency reductions below compare with the
matching r2/B=2h basis from the previous step, retimed in this experiment.

| Retained research choice | Complete-request result across measured words/CPUs | Main tradeoff |
| --- | --- | --- |
| STD128 BR b7/L3, drop 7 | 25.6–35.3% lower latency | 25% fewer BR coefficient bytes; output RMS remains about 2.03 at q |
| STD128 BR b10/L2, drop 8 | 50.5–69.9% lower latency | Half the BR payload; output RMS grows to 5.36–5.92 at q |
| Function BR b27/L1, drop 27 | 48.3–49.9% lower latency | Half the BR payload, 64 KiB less evaluator space; final modulus switching still dominates RMS |
| MEDIUM BR b9/L2, drop 10 | No consistent speedup across cores | Unchanged payload; output RMS falls from 5.37–5.65 to 3.07–3.27, with a larger worst-case remainder allowance |

The b7/L3 STD128 choice and b27/L1 function choice are the main candidates for
consumer-specific validation. Faster or lower-RMS alternatives retain their
explicit error tradeoffs; finite successful requests do not establish a security
level or a decryption-failure probability. The original KS choices are retained
for the next main comparison.

## Error budget before timing

All quantities below are in Q-coefficient units until multiplied by rho=q/Q.
Phase identities are modulo Q; the error bounds use integer lifts of their
noise terms before reduction.
Write beta=2^b for the gadget radix, L for the retained level count, and
`d = bit_width(Q) - b*L`. The repository's
[`ApproxSignedBasis`](../../crates/primus_decompose/src/primitive/basis.rs)
retains floor(bit_width(Q)/b) levels at most; specifying fewer levels drops
additional low bits. It is not OpenFHE's ceil-width exact digit convention.
The reconstructed coefficient has circular residual at most
`epsilon(d) = 0 if d=0, otherwise 2^(d-1)`, and digits lie in `[-beta/2,beta/2)`.
The non-power-of-two adjustment and low-to-high carry protocol remain unchanged.

### Input selection and exact NTT arithmetic

Inputs are encrypted at q, using sigma=3.19; the actual sampler's declared
truncated support is at most 38 in magnitude. The q-to-Q adapter preserves
every mask/body q-to-2N exponent exactly because q divides 2N in these cases;
this equality is checked for every measured input. Input noise still changes
the selected LUT point: NAND adds two encrypted inputs, while the function
uses one. The minimum distance to a LUT transition, in q units, is 64 for
NAND and 128 for the padded function. Once selection stays in the correct
constant interval, input noise does not add linearly to the output phase error.

The function's 38 bound fits its input interval. NAND's worst-case sum bound
is 76, so this truncation bound alone cannot guarantee selection; the ideal
independent Gaussian approximation has standard deviation sqrt(2)*3.19, but
that is not a tail proof for the implemented finite-precision CDT. The experiment
checks actual phase selection separately from output decoding. No input, BR-key
or KS-key sampler is changed. NTT arithmetic at the fixed primes is exact and
contributes no Fourier-style approximation term.

### Bucket external products

For ring secret S and GLWE C=(a,b), let `phi_S(C)=b-a*S`. Decompose every
component, and define the residual vector R by `C=Reconstruct(D)+R` modulo Q.
Bucket j encrypts a monomial M_j (or 1) and has m_j public selectors plus a dummy.
The existing external product satisfies

```text
phi_S(C_j) = M_j*phi_S(C_{j-1})
             - M_j*phi_S(R_j) + sum_{row,level} D_j,row,level * E_j,row,level.
```

M_j is a signed permutation of coefficients, with norm one; it does not amplify
previous error. Every aggregate error polynomial E is a sum of m_j+1 independently
generated row-error polynomials, with public monomial rotations. In the centered
independent-row model, its coefficient variance is (m_j+1)*v. The newly injected
error coefficient, conditional on the prior accumulator and public exponents,
has variance `(m_j+1)*v*sum(||D_j,row,level||_2^2)`. Digit polynomials depend on
prior errors, so this does not assert independence after conditioning on the
whole sequence of future decompositions.

Let S1 be the sum of absolute ring-secret coefficients. The deterministic
per-bucket residual bound is `epsilon_BR*(1+S1)`. If each fresh row coefficient
is bounded by Emax=38, the fresh-error bound is
`(m_j+1)*Emax*sum(||D_j,row,level||_1)`. Thus a conservative BR bound is

```text
E_BR <= B*epsilon_BR*(1+S1)
        + (r*n+B)*Emax*(k+1)*L_BR*N*beta_BR/2.
```

No selector or dummy is removed. The initial trivial accumulator has zero mask,
which can lower its actual digit energy; the displayed bound covers all buckets.
For the uniform ternary ring secret, S1<=k*N is a deterministic bound, while
E[S1]=2*k*N/3 is only a distributional average.

### Ring KS, extraction, encoding and final modulus switch

Ring KS decomposes the accumulator's mask only, preserving its body. With R_a
as its mask residual, its exact phase change is

```text
phi_out - phi_in = R_a*S_in - sum_{row,level} D_KS,row,level * E_KS,row,level.
```

The remainder bound is `epsilon_KS*S1`; fresh variance conditional on the input
is `v_KS*sum(||D_KS||_2^2)`, and the fresh-error bound is
`Emax*k*L_KS*N*beta_KS/2`. Sample extraction changes representation without adding
arithmetic error. The output secret is the original fixed-weight binary secret
of weight h. For nearest coefficient modulus switching, each rounding residual
eta has absolute value at most 1/2, giving

```text
E_out = rho*(E_BR + E_KS) + delta_encoding + eta_b - sum_i s_i*eta_a_i,
|eta_b - sum_i s_i*eta_a_i| <= (h+1)/2.
```

`delta_encoding` includes the actual LUT value and NAND bias before conversion,
and the q-codec's expected encoding. Its exact integer numerator is checked,
rather than assuming that the odd Q equals a power of two. The output decoding
radii are 64 and 128 at q. A sufficient correctness condition combines correct
input selection with the sum of the deterministic BR/KS, encoding and final
rounding bounds being below the corresponding output radius. The worst-case
fresh-error bound is too loose to certify even the original profiles: this
experiment does not establish a cryptographic decryption-failure probability.

### Conditional fresh-key bound

A stronger bound for a fixed input independent of evaluation-key noise can use
the sampler's finite support without assuming uniform digits or Gaussian tails.
Model RNG words as independent uniform words. For this sigma the
[CDT sampler](../../crates/primus_distr/src/discrete_gaussian/cdt.rs) has support
[-38,38]; its shared magnitude/sign word can introduce a tiny mean. Every
magnitude occupies a contiguous interval of u64 words, whose odd/even counts
differ by at most one, so `|mu| <= sum(1..=38)/2^64`. Include that mean as a
deterministic drift rather than assuming exact centering.

Within each bucket, digits depend only on earlier buckets. Hoeffding's bounded
variable mgf bound therefore composes across the fresh row errors, and then the
independently generated KS rows. Monomial transport to the final output
coefficient is fixed by the input/support, not by these errors. A deterministic
variance proxy for the centered fresh part, in q units, is

```text
Vmax = rho^2 * 38^2 * [
    (r*n+B)*(k+1)*L_BR*N*(beta_BR/2)^2
    + k*L_KS*N*(beta_KS/2)^2
].

drift <= rho*|mu| * [
    (r*n+B)*(k+1)*L_BR*N*beta_BR/2
    + k*L_KS*N*beta_KS/2
].
```

If a is the output radius minus the deterministic decomposition, encoding,
final-rounding and mean-drift allowances, `a>0` gives the conditional bound
`Pr[output error] <= min(1, 2*exp(-a^2/(2*Vmax)))`, provided input selection is
correct. For these LUTs, use the conservative encoding allowance `2*rho`:
the NAND scale/bias differs from its ideal Q encoding by less than two, and
the function uses nearest Q encoding; their expected encodings at q are exact.
For the function r2/B140 b27/L1 with original KS, `sqrt(Vmax)=2.4153`
and `a=88.1229` at q; its drift allowance is below 1.1e-14. Input selection is
also covered by 38<128. This supplies a useful bounded-noise argument for the
one-level experiment; the bound is too loose for the gate candidates, whose
input-selection probability also needs separate treatment.

This probability is over fresh evaluation-key randomness in the stated ideal
RNG model. It is not a guarantee for every fixed key, a security estimate for
the finite-seed RNG, or a bound for arbitrary adaptive/chained requests reusing
the same row errors. Those dependencies must be considered when a consumer
feeds key-dependent results back into another operation.

### Model used to rank the finite candidates

For ranking only, approximate balanced digits as uniform and dropped residuals
as centered uniform rounding noise. At k=1 the fresh contributions are

```text
V_BR,fresh ≈ (r*n+B)*(k+1)*L_BR*N*beta_BR^2*v/12,
V_KS,fresh ≈ k*L_KS*N*beta_KS^2*v/12.
```

The residual model adds `B*(1+2*k*N/3)*2^(2*d_BR)/12` and
`(2*k*N/3)*2^(2*d_KS)/12`, omitting a term when its d is zero. Scale their sum
and fresh variances by rho^2, then add `(h+1)/12` for final modulus rounding.
Use v=3.19^2 as a numerical approximation, not an exact property of the CDT.
These independence, centering and uniform-digit assumptions need not hold for
all accumulator states or repeated inputs; measured stage RMS is checked against
them, and finite successes cannot certify a tail bound or transfer paper security
labels to the candidates.

This screen admits a few cost/accuracy tradeoffs, not a new default parameter
set. A one-level 28-bit gate with base log 14 predicts much larger error and is
not generated. At 54 bits, one retained level with base log 27 halves BR payload
while leaving a modest deterministic residual allowance after scaling to q.
Base log 25 keeps one level, trading still smaller fresh noise for a larger
residual bound. MEDIUM's two-layer base log 9 is tested as a noise tradeoff,
although its conservative residual bound alone nearly consumes the output radius;
its good RMS must not be interpreted as a worst-case guarantee.

## Candidate screen

BR and KS columns show `base log / retained levels / dropped bits`. Identical
arithmetic choices share this preflight table across u32/u64. The remainder
column bounds BR plus KS decomposition residuals at q, using S1<=N. It excludes
fresh-key noise, encoding and final rounding; it is **not** an output-error bound.
Final rounding adds a deterministic allowance of 22, 16 or 35.5 for STD128,
MEDIUM or the function. The model SD uses the assumptions above. No bound is
inferred from a small measured RMS.

| Profile | r / B | BR b/L/d | KS b/L/d | Model output SD at q | Decomposition remainder bound at q |
| --- | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND | 3 / 46 | 7/4/0 | 7/4/0 | 2.227 | 0 |
| STD128 NAND | 2 / 86 | 7/4/0 | 7/4/0 | 2.133 | 0 |
| STD128 NAND | 2 / 86 | 7/3/7 | 7/4/0 | 2.081 | 10.763 |
| STD128 NAND | 2 / 86 | 9/3/1 | 7/4/0 | 3.778 | 0.16817 |
| STD128 NAND | 2 / 86 | 10/2/8 | 7/4/0 | 5.653 | 21.526 |
| MEDIUM NAND | 3 / 34 | 10/2/8 | 7/4/0 | 6.621 | 8.5104 |
| MEDIUM NAND | 2 / 62 | 10/2/8 | 7/4/0 | 5.535 | 15.519 |
| MEDIUM NAND | 2 / 62 | 9/2/10 | 7/4/0 | 3.110 | 62.076 |
| MEDIUM NAND | 2 / 62 | 7/3/7 | 7/4/0 | 1.823 | 7.7595 |
| Padded function | 3 / 73 | 27/2/0 | 5/10/4 | 2.441 | 3.7253e-09 |
| Padded function | 2 / 140 | 27/2/0 | 5/10/4 | 2.438 | 3.7253e-09 |
| Padded function | 2 / 140 | 27/1/27 | 5/10/4 | 2.435 | 4.3771 |
| Padded function | 2 / 140 | 25/1/29 | 5/10/4 | 2.433 | 17.509 |
| STD128 NAND | 2 / 86 | 7/3/7 | 9/3/1 | 2.081 | 10.765 |
| Padded function | 2 / 140 | 27/1/27 | 9/6/0 | 2.435 | 4.3771 |

At r=2/B=2h, the discarded one-level gate b14/L1 choice predicts SD near 60 at q,
already close to the radius 64; no encrypted key or timing run is spent on it.
The complete deterministic fresh-error bounds for the measured rows are much
larger than the decoding radii, including the original profiles. They remain
useful for stating contracts, not for certifying a practical failure rate here.

## Validation and separated phase errors

Twenty-four configurations have eight client/server-key trials each and eight
input seeds per key: **192 keys, 7,424 complete requests**, including all four
NAND pairs or all eight function messages. All decode and LUT-selection checks
pass, every q-to-Q-to-2N public exponent agrees, and each key passes an additional
zero-allocation online request. These are fixed, paired inputs across choices;
they are not 7,424 independent draws from a ciphertext failure distribution.
No key generation failed in this finite corpus; the earlier graph-screen failure
rates, particularly h70/r3/B73, remain applicable.

An untimed second raw BR on each input exposes the accumulator's coefficient-zero
phase under its ring secret. Its error is measured against the independently
computed direct-phase LUT coefficient, with the negacyclic sign. Decrypting the
ordinary returned LWE at Q then isolates the ring-KS phase change. Finally an
exact i128 calculation checks the modulus-switch identity and its `(h+1)/2`
bound, including the actual encoding/bias numerator. This diagnostics pass and
its scratch are outside the benchmark and evaluator memory measurements.

The table scales BR and KS error to q for comparison; RMS combines all seeds
for that row. Output max/RMS includes the final conversion. Different components
can correlate, so their RMS values need not add in quadrature. Maximum input
phase errors observed are 12 for u32 gates, 7 for u64 gates and 6 for the function;
these are corpus observations, not sampler support bounds.

| Profile / word | r / B | BR b/L/d | KS b/L/d | BR RMS at q | KS RMS at q | Final rounding RMS | Output max / RMS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 7/4/0 | 7/4/0 | 1.132 | 0.01402 | 1.858 | 8 / 2.207 |
| STD128 NAND / u32 | 2 / 86 | 7/4/0 | 7/4/0 | 0.9512 | 0.01474 | 1.899 | 9 / 2.127 |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 7/4/0 | 0.8525 | 0.01422 | 1.863 | 6 / 2.037 |
| STD128 NAND / u32 | 2 / 86 | 9/3/1 | 7/4/0 | 3.328 | 0.01223 | 1.811 | 11 / 3.988 |
| STD128 NAND / u32 | 2 / 86 | 10/2/8 | 7/4/0 | 5.58 | 0.01452 | 2.090 | 22 / 5.922 |
| MEDIUM NAND / u32 | 3 / 34 | 10/2/8 | 7/4/0 | 6.835 | 0.01462 | 1.632 | 18 / 6.976 |
| MEDIUM NAND / u32 | 2 / 62 | 10/2/8 | 7/4/0 | 5.045 | 0.01373 | 1.646 | 16 / 5.370 |
| MEDIUM NAND / u32 | 2 / 62 | 9/2/10 | 7/4/0 | 2.6 | 0.01497 | 1.727 | 12 / 3.267 |
| MEDIUM NAND / u32 | 2 / 62 | 7/3/7 | 7/4/0 | 0.8327 | 0.01416 | 1.594 | 6 / 1.746 |
| STD128 NAND / u64 | 3 / 46 | 7/4/0 | 7/4/0 | 1.15 | 0.01443 | 1.979 | 6 / 2.281 |
| STD128 NAND / u64 | 2 / 86 | 7/4/0 | 7/4/0 | 0.8583 | 0.01482 | 1.875 | 6 / 2.008 |
| STD128 NAND / u64 | 2 / 86 | 7/3/7 | 7/4/0 | 0.8042 | 0.01399 | 1.802 | 5 / 2.031 |
| STD128 NAND / u64 | 2 / 86 | 9/3/1 | 7/4/0 | 3.343 | 0.01475 | 1.894 | 13 / 3.928 |
| STD128 NAND / u64 | 2 / 86 | 10/2/8 | 7/4/0 | 5.057 | 0.01416 | 1.921 | 17 / 5.359 |
| MEDIUM NAND / u64 | 3 / 34 | 10/2/8 | 7/4/0 | 6.377 | 0.01405 | 1.542 | 21 / 6.316 |
| MEDIUM NAND / u64 | 2 / 62 | 10/2/8 | 7/4/0 | 5.586 | 0.01482 | 1.761 | 15 / 5.652 |
| MEDIUM NAND / u64 | 2 / 62 | 9/2/10 | 7/4/0 | 2.593 | 0.01489 | 1.498 | 10 / 3.067 |
| MEDIUM NAND / u64 | 2 / 62 | 7/3/7 | 7/4/0 | 0.8845 | 0.01475 | 1.534 | 5 / 1.785 |
| Padded function / u64 | 3 / 73 | 27/2/0 | 5/10/4 | 0.1977 | 9.574e-10 | 2.460 | 10 / 2.449 |
| Padded function / u64 | 2 / 140 | 27/2/0 | 5/10/4 | 0.1666 | 9.89e-10 | 2.431 | 8 / 2.426 |
| Padded function / u64 | 2 / 140 | 27/1/27 | 5/10/4 | 0.1166 | 9.574e-10 | 2.402 | 7 / 2.402 |
| Padded function / u64 | 2 / 140 | 25/1/29 | 5/10/4 | 0.0337 | 9.947e-10 | 2.480 | 10 / 2.480 |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 9/3/1 | 0.8525 | 0.04768 | 1.923 | 6 / 2.095 |
| Padded function / u64 | 2 / 140 | 27/1/27 | 9/6/0 | 0.1166 | 1.187e-08 | 2.440 | 8 / 2.443 |

These measurements distinguish two useful choices for STD128: b7/L3 preserves
roughly the original output RMS while reducing BR payload by one quarter;
b10/L2 halves payload but raises output RMS. The b9/L3 control has the same
payload as b7/L3 and substantially larger measured fresh error, trading that
for a much smaller worst-case decomposition remainder; it is not selected as
the next cost/accuracy candidate.

MEDIUM b9/L2 reduces BR RMS without shrinking the key. Its weaker deterministic
remainder allowance still needs attention in any consumer budget. The b7/L3
control lowers RMS further at the cost of 50% more BR payload. The function
b27/L1 cuts payload in half while final modulus switching dominates observed
output RMS. Lowering that one level to b25 reduces fresh BR noise further,
but increases the deterministic residual allowance and does not remove the
modulus-switch contribution.

The KS controls reduce only 8 KiB of key in the u32 gate and 128 KiB in the
function. Their measured KS error grows but remains small relative to final
rounding. This does not motivate reducing KS noise or introducing a new noise API.

## Complete request and raw blind rotation

AMD Ryzen 9 9955HX3D; rustc/cargo 1.98.1; release, stable/default features and
repository `target-cpu=native`. CPU 4 and CPU 8 belong to the 96/32 MiB L3 groups.
Twenty configurations are timed in fresh processes, with setup and allocation
outside both `bench_function` and `b.iter`. Each iteration executes one operation.
Criterion uses 40 flat samples, 0.5 s warmup and a 2 s measurement target.

CPU 4 runs the table order and then its reverse; CPU 8 reverses this sequence.
Complete requests precede raw BR in each process. No compiler, second benchmark
or validation corpus runs concurrently. Cells show the range of two run means,
followed by the envelope of their individual 95% intervals in brackets. This
envelope is not a newly estimated cross-run confidence interval. There is no
performance-counter evidence for a particular cache mechanism.

### One complete q-to-q request

| Profile / word | r / B | BR b/L/d | KS b/L/d | CPU 4 ms | CPU 8 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 7/4/0 | 7/4/0 | 8.259–8.293 [8.201–8.376] | 8.829–8.851 [8.762–8.955] |
| STD128 NAND / u32 | 2 / 86 | 7/4/0 | 7/4/0 | 5.596–5.612 [5.555–5.672] | 6.446–6.458 [6.395–6.527] |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 7/4/0 | 3.622–3.636 [3.592–3.664] | 4.788–4.808 [4.749–4.865] |
| STD128 NAND / u32 | 2 / 86 | 9/3/1 | 7/4/0 | 3.618–3.647 [3.597–3.684] | 4.794–5.546 [4.757–5.793] |
| STD128 NAND / u32 | 2 / 86 | 10/2/8 | 7/4/0 | 1.658–1.720 [1.652–1.729] | 3.149–3.161 [3.113–3.199] |
| MEDIUM NAND / u32 | 3 / 34 | 10/2/8 | 7/4/0 | 2.930–2.937 [2.898–2.987] | 4.303–4.347 [4.267–4.408] |
| MEDIUM NAND / u32 | 2 / 62 | 10/2/8 | 7/4/0 | 1.584–1.657 [1.580–1.665] | 2.999–2.999 [2.971–3.040] |
| MEDIUM NAND / u32 | 2 / 62 | 9/2/10 | 7/4/0 | 1.578–1.615 [1.571–1.626] | 2.993–3.015 [2.968–3.049] |
| MEDIUM NAND / u32 | 2 / 62 | 7/3/7 | 7/4/0 | 3.395–3.418 [3.369–3.451] | 4.652–4.957 [4.612–5.011] |
| STD128 NAND / u64 | 2 / 86 | 7/4/0 | 7/4/0 | 9.781–9.877 [9.733–10.014] | 10.387–10.427 [10.314–10.531] |
| STD128 NAND / u64 | 2 / 86 | 7/3/7 | 7/4/0 | 7.178–7.195 [7.140–7.257] | 7.745–7.748 [7.693–7.821] |
| STD128 NAND / u64 | 2 / 86 | 10/2/8 | 7/4/0 | 4.632–4.696 [4.593–4.732] | 5.124–5.173 [5.083–5.223] |
| MEDIUM NAND / u64 | 2 / 62 | 10/2/8 | 7/4/0 | 4.061–4.262 [4.035–4.440] | 4.714–4.749 [4.680–4.806] |
| MEDIUM NAND / u64 | 2 / 62 | 9/2/10 | 7/4/0 | 4.016–4.019 [3.988–4.060] | 4.718–4.719 [4.684–4.769] |
| Padded function / u64 | 3 / 73 | 27/2/0 | 5/10/4 | 25.977–26.021 [25.826–26.230] | 25.621–26.007 [25.428–26.527] |
| Padded function / u64 | 2 / 140 | 27/2/0 | 5/10/4 | 21.371–21.482 [21.266–21.613] | 21.219–21.360 [21.093–21.510] |
| Padded function / u64 | 2 / 140 | 27/1/27 | 5/10/4 | 10.704–10.770 [10.653–10.844] | 10.986–11.017 [10.915–11.105] |
| Padded function / u64 | 2 / 140 | 25/1/29 | 5/10/4 | 10.810–10.833 [10.759–10.918] | 10.935–11.082 [10.882–11.204] |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 9/3/1 | 3.589–3.616 [3.568–3.645] | 4.782–4.840 [4.752–4.897] |
| Padded function / u64 | 2 / 140 | 27/1/27 | 9/6/0 | 10.619–10.658 [10.573–10.725] | 10.946–11.015 [10.892–11.098] |

### One raw BR

| Profile / word | r / B | BR b/L/d | KS b/L/d | CPU 4 ms | CPU 8 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 7/4/0 | 7/4/0 | 8.246–8.357 [8.181–8.440] | 8.867–8.880 [8.761–8.997] |
| STD128 NAND / u32 | 2 / 86 | 7/4/0 | 7/4/0 | 5.723–5.748 [5.684–5.805] | 6.506–6.511 [6.460–6.586] |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 7/4/0 | 3.679–3.750 [3.653–3.801] | 4.852–4.856 [4.806–4.919] |
| STD128 NAND / u32 | 2 / 86 | 9/3/1 | 7/4/0 | 3.703–3.707 [3.673–3.743] | 4.836–4.887 [4.797–4.949] |
| STD128 NAND / u32 | 2 / 86 | 10/2/8 | 7/4/0 | 1.733–1.774 [1.725–1.784] | 3.176–3.199 [3.149–3.236] |
| MEDIUM NAND / u32 | 3 / 34 | 10/2/8 | 7/4/0 | 2.856–2.865 [2.832–2.895] | 4.283–4.291 [4.240–4.358] |
| MEDIUM NAND / u32 | 2 / 62 | 10/2/8 | 7/4/0 | 1.570–1.647 [1.566–1.658] | 2.982–2.993 [2.956–3.028] |
| MEDIUM NAND / u32 | 2 / 62 | 9/2/10 | 7/4/0 | 1.582–1.623 [1.572–1.635] | 2.983–3.031 [2.958–3.096] |
| MEDIUM NAND / u32 | 2 / 62 | 7/3/7 | 7/4/0 | 3.359–3.429 [3.341–3.462] | 4.608–4.689 [4.571–4.740] |
| STD128 NAND / u64 | 2 / 86 | 7/4/0 | 7/4/0 | 9.816–9.819 [9.740–9.911] | 10.428–10.979 [10.359–11.087] |
| STD128 NAND / u64 | 2 / 86 | 7/3/7 | 7/4/0 | 7.201–7.235 [7.146–7.351] | 7.736–7.747 [7.684–7.815] |
| STD128 NAND / u64 | 2 / 86 | 10/2/8 | 7/4/0 | 4.447–4.469 [4.417–4.509] | 5.078–5.094 [5.041–5.162] |
| MEDIUM NAND / u64 | 2 / 62 | 10/2/8 | 7/4/0 | 4.019–4.208 [3.996–4.332] | 4.693–4.712 [4.654–4.754] |
| MEDIUM NAND / u64 | 2 / 62 | 9/2/10 | 7/4/0 | 3.995–4.020 [3.971–4.054] | 4.710–4.761 [4.676–4.849] |
| Padded function / u64 | 3 / 73 | 27/2/0 | 5/10/4 | 25.474–25.554 [25.327–25.782] | 25.222–25.505 [25.031–25.770] |
| Padded function / u64 | 2 / 140 | 27/2/0 | 5/10/4 | 21.268–21.388 [21.182–21.496] | 21.215–21.411 [21.051–21.616] |
| Padded function / u64 | 2 / 140 | 27/1/27 | 5/10/4 | 10.663–10.698 [10.616–10.764] | 10.952–11.085 [10.871–11.159] |
| Padded function / u64 | 2 / 140 | 25/1/29 | 5/10/4 | 10.682–10.738 [10.636–10.837] | 10.918–10.996 [10.861–11.112] |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 9/3/1 | 3.670–3.674 [3.643–3.708] | 4.843–4.859 [4.815–4.912] |
| Padded function / u64 | 2 / 140 | 27/1/27 | 9/6/0 | 10.447–10.470 [10.377–10.538] | 10.794–10.838 [10.739–10.935] |

Comparisons of decomposition below use the corresponding **r2/B=2h baseline**,
not the earlier r3 result, and average the two complete-request means per CPU.
The original r3 rows separately show the combined copies-plus-decomposition
change. Classic, Fourier, NTRU, CBS/one-hot/LUT and nightly SIMD performance are
not retimed in this experiment.

| Working r2 profile | Candidate BR | CPU 4 latency reduction | CPU 8 latency reduction |
| --- | ---: | ---: | ---: |
| STD128 NAND / u32 | 7/3/7 | +35.25% | +25.63% |
| STD128 NAND / u32 | 9/3/1 | +35.18% | +19.87% |
| STD128 NAND / u32 | 10/2/8 | +69.86% | +51.10% |
| MEDIUM NAND / u32 | 9/2/10 | +1.47% | -0.17% |
| MEDIUM NAND / u32 | 7/3/7 | -110.24% | -60.22% |
| STD128 NAND / u64 | 7/3/7 | +26.88% | +25.57% |
| STD128 NAND / u64 | 10/2/8 | +52.55% | +50.53% |
| MEDIUM NAND / u64 | 9/2/10 | +3.47% | +0.27% |
| Padded function / u64 | 27/1/27 | +49.89% | +48.32% |
| Padded function / u64 | 25/1/29 | +49.50% | +48.29% |

The STD128/u32 b9/L3 CPU 8 complete runs vary from 4.794 to 5.546 ms;
MEDIUM/u32 b7/L3 varies from 4.652 to 4.957 ms. The raw-BR STD128/u64 baseline
also varies on CPU 8. These observations remain in the tables rather than being
removed as outliers; the primary b7/L3 and b27/L1 decisions do not rely on them.

Raw BR and complete requests use distinct reusable workspaces and call sites.
They are separately timed workloads: their difference is not a measurement of
KS cost. In particular, the function's smaller-KS control also shifts the raw-BR
time although its BR key and numerical work are unchanged. Its small complete
latency change cannot be attributed to faster KS arithmetic from these results.

## Key generation and storage

Each resource row uses the same eight-key corpus on CPU 4. Keygen time is the
median of untimed-setup wall-clock observations, including all internal matching
retries, independent BR/KS RNG setup and generation workspaces, excluding the
already prepared context/client and returned-key drop. These times do not have
Criterion confidence intervals. An untimed public BucketMap replay confirms the
actual generated map; it is outside the construction measurement.

Heap columns count incremental requested live bytes and peak, not traffic, RSS
or stack. Server retained/peak and evaluator retained/peak are measured in
separate scopes; the evaluator's retained and construction peak are equal in
these cases. Values below are the maximum across the eight keys. Caller input,
output, LUT and diagnostic buffers are excluded. BR coefficient bytes are exactly
`(r*n+B)*(k+1)^2*L_BR*N*sizeof(T)`; no material or dummy is omitted.

| Profile / word | r / B | BR b/L/d | KS b/L/d | BR MiB | KS KiB | Server retained / peak bytes | Evaluator bytes | Keygen median ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| STD128 NAND / u32 | 3 / 46 | 7/4/0 | 7/4/0 | 194.875 | 32 | 204399064 / 204431832 | 133120 | 254.65 |
| STD128 NAND / u32 | 2 / 86 | 7/4/0 | 7/4/0 | 133.375 | 32 | 139903768 / 139936536 | 133120 | 175.06 |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 7/4/0 | 100.031 | 32 | 104940300 / 104981260 | 116736 | 130.54 |
| STD128 NAND / u32 | 2 / 86 | 9/3/1 | 7/4/0 | 100.031 | 32 | 104940300 / 104981260 | 116736 | 130.93 |
| STD128 NAND / u32 | 2 / 86 | 10/2/8 | 7/4/0 | 66.688 | 32 | 69976832 / 70009600 | 100352 | 85.96 |
| MEDIUM NAND / u32 | 3 / 34 | 10/2/8 | 7/4/0 | 97.062 | 32 | 101835104 / 101867872 | 100352 | 126.11 |
| MEDIUM NAND / u32 | 2 / 62 | 10/2/8 | 7/4/0 | 65.938 | 32 | 69190208 / 69222976 | 100352 | 85.29 |
| MEDIUM NAND / u32 | 2 / 62 | 9/2/10 | 7/4/0 | 65.938 | 32 | 69190208 / 69222976 | 100352 | 85.15 |
| MEDIUM NAND / u32 | 2 / 62 | 7/3/7 | 7/4/0 | 98.906 | 32 | 103760460 / 103801420 | 116736 | 129.13 |
| STD128 NAND / u64 | 3 / 46 | 7/4/0 | 7/4/0 | 389.750 | 64 | 408773176 / 408838712 | 256000 | 353.03 |
| STD128 NAND / u64 | 2 / 86 | 7/4/0 | 7/4/0 | 266.750 | 64 | 279790456 / 279855992 | 256000 | 242.01 |
| STD128 NAND / u64 | 2 / 86 | 7/3/7 | 7/4/0 | 200.062 | 64 | 209863520 / 209945440 | 223232 | 182.24 |
| STD128 NAND / u64 | 2 / 86 | 9/3/1 | 7/4/0 | 200.062 | 64 | 209863520 / 209945440 | 223232 | 181.65 |
| STD128 NAND / u64 | 2 / 86 | 10/2/8 | 7/4/0 | 133.375 | 64 | 139936584 / 140002120 | 190464 | 122.48 |
| MEDIUM NAND / u64 | 3 / 34 | 10/2/8 | 7/4/0 | 194.125 | 64 | 203645352 / 203710888 | 190464 | 175.24 |
| MEDIUM NAND / u64 | 2 / 62 | 10/2/8 | 7/4/0 | 131.875 | 64 | 138363528 / 138429064 | 190464 | 119.89 |
| MEDIUM NAND / u64 | 2 / 62 | 9/2/10 | 7/4/0 | 131.875 | 64 | 138363528 / 138429064 | 190464 | 119.31 |
| MEDIUM NAND / u64 | 2 / 62 | 7/3/7 | 7/4/0 | 197.812 | 64 | 207504032 / 207585952 | 223232 | 178.88 |
| Padded function / u64 | 3 / 73 | 27/2/0 | 5/10/4 | 777.125 | 320 | 815252336 / 815481712 | 380928 | 746.13 |
| Padded function / u64 | 2 / 140 | 27/2/0 | 5/10/4 | 529.500 | 320 | 555582856 / 555812232 | 380928 | 509.26 |
| Padded function / u64 | 2 / 140 | 27/1/27 | 5/10/4 | 264.750 | 320 | 277972336 / 278201712 | 315392 | 254.04 |
| Padded function / u64 | 2 / 140 | 25/1/29 | 5/10/4 | 264.750 | 320 | 277972336 / 278201712 | 315392 | 254.96 |
| STD128 NAND / u32 | 2 / 86 | 7/3/7 | 9/3/1 | 100.031 | 24 | 104932096 / 104960768 | 116736 | 130.65 |
| Padded function / u64 | 2 / 140 | 27/1/27 | 9/6/0 | 264.750 | 192 | 277841168 / 278005008 | 315392 | 254.20 |

## Reproduction and retained decision

Start at `55de85cb` and reuse the exact numerical operations in
[`paper/parameters.rs`](../../crates/primus_tfhe_glwe_ntt/benches/paper/parameters.rs)
and [`paper/request.rs`](../../crates/primus_tfhe_glwe_ntt/benches/paper/request.rs).
Set both `DecompositionConfig` fields explicitly with the b/L pairs in the tables;
keep them independent even when their base logs are equal. Do not let `None`
silently choose a different level count. Request setup, warmup and validation
remain outside every timed iteration.

```rust
let br = generator.try_generate_sparse_blind_rotation_key(
    &client, copy_count, bucket_count, &mut br_rng,
)?;
let ks = generator.try_generate_glwe_key_switching_key(&client, &mut ks_rng)?;
let server = ServerKey::new(BlindRotationKey::Sparse(br), ks, None);
```

Use rand 0.10.3 StdRng: trial t has client seed `42+t`, BR seed `4242+100*t`,
and **independent KS seed `84242+100*t`**. This fixes returned key material when
BR choices change; equal checksums across all matching word/profile/KS-basis/trial
rows corroborate the deterministic construction. This KS seed differs from the
prior r/B experiment, so its historical timings are not the adjacent baseline.
Keep failed generation attempts in the corpus rather than replacing the client.

Each key validates input seeds `43,4343,43002,43003,43004,43005,43006,43007`.
The timing fixture uses trial zero and restores seed 43, message one (both inputs
for NAND) after validation. Use the complete timing table order for CPU 4's first
pass and reverse it for the second; CPU 8 starts in reverse. Criterion 0.8 uses
`--sample-size 40 --warm-up-time 0.5 --measurement-time 2`, with `taskset -c 4`
or `taskset -c 8`. Each process runs complete and raw-BR stages separately.

Keep STD128 b7/L3 as the lower-error cost candidate and b10/L2 as the faster,
larger-error alternative. Keep the function b27/L1 as the main payload candidate;
b25/L1 adds a residual tradeoff but final rounding still limits observed RMS.
MEDIUM b9/L2 is an accuracy candidate with unchanged payload; b7/L3 is a slower,
lower-error control. Retain the original KS basis for the next main comparison
unless that consumer specifically needs the small KS storage saving.

Before promoting any choice, the actual consumer must establish its output
scale and error allowance, including interleaved rotation resolution, gadget
levels, factors or projection as applicable. Other backends need their own
arithmetic and noise analysis. The matching/security conditioning limits from
the preceding r/B screen are unchanged. No default, benchmark or example
parameter is automatically replaced by these successful finite samples.

Existing focused validation also passes: five primitive decomposition-oracle
tests and four GLWE NTT sparse BR/PBS tests. No new ordinary tests are added,
and no full-workspace or nightly SIMD run is implied.

```sh
cargo test -p primus_decompose --test primitive_approx_signed_basis_oracle
cargo test -p primus_tfhe_glwe_ntt --test sparse_pbs --test sparse_blind_rotation
```

The temporary consumer, phase instrumentation, allocator and scan/timing outputs
are removed after recording the results. No new production strategy, dependency,
ordinary test or benchmark target is retained.

The subsequent [consumer validation](sparse-consumer-measurements.md) checks
ManyLUT resolution, factor amplification, feedback and CBS→CMux. It retains
specific PBS benchmark candidates and a separate 54-bit CBS output basis;
the tested 28-bit PBS choices do not pass the tested CBS consumer.
