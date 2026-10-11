# Bootstrapping numerical contracts

Use the [operation guide](../../crates/primus_tfhe/README.md) to choose a workflow and the [parameter guide](tfhe-parameters.md) for experimental configurations. This guide connects the numerical conditions across compilation, blind rotation, CBS and high-precision lookup. Method-level layouts, checks and scratch contracts remain in rustdoc. These conditions do not provide a security estimate or failure-probability certificate.

All polynomial operations below use the negacyclic ring `R_Q = Z_Q[X]/(X^N+1)`. N is a supported power of two; q denotes the external LWE modulus and Q the accumulator modulus. Native moduli mean `2^T::BITS`. Input/output plaintext moduli can differ. Error magnitudes use centered representatives; identities modulo Q alone are not real-valued noise bounds.

## Rotation geometry

For canonical x, define the ties-up quantizer

```text
R(x,q,L) = floor((x*L + floor(q/2))/q) mod L.
E_q(m)  = round(m*q/t_in) mod q.
```

Compilation uses `R(E_q(m),q,L)`, not `round(m*L/t_in)`. The two rounds can move a center: with N=32, q=5, t_in=3, m=1 and L=2N, encoding gives 2 and the center is 26; rounding the ideal fraction directly gives 21. See [rotation modulus switching](../../crates/primus_tfhe/src/rotation.rs).

For k interleaved outputs, let s be `next_power_of_two(k)` and H=N/s. Output j occupies coefficients `s*r+j`; each programmed input interval repeats its k encoded outputs followed by s-k zero lanes. H is the number of positions per output, not a repetition count for one message. Compilation places centers in 2H positions. It programs a front-half prefix of length `D<=ceil(t_in/2)` and appends the terminal center `min(R(E_q(D),q,2H),H)` carrying the negative of output zero's group. Each position takes the nearest center, ties going to the larger center; the remaining tail is not another valid input domain. All centers, including the terminal one, must increase strictly. `D<=H` is necessary capacity, not a noise-margin guarantee. See [front-half intervals](../../crates/primus_tfhe/src/lookup_table/compile/front_half.rs).

Execution instead quantizes each LWE coordinate at step s:

```text
R_s(x) = s*R(x,q,2N/s)
u_bar  = R_s(b) - sum_i R_s(a_i)*secret_i
ACC    = X^(-u_bar)*T.
```

Quantizing the decrypted phase once is not equivalent. Because s divides N, negacyclic wrapping preserves the output lane. The physical 2N must fit the coefficient word even for Native inputs. Ordinary PBS/MVB use step one; CBS/one-hot use their padded gadget width. Input error budgets must include encoding rounding and coordinate-wise quantization in addition to fresh encryption noise.

For an odd full domain `t_in=2h+1`, fold centers modulo N and negate upper-half outputs. The sorted input order is `0,h+1,1,h+2,...,h`; append N with `-F(0)`. Boundaries are `ceil((left+right)/2)`, and collisions of actual rounded centers are rejected. Typical spacing is N/t_in, about half the front-half spacing. This is a single-output entry; interleaved and bivariate compilation retain front-half contracts. See [odd-domain folding](../../crates/primus_tfhe/src/lookup_table/compile/odd_full_domain.rs).

## Ciphertext domains and return

| Path | Domain relationship |
| --- | --- |
| GLWE PBS | External LWE, accumulator and output share the ciphertext modulus. PBS order determines which secret/dimension enters BR and where KS occurs. |
| NTRU PBS and lookup | Independent external secret s at q and ring secret f at Q. Return performs coefficient-wise nearest Q→q rounding, signed phase extraction, then LWE KS at q. |
| Raw LUT compilation | Input q and coefficient Q can be independent; output encoding is a separate choice. |
| Bivariate LUT | Its constructor currently requires a common ciphertext modulus. |

For GLWE, let n be the small BR-control dimension and kN the flattened ring-secret dimension, with `n<=kN`. `BootstrapKeyswitch` accepts and returns the small-secret LWE: BR precedes ring KS and compact extraction. `KeyswitchBootstrap` accepts and returns the flattened-ring-secret LWE: inverse extraction, ring KS and compact extraction prepare the small input for BR, followed by full extraction. Equal ciphertext moduli do not make these external domains interchangeable.

Returning a phase rescales its existing centers; it does not recreate the output codec's centers. Include coefficient rounding multiplied by the extraction secret, KS error and encoding-scale mismatch in the output budget. For example, a Scaled output requires accounting for `(q/Q)*round(Q/t_out) - round(q/t_out)`. ManyLUT shares the conversion across extracted outputs; MVB converts each factor product. See [GLWE orders](../../crates/primus_tfhe_glwe/README.md) and [NTRU returns](../../crates/primus_tfhe_ntru/README.md#ntrulwe-returns).

All configured noise standard deviations use coefficient units, including Fourier configurations. BR and KS noise are independent choices; NTRU return KS uses q while BR uses Q. CBS trace/scheme-switch rows inherit accumulator encryption noise but have separate decompositions and error propagation. In GLWE KS→BR, fresh external LWE encryption uses the ring/BR noise setting, not KS-key noise. These sampler deviations describe fresh private-key encryption or individual key rows; public-key encryption includes additional public-key and combination errors. The [GLWE](../../crates/primus_tfhe_glwe/README.md#parameters-and-external-key-domain) and [NTRU](../../crates/primus_tfhe_ntru/README.md) family guides identify the configuration fields.

## Ternary and sparse rotation

Classic ternary represents a secret coordinate by mutually exclusive bits s_plus and s_minus. For its quantized mask exponent a, combine gadget controls as `G=Enc(s_plus)-X^(-a)*Enc(s_minus)`. Adding the external product of G with `(X^a-1)*ACC` implements rotation by `X^(a*(s_plus-s_minus))`. This saves an external product but retains both control ciphertexts' errors. NTT combination is exact in the field; Fourier adds its transform/conversion error.

Sparse BR uses a public map with c distinct bucket choices per input position and a private matching with at most one selected position per bucket. For bucket C_j,

```text
G_j = Dummy_j + sum_{i in C_j} X^a_i * Selector_(j,i).
```

The independently encrypted dummy represents one minus the sum of that bucket's selector bits. An unused bucket therefore targets the identity monomial, not zero. Encrypted zero selectors and the dummy still contribute noise. Under independent centered row errors of variance sigma², each coefficient of the aggregate row has variance `(|C_j|+1)*sigma²`; differing bucket sizes require an appropriate bound, not just their average. This local variance calculation does not establish the full BR tail distribution. Mapping and matching are defined in [sparse.rs](../../crates/primus_tfhe/src/sparse.rs).

Retrying the public map until matching succeeds conditions the published map on the fixed secret admitting a matching. It reduces generation failure without removing that correlation. Only the independent NTRU ring secret is conditioned on invertibility and, for Fourier, inverse stability; the external fixed-weight secret may have even weight. Conditioned secret/map distributions and evaluation-key KDM/circular-security assumptions require separate analysis. Matching, rejection sampling and inverse preparation have no constant-time guarantee.

## NTRU first lifting

Write the NTRU phase as `f*C = message + error`. NLEV[mu] has rows with phase `g_l*mu + e_l`; NGSW[mu] has rows targeting `g_l*f*mu`. For gadget decomposition define

```text
epsilon(P) = P - sum_l g_l*D_l(P).
```

Classic BR starts from the public polynomial `P=T*X^(-b)` with quantized b, and fuses lifting with coordinate zero:

```text
K = I + (X^a-1)*B_plus + (X^(-a)-1)*B_minus
C = sum_l D_l(P)*K_l.
```

I is NLEV[1], the B controls are NLEV secret bits, and binary omits B_minus. K targets `H=X^(a*secret_0)`, so the phase is `P*H - epsilon(P)*H + sum_l D_l(P)*e_l(K)`. Only P is approximately decomposed: a small monomial difference is not discarded by that decomposition. If a=0, K=I still performs the required lift.

Sparse BR uses the first bucket's NLEV aggregate K_0 instead. The same phase formula holds with H equal to the selected monomial, or one for an unoccupied bucket. Even an empty first bucket lifts through its encrypted dummy. Later coordinates/buckets use NGSW on encrypted accumulators; NGSW's extra f factor prevents substituting it for this public-polynomial lift. MVB, CBS and one-hot use the same BR initialization. See the [NTRU family](../../crates/primus_tfhe_ntru/README.md#sparse-coefficient-keys).

## Ordinary CBS and consumption

Ordinary CBS programs a front-half Rounded input domain with gadget-scaled values `g_l*F(m)`, projects the resulting coefficients into GLev/NLev rows, and can scheme-switch to GGSW/NGSW. The result remains under the accumulator secret, without an ordinary output message codec or LWE return. GLWE KS→BR still performs input KS before this flow. The ManyLUT accumulator may have a nonzero message tail, so prefix expansion requiring a zero tail cannot replace its projections.

For CMux consumption, F must be bit-valued over the entire programmed domain. Candidate ciphertexts must share the accumulator secret, modulus and encoding. Matching output lengths does not establish that BR decomposition resolves the LUT's smallest gadget scale or that the resulting control's noise fits its consumer. See [CBS compilation and consumption](../../crates/primus_tfhe/README.md#cbs-output-and-consumption).

NTRU scheme-switch material binds the complete output basis. GLWE material binds output layout and supports a different output basis only through the evaluator's checked compatibility entry. Neither check proves actual secret or transform identity. See [GLWE CBS](../../crates/primus_tfhe_glwe/README.md#boolean-and-cbs) and [NTRU CBS](../../crates/primus_tfhe_ntru/README.md#cbs-and-examples).

## One-hot CBS

Let the chunk radix be `M=2^tau`, with input message modulus t=2M. Input m uses unsigned Rounded encoding `round(q*m/(2M))`. If L is the output gadget level count, set `W=next_power_of_two(L)`, `S=N/M` and `A=N/(2MW)`; require `2MW<=N`. Padding levels are zero. The test polynomial is

```text
T = sum_{j=1-A}^{A} sum_{l=0}^{L-1} g_l*X^(l-jW).
```

BR quantization uses step W, not MW. If its actual quantized phase satisfies `u_bar=S*m+W*e mod 2N` with `-A<=e<A`, negative BR followed by `X^(rS-l)` and full normalized reverse trace targets `g_l*delta_r(m)`. The guard is left-closed/right-open: a midpoint belongs to the larger message. e includes input encryption, encoding and coordinate-quantization errors. N and gadget capacity checks cannot prove this guard. See [OneHotLookupTable](../../crates/primus_tfhe_ntru/src/one_hot.rs).

Full reverse trace targets a constant without assuming a zero message tail. Partial reverse trace retains a subring polynomial; prefix coefficient expansion yields independent constants only when the target plaintext is zero outside that prefix. Requesting fewer outputs does not establish this premise, nor does a plaintext zero tail imply zero ciphertext/noise tails.

| Backend | Trace normalization and error |
| --- | --- |
| NTT | Multiply canonical residues by `2^-1 mod Q`, requiring odd Q below `2^(T::BITS-1)`. This is not rounded integer division or independent real-noise halving. Late automorphism-KS errors can remain outside the target coefficients. |
| Fourier | Apply unsigned `floor(c/2)` to coefficients, including wrapped negative representatives, before automorphism. Never divide Fourier complex values by two. Coefficient parity/rounding error enters the phase multiplied by f; account for f's norm, subsequent trace maps, FFT and KS errors. Parity errors need not be independent or unbiased. |

The precise projection/normalization contracts are on [NTT trace](../../crates/primus_ntru/src/trace/ntt.rs) and [Fourier trace](../../crates/primus_ntru/src/trace/fourier.rs). NLEV→NGSW scheme switching preserves the complete output basis and adds f/f²-dependent errors; see [CBS parameters](../../crates/primus_tfhe_ntru/src/circuit_bootstrap.rs). Budget them at the smallest output gadget scale and at the eventual consumer.

Full one-hot APIs produce all M coefficient NLEVs or transformed NGSWs. Compact NGSW APIs omit branch zero for consumers of the form `C0 + sum_{r>0} delta_r*(Cr-C0)`. They skip its projection/scheme switch, not shared BR, and do not widen the guard. The fused consumer sums all external-product errors; sequential CMux estimates cannot simply be reused. Fourier rounds after the sum, so ciphertext coefficients can differ from separately converted products. The first public lookup layer still needs all M NLEVs.

## Factorized MVB

In the integer negacyclic ring, `S=1+X+...+X^(N-1)` satisfies `(1-X)*S=2`. For an unscaled integer LUT p_i, form `W_i=(1-X)*p_i`: its first coefficient is `p_i[0]+p_i[N-1]`, and later coefficients are `p_i[j]-p_i[j-1]`. With actual Scaled output scale Delta, `V=(Delta/2)*S` gives `V*W_i=Delta*p_i`.

Odd Q uses the modular inverse of two; Native Q requires an even actual Delta and integer halving. This construction halves noiseless V, not a noisy ciphertext. Never reduce W_i modulo the plaintext modulus. Fourier transforms signed integer factors without torus scaling. See [FactorizedLookupTable](../../crates/primus_tfhe/src/lookup_table/factorized.rs).

All outputs share the initialization/BR error e_BR. A deterministic bound is `||W_i*e_BR||_infinity <= ||W_i||_1*||e_BR||_infinity`. Outputs are correlated; independent-coefficient variance estimates need additional assumptions. GLWE BR→KS adds output KS error after multiplication; KS→BR switches the input once before BR. NTRU factors amplify both first-lift and BR errors before each Q→q/extraction/KS return.

At the final ciphertext modulus q, let Delta be the decoder's scale and `epsilon=t_out*Delta-q`. For decoded message y and integer phase error e relative to `Delta*y`, a sufficient condition is `|epsilon*y+t_out*e|<q/2`; input rotation margins remain a separate requirement. Scaled numeric flags are not automatically Boolean gate inputs or Rounded feedback ciphertexts. Prefer ManyLUT when capacity and margins suffice; MVB needs suitable factor norms and its own transform/error budget.

## Fixed complete high-precision lookup

Let c be the input chunk count, d the low coefficient-selecting count, o the independent output count and `h=c-d`. Define `K=M^d<=N` and `P=M^h`. For `x=p*K+z`, output j's polynomial p stores `round(Q*F(x,j)/(2M))` at coefficient z, with coefficients K..N zero. Public storage has `o*P*N` coefficients in `[output][prefix][coefficient]` order. All polynomials and outputs are retained, including equal ones. See [table geometry](../../crates/primus_tfhe_ntru_lut/README.md#encoding-and-table-partition).

Each request performs one-hot CBS on all c chunks. The complete selection tree consumes these selectors as follows:

| Input chunks | Role |
| --- | --- |
| `0..d` | Nonzero NGSW selectors form one encrypted rotation per low chunk. |
| d, if h>0 | All M NLEVs select and lift each group of public polynomials. |
| `d+1..c` | M-1 NGSWs per chunk select among already encrypted child results. |

The first layer computes `sum_r P_r odot NLEV[delta_r]`, including r=0. Later groups compute `C0 + sum_{r>0}(Cr-C0) otimes NGSW[delta_r]`. Every output executes all layers, regardless of repeated values. Each group accumulates transform-domain products before one inverse transform.

For h>0, there are P public products and `P/M-1` encrypted products per output: `P+P/M-1` selection products and `(P-1)/(M-1)` selection groups/inverse transforms. Then d rotation products follow. For M=16, d=3 and c=4/5/6, selection counts are 16/271/4351; P-1 would undercount the first layer. For h=0, there is one NLEV[1] lift and d rotations instead.

`needs_public_lift()` is exactly h=0. The complete context borrows a classic initializer or generates independent lift material for sparse BR. For explicit composition, a supplied lift takes precedence even if invalid; it is rejected rather than silently replaced. Its generation basis may differ from BR/CBS and must accompany the ciphertext. With h>0 surplus lift is ignored. Shape checks do not prove the encoded one, actual secret, basis/transform pairing or decomposition precision. See the binding contracts in [NTT](../../crates/primus_tfhe_ntru_lut/src/ntt.rs) and [Fourier](../../crates/primus_tfhe_ntru_lut/src/fourier.rs).

Low chunk i forms `C_i=G+sum_{r>0}(X^(-r*M^i)-1)*NGSW[delta_r]`, targeting `NGSW[X^(-m_i*M^i)]`. G is the public gadget encoding of one, not an NLEV lift; Fourier factors use integer transforms while G uses torus scale. Negative rotation by the combined low digits moves the selected positive coefficient index z to coefficient zero, then the result returns to the external LWE domain.

With the decomposition residual defined above, the first public selection contributes `-epsilon(P_selected)`; encrypted selection contributes `-f*epsilon(C_selected-C0)`, while child error follows the selected branch. Add digit-weighted selector row errors, rotation products, return errors and, for Fourier, FFT/conversion rounding. Shared selectors correlate errors across groups and outputs. Exact NTT summation and fixed operation counts do not establish a joint noise budget.

The data table needs no plateau repetitions: the preceding one-hot test polynomial supplies the input guard. Subsequent operations still require output decoding margin. Recommended configs use classic BR; sparse is explicit and preserves the complete tree. Historical pruning/deduplication measurements are not evidence for its current costs. Current creation and evaluation measurements are separate [crate-local benchmarks](../../crates/primus_tfhe_ntru_lut/README.md#benchmarks).
