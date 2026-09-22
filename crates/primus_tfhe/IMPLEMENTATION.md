# TFHE implementation notes

These notes retain cross-layer invariants and measured design tradeoffs. For supported operations and application workflows, use the [English guide](README.md) or [中文指南](README.zh_CN.md). Method-level input, output and scratch contracts remain in rustdoc.

## Rotation geometry

Let N be the negacyclic polynomial length, k the output count, s its next power of two (s=1 for unary LUTs), and M=N/s. Output j occupies coefficients s*r+j. Each input interval repeats a group of k encoded outputs and s-k zeros. M counts positions per output, not repetitions of one input. Even equally spaced centers have split first/last intervals.

Compilation first encodes E(m)=round(m*q_in/t), then quantizes E(m) into 2M positions. Write R(x,q,L)=round(x*L/q) mod L. Both rounds use ties upward; merging them into round(2M*m/t) can change the centers. For example, N=16, s=1, t=3, q_in=5, m=1 gives center 13, rather than 11. Nearest-center intervals assign ties to the larger center. The front-half compiler terminates the programmed prefix D with the center min(R(E(D)),M) carrying -f(0). Capacity D<=M does not establish distinct centers or a sufficient noise margin.

Online rotation quantizes every ciphertext coefficient as R_s(x)=s*R(x,q_in,2N/s). The exponent is -R_s(b)+sum_i R_s(a_i)*secret_i. It is not a single quantization of the LWE phase. Since s divides N, negacyclic wrapping preserves the output lane modulo s. The physical 2N must be representable by the coefficient type, including Native inputs. Raw compilation permits independent input and coefficient moduli; complete backends currently require equal ciphertext moduli. Output plaintext encoding can still differ.

For odd full domains t=2h+1, fold centers at N and negate upper-half outputs. The sorted input order is 0,h+1,1,h+2,...,h; the compiler rejects collisions of the actual rounded centers. Append center N with -f(0), with interval boundaries ceil((left+right)/2). Typical spacing N/t is half the front-half spacing; t<=N alone does not prove margin. See [front-half compilation](src/lookup_table/compile/front_half.rs) and [odd full-domain compilation](src/lookup_table/compile/odd_full_domain.rs).

## Ternary and sparse rotation

Classic ternary uses mutually exclusive selector bits s_plus and s_minus. Combining controls as G=Enc(s_plus)-X^(-a)*Enc(s_minus), then adding the external product G * ((X^a-1)*ACC), implements rotation by X^(a*(s_plus-s_minus)) with one external product. The two control ciphertexts still contribute encryption noise. NTT combines exact field values; Fourier uses its documented transform representation and rounding.

Sparse rotation uses a public map that independently assigns c distinct buckets to every input index. A private matching assigns each nonzero secret position to exactly one copy, with at most one selected index per bucket. Public bucket sizes can differ. Each selector is independently encrypted; the dummy encrypts one minus the sum of the bucket's selectors. For bucket C_j, aggregate G_j=Dummy_j+sum_{i in C_j} X^a_i*Selector_(j,i), then perform one external product. An unused bucket encrypts the identity monomial, not zero. All encrypted zeros and dummies participate; under independent centered row errors, the aggregate row variance is (|C_j|+1)*sigma². Fewer external products do not imply proportionately less noise, and average bucket length cannot replace a worst-case bound.

Matching retries only the public map, at most eight times with the same client secret. Successful publication conditions the map on that secret admitting a full matching. Repeated attempts reduce generation failure, not that secret/map correlation. Matching, rejection sampling and inverse preparation have no constant-time guarantee. NTRU first conditions its client secret on ring invertibility, and Fourier additionally on numerical stability. Native fixed-weight binary secrets require odd weight. These conditioned distributions and evaluation-key KDM/circular-security assumptions need separate security analysis; functional tests do not certify parameters or tail bounds.

GLWE initializes a trivial accumulator. NTRU instead uses an encrypted NLev[1], whose initialization error must be budgeted independently. An NGSW row encrypts a gadget-scaled multiple of the accumulator secret; it cannot replace NLev[1]. NTRU sparse CBS/MVB remain rejected at construction. See [shared mapping and matching](src/sparse.rs) and the [NTRU secret and CBS contracts](../primus_tfhe_ntru/README.md).

## Factorized MVB

In the integer negacyclic ring, S=1+X+...+X^(N-1) satisfies (1-X)S=2. For each unscaled integer LUT p_i, form W_i=(1-X)p_i, with w_i[0]=p_i[0]+p_i[N-1] and w_i[j]=p_i[j]-p_i[j-1]. The common polynomial V=(Delta/2)*S satisfies V*W_i=Delta*p_i. For odd q, halving uses the modular inverse of two; Native requires an even actual Scaled delta and ordinary integer halving. This only happens in the noiseless V; modular halving of a noisy ciphertext does not halve its error. Never reduce factors modulo the plaintext modulus. Fourier transforms their signed integer lifts, not torus-scaled values.

All outputs share one BR error e_BR. A deterministic bound is ||W_i*e_BR||_infinity <= ||W_i||_1*||e_BR||_infinity. Outputs are correlated; replacing this by an independent-coefficient variance estimate requires additional assumptions. With epsilon=t_out*Delta-q, a sufficient Scaled decoding condition for output y and integer error e is |epsilon*y+t_out*e|<q/2. Input rotation margins are a separate condition.

GLWE BR→KS applies KS after each product: moving KS before the factors would amplify its error too. KS→BR switches the input once. NTRU factors amplify both initialization and BR error before per-output KS. Generic trace projection cannot become partial coefficient expansion unless the target plaintext's remaining coefficients are known zero. Fourier trace normalization also introduces rounding; its error analysis is not the NTT one.

Prefer interleaved ManyLUT when capacity and rotation margins suffice. MVB is useful for many outputs with small integer differences when interleaving loses capacity or precision. It needs extra program storage and a factor/FFT noise budget; it is not universally faster. Scaled numeric flags are not automatically Boolean gate inputs or the original Rounded input encoding. See [factor construction](src/lookup_table/factorized.rs).

## Performance decisions and reproducibility

The following are historical observations on Ryzen 9 9955HX3D, x86_64 Linux, with target-cpu=native. Default used rustc 1.98.0; SIMD used nightly 1.100.0 (2026-08-26). Compare revisions within the same toolchain and features, not default against SIMD to infer vectorization benefits. CPU boost/SMT and code layout can affect small differences. None of these measurements certifies production parameters.

| Decision | Evidence and retained limitation |
| --- | --- |
| Shared family LUT construction | Against cba9c01, Native u32 N=1024, t=255, k=4 was about 4.4% (0.06 µs) slower; other sampled cases improved. Keep the shared checks and direct fill, not a universal speedup claim. |
| Shared CBS workspace | Against 618768d, NTRU NTT u64 N=1024 saved 25 KiB; SIMD CBS remained about 2–3% slower. Restoring independent trace scratch did not remove the difference. |
| Contiguous MVB factors | Against 31b9a67, GLWE NTT D=64/k=17 construction improved slightly; BR→KS was about 3% slower, KS→BR near baseline. Contiguous storage does not guarantee cache residency across transforms/KS. |
| Sparse CBS key generation | Reusing a prepared accumulator secret was retained for GLWE Fourier, with no default-feature speedup evidence. The NTT prototype was reverted after complete keygen regressed. |
| Sparse vs classic | u32 benefits do not generalize to u64; larger selector keys and coefficient aggregation can outweigh fewer external products. Compare complete keygen and PBS independently. |
| Lower arithmetic | Retain ordinary loops for the measured Native/Barrett add/sub slices and u64 Shoup in-place canonical multiplication; keep profitable Barrett multiplication/dot-product SIMD. Do not replace all SIMD kernels together. |
| GLWE coefficient clients | NTT coefficient-domain encryption/decryption saves transforms with exact equivalence. The Fourier prototype changed u64 phase error and was not adopted. |

Common Boolean and 2+2 bit PBS parameters, their TFHE-rs reference and run commands are in [BENCHMARKS.md](BENCHMARKS.md). Other fixtures live with [shared LUT benchmarks](benches/lookup_table.rs) and the four backend bench directories: [GLWE NTT](../primus_tfhe_glwe_ntt/benches), [GLWE Fourier](../primus_tfhe_glwe_fourier/benches), [NTRU NTT](../primus_tfhe_ntru_ntt/benches), [NTRU Fourier](../primus_tfhe_ntru_fourier/benches). Use the same parameters, CPU affinity, toolchain and features for each comparison; keep setup outside online timing and do not compile concurrently with measurements. Historical n=512 fixtures are not current common PBS or n=728 sparse results or security recommendations.

Full derivations, rejected prototypes and raw measurements are preserved at commit 7940e33. For example, `git show 7940e33:docs/tfhe-refactor-costs.md` recovers the method and `git show 7940e33:docs/benchmarks/tfhe-r2.csv` recovers its data. Other archived sources include tfhe-mvb.md, tfhe-sparse-pbs.md, tfhe-ntru-sparse.md, simd-u64.md and glwe-coefficient-client.md under that commit's docs tree. The old implementation-decisions reference under its .agents tree includes unverified non-TFHE follow-ups; they are historical leads, not validated defects or current API contracts.

## Validation

The [CI workflow](../../.github/workflows/ci.yml) defines workspace stable checks and nightly all-feature Clippy, tests and strict private rustdoc. The [justfile](../../justfile) also provides targeted TFHE/default/SIMD workflows. Tests use functional parameters, independent phase/rotation oracles, and allocation checks; they do not prove noise tails, constant-time behavior, non-x86 portability or production security. New algorithms and unsupported combinations require their own algebra, noise and complete-workload validation.
