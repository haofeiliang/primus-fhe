# TFHE arithmetic parameter matrix

This guide records the experimental teaching parameters, their mathematical domains and historical numerical observations. The parameters have no security or failure-probability assessment. Two fixed seeds establish observations, not a probabilistic guarantee. Shared geometry does not make NTT, Fourier, GLWE and NTRU equally secure or their costs directly comparable.

Inventory reviewed on 2026-10-08 against source revision `9a80c506`. The numerical choices below are local arithmetic fixtures, versioned by their source revision. Historical measurements retain their own dates; this inventory review did not rerun the numerical matrix. Construction validity, sampled functional correctness, security estimates and decryption-failure bounds are separate evidence.

The centralized benchmark package, its parameter diagnostic and all `primus_tfhe*`
unit/integration tests have been removed for an example-driven API redesign.
The 30 teaching examples and backend `experimental` configs remain available.
Historical profiles and results below describe the recorded revision; they are
not current test coverage or runnable validation instructions. New focused tests
and per-backend benchmarks will be designed after the recommended workflows.
The historical [paper comparison](../performance/sparse-paper-comparison.md)
records separate Table-3-shaped profiles; its timings do not replace the teaching
profiles or establish a joint noise/security budget.

## Moduli, geometry and secret domains

| Symbol | Representation and value | Use |
| --- | --- | --- |
| Q27 | `BarrettModulus<u32>`, 132120577 | NTT ordinary PBS, sparse PBS and MVB |
| Q30 | `BarrettModulus<u32>`, 998244353 | NTT CBS, one-hot and high-precision lookup |
| Q50 | `BarrettModulus<u64>`, 1125899906826241 | All u64 NTT profiles |
| Native32 / Native64 | `NativeModulus<u32/u64>`, implicit 2^32 / 2^64 | Fourier accumulator; also GLWE external modulus |
| q24 | `PowOf2Modulus<u32/u64>`, 2^24 | Independent NTRU external LWE and return key |

All three NTT primes satisfy Q mod 4096 = 1 and the existing NTT table constructors accept N=1024/2048. Each fits the Barrett bound Q<2^(BITS−2). `NativeModulus` never constructs an unrepresentable `1 << BITS`. Explicit powers of two use `PowOf2Modulus`; all NTRU examples use independent external q=2^24.

Key geometry and message configuration are separate. The [teaching workloads](#teaching-examples) below identify their actual message domains; the historical observations identify their own workloads separately. Family factories prepare workload codecs when binding clients and compiling programs; this establishes encoding and layout conditions, not a noise budget.

The historical matrix used the geometries below with u32 and u64, both RustFFT and TFHE-FFT, and both GLWE orders `BootstrapKeyswitch` and `KeyswitchBootstrap`. GLWE has k=1 in these profiles. Here n is the small LWE dimension: in `KeyswitchBootstrap`, the external client domain has kN coefficients, not n. GLWE uses q=Q. NTRU has independent external LWE and ring secrets and returns Q→q24→LWE KS.

| Key profile | n / N | External/small secret | Ring secret |
| --- | --- | --- | --- |
| GLWE dense Boolean / 2+2 bit PBS | 800 / 1024; 866 / 2048 | uniform binary | uniform binary |
| GLWE circuit / ternary PBS | 800 / 1024 | uniform binary or uniform ternary | uniform ternary |
| GLWE fixed-weight / sparse / MVB | 728 / 1024 | fixed-weight binary, h=32 | sparse ternary |
| NTRU dense Boolean / 2+2 bit PBS | 800 / 1024; 866 / 2048 | uniform binary or uniform ternary | sparse ternary |
| NTRU fixed-weight / sparse / MVB | 728 / 1024 | fixed-weight binary, h=32 | sparse ternary |
| NTRU circuit / one-hot / lookup diagnostic | 800 / 1024 | uniform binary or uniform ternary | sparse ternary |
| NTRU teaching one-hot / teaching lookup | 800 / 1024 | fixed-weight binary, h=32 | sparse ternary |

`SparseTernary` is the existing distribution with probabilities (−1,0,+1)=(1/4,1/2,1/4), not an exact-weight ring key. NTRU samples f directly from this signed distribution, then screens it for the backend's invertibility requirements; do not reinterpret it as an unimplemented `1+2F` secret distribution. Its external LWE secret is independent. The 728/h32 geometry exercises fixed-weight/sparse algorithms and narrow MVB input cells. Sparse keys use copy_count=3 and bucket_count=64. Their map-generation retry does not replace the client secret or search for successful numerical seeds.

## Noise by key role

All constructor arguments are **coefficient-domain standard deviations under the role's own modulus**. Let α=2.046151696979124e−6 and β=2.845267479601915e−15, the constants already used by the dense GLWE PBS fixtures. Keeping these constants does not import a security claim from another parameter set.

| Profile | Small/external LWE σ | Ring encryption / BR σ | KS material σ | Trace / scheme-switch σ |
| --- | --- | --- | --- | --- |
| GLWE dense PBS | αQ | max(βQ,6.4) | max(βQ,6.4), the shared GLWE KS key noise | not used |
| GLWE circuit / ternary | αQ | 6.4 | 6.4, the shared GLWE KS key noise | 6.4 / 6.4 |
| GLWE fixed-weight / sparse / MVB | 3.2Q/16384 | 6.4 | 6.4, the shared GLWE KS key noise | 6.4 / 6.4 when CBS is requested |
| NTRU dense / circuit / n800-h32 lookup | α·2^24 ≈34.328 | 0.7 | 3.2 at q24 | 0.7 / 0.7 when CBS is requested |
| NTRU fixed-weight / sparse / MVB | 3.2·2^24/16384 =3276.8 | 0.7 | 3.2 at q24 | 0.7 / 0.7 when CBS is requested |

Both GLWE orders use the same kind of GLWE KS material; order changes where it is applied. BR and KS have independent configuration fields. These fixtures happen to give them equal σ; this is not an API requirement. The small-LWE σ is the fresh input-encryption noise for PBS→KS. KS→PBS external inputs use the extracted ring-secret domain and BR/accumulator-derived LWE noise, not the KS key's noise. See the [domain and return-path guide](tfhe-parameters-and-boundaries.md).

`CbsGadgetConfig` supplies three decompositions. Its trace and scheme-switch parameters inherit the accumulator encryption parameters, including σ; advanced direct CBS construction can instead supply compatible parameters with independent noise. The generated keys are independently sampled. NTRU keeps ring/CBS σ=0.7 separate from external LWE and return KS noise. Its n800/h32 teaching lookup uses αq24, whereas the historical n728/h32 diagnostics used σ=3276.8: equal Hamming weight does not make those profiles interchangeable. CBS and NGSW products amplify errors through f and f²; changing dimensions, distributions or noise needs a joint budget.

The [default noise sampler](../../crates/primus_distr/src/discrete_gaussian/mod.rs) is a centered, truncated discrete Gaussian, represented as canonical residues. Its inclusive magnitude bound is `max(1, floor(12σ))`; it selects a 64-bit CDT for maximum magnitude ≤255 and a discrete Ziggurat otherwise. Here σ is the sampler parameter, not a measured standard deviation of evaluated ciphertexts. The optional precise CDT is a separate sampler, not an automatic consequence of enabling `high_precision`. Security or tail analyses must account for this sampling model, its approximation and NTRU's accepted-key conditioning. A normalized constant copied from another implementation does not transfer that implementation's claims to these secrets, moduli, samplers and algorithms.

## Decomposition by operation

Notation is `(log2 radix, level count; discarded bits)`. With explicit non-power-of-two Q, `value_bits=bit_width(Q)`; native uses BITS. Discarded bits are `value_bits − log_basis × levels`. `None` in a config means `floor(value_bits/log_basis)` levels; it does **not** generally mean an exact decomposition.

### Dense GLWE PBS

| Word / backend | BR | KS |
| --- | --- | --- |
| u32 NTT Q27 | (5,5;2) | (2,13;1) |
| u64 NTT Q50 | (23,1;27) | (3,5;35) |
| u32 Fourier | (8,3;8) | (2,13;6) |
| u64 Fourier | (23,1;41) | (3,5;49) |

These numerical profiles were recorded from the former GLWE PBS benchmarks. The current u64 teaching configs retain their numerical choices; the u32 rows are historical reference profiles.

### GLWE circuit, ternary and fixed-weight diagnostics

BR and KS use full-length base 2^2 for u32 and base 2^8 for u64. Trace and scheme-switch use the same respective full bases and fresh accumulator noise distribution, with independently sampled keys. Q27 remains appropriate for fixed-weight PBS/MVB; **u32 CBS uses Q30**.

| Word / modulus | Full internal basis | CBS output basis | Smallest CBS scalar |
| --- | --- | --- | --- |
| u32 Q27, PBS/MVB only | (2,13;1) | — | — |
| u32 Q30, CBS | (2,15;0) | (3,3;21) | 2^21 |
| u32 native | (2,16;0) | (3,3;23) | 2^23 |
| u64 Q50 | (8,6;2) | (8,2;34) | 2^34 |
| u64 native | (8,8;0) | (8,2;48) | 2^48 |

CBS output widths are padded to W=4 for u32 and W=2 for u64. The historical large-parameter diagnostic checked every GGSW row and level, not just a decoded CMux result.

### NTRU PBS, CBS and lookup

BR, trace and scheme-switch use full-length base 2^2 for u32 and base 2^8 for u64. Return KS is always at q24 with `(3,8;0)`. Ordinary PBS/sparse/MVB use Q27 for u32 NTT; **CBS/one-hot/lookup use Q30**.

| Word / accumulator modulus | BR / trace / scheme-switch basis | CBS / one-hot output | Smallest output scalar |
| --- | --- | --- | --- |
| u32 Q27, PBS/MVB only | (2,13;1) | — | — |
| u32 Q30 | (2,15;0) | (3,4;18) | 2^18 |
| u32 native | (2,16;0) | (3,4;20) | 2^20 |
| u64 Q50 | (8,6;2) | (8,3;26) | 2^26 |
| u64 native | (8,8;0) | (8,3;40) | 2^40 |

The former lookup benchmark paired classic/sparse at n800/h32 with this circuit profile, c8/d5/o8 and independently seeded input. A sparse table with public lifts used independent NLEV[1], selecting BR's basis and sigma 0.7 in that fixture; tables without lifts generated none. Historical complete-request timings, retained material and returned phase residuals are recorded in the [sparse report](../performance/sparse-baseline.md#ntru-high-precision-lookup); those observations are specific to that workload.

The former standalone parameter diagnostic used M=4, c=7 input chunks, d=5 coefficient chunks, o=3 output chunks. Thus M^d=N=1024 and the 14-bit input selects among 16 public polynomials per output. This exercises public lifting, a further encrypted CMux layer, five aggregate rotations, and Q→q24 return. Output width is independent of input width. These are dimensions of that historical observation, not an additional evaluator restriction.

For one-hot, L=4 (u32) or 3 (u64), so W=4 and A=N/(2MW)=32. With R_W the prepared rotation modulus switch, the historical diagnostic computed

`e = centered(R_W(b) − Σ R_W(a_i)s_i − m·N/M) / W`

and checked the actual left-closed guard `−A ≤ e < A`. This includes rounding of every mask coefficient; it is not a modulus switch of the already decrypted phase. Fourier uses the existing coefficient-halving reverse trace and includes its rounding/FFT error in the observed output residuals.

The 27-bit u32 candidate did not provide a sufficient joint CBS/product budget at n=800. Q30 alone with a coarse three-level output also failed. Small internal digits and four output levels balance selector error against product decomposition error. The selected profiles retain the existing NTRU secret distribution, dimensions and ring noise, without seed selection or relaxed acceptance thresholds. Intermediate trials with larger ring noise are not supported presets.

## Operation conditions and error budgets

Here `t_in/t_out` denote message moduli, `q/Q` denote external/ring ciphertext moduli, and `D` is the programmed input count. For the ordinary padded input, `D=ceil(t_in/2)` and messages lie in `0..D`; low-level prefix compilers can choose a smaller nonempty D. Odd full-domain LUTs have a separate contract. A capacity check alone does not establish a usable rotation margin.

| Operation | Encoding and construction conditions | Error budget still required |
| --- | --- | --- |
| Single-output PBS | Unsigned Rounded input/output; `D<=N`; `F(m)<t_out`. Each front-half plateau uses the actual encoded and switched message center | Input noise and per-mask switching error must stay in the correct plateau; BR error, output encoding and return error must fit the output decoder |
| Interleaved ManyLUT | Same input, k positive outputs; `s=next_power_of_two(k)`, `D<=N/s`; slots k..s are padding, not extra outputs | Rotation is quantized to step s. Larger s changes plateau margins and mask-rounding error even when the input codec is unchanged |
| Factorized MVB | Unsigned Rounded input, Scaled outputs; `D<=N`; k positive unpadded factors; explicit odd ring Q or Native with even output scale | Each signed integer factor amplifies BR error; Scaled recovery and the complete return path must fit jointly. k alone is not an applicability bound |
| Ordinary CBS | Rounded selector input; L gadget levels interleaved at `W=next_power_of_two(L)`, `D<=N/W`; program stores `g_j*F(m) mod Q` and binds the exact output basis | BR, reverse trace, scheme-switch and subsequent gadget consumption. CMux requires F to be a bit over the entire programmed domain; general integer external products need their own budget |
| NTRU one-hot CBS | `t_in=2M`, `M=2^tau>=2`; `2MW<=N`; full selectors r=0..M−1 or a compact nonzero batch r=1..M−1 | Actual quantized phase must satisfy the left-closed guard; NLEV/NGSW conversion and consumption require a further output budget |
| High-precision NTRU lookup | Uniform tau, positive input/output counts c/o, `0<=d<=c`, `M^d<=N`; full enumerated input domain fits host indexing; each output chunk is below M | One-hot guards for all chunks, selection products, aggregate rotations, any public lift, f/f² amplification and Q→q/KS return. Shared selectors make errors correlated |

### Rotation margins and returned phases

The [front-half compiler](../../crates/primus_tfhe/src/lookup_table/compile/front_half.rs) first computes `E(m)=round(m*q/t_in)` and then the rotation center, both with upward ties. It fills nearest-center plateaus, with a midpoint belonging to the higher center. For interleaving, switching each b/a coefficient uses

`rho_s(x)=s*round(x*2N/(s*q))`, `u_bar=rho_s(b)−sum_i rho_s(a_i)*s_i`.

Blind rotation uses `−u_bar`. Quantizing a decrypted phase once is not equivalent to this per-coefficient switching; secret magnitude, weight and dimension affect the accumulated rounding error. Besides `D<=N/s`, the compiler checks distinct centers. The runtime error must stay within the appropriate plateau, including endpoints and its negative negacyclic extension.

GLWE keeps `q=Q`. `BootstrapKeyswitch` applies BR→ring KS→compact extraction, with an external small-LWE secret of dimension n. `KeyswitchBootstrap` applies ring KS→compact extraction→BR→full extraction, with an external extracted-ring secret of dimension kN. Fresh input σ also changes with this order as described above. These are distinct client domains, not interchangeable order labels.

NTRU uses independent q and Q. LUT coefficients are encoded at Q; the current ordinary return performs coefficient Q→q switching, sample extraction, then LWE KS. Rounding is not exact re-encoding at q. Output-codec capacity and error must be checked at the actual returned modulus, including the return-key noise. Complete CBS/one-hot bundles retain return material for downstream LWE results; the CBS stage itself allocates no return scratch.

### Factorized output recovery

For the [MVB compiler](../../crates/primus_tfhe/src/lookup_table/factorized.rs), the common polynomial is `V=(Delta_Q/2)*(1+X+...+X^(N−1))` and each factor is `W_i=(1−X)*p_i`, where p_i is the signed unscaled LUT. Thus `V*W_i=Delta_Q*p_i`. Modular division by two under odd Q applies only to noiseless V. Native uses ordinary halving of an even scale; explicit even ring moduli are not supported here.

The bound `||W_i*e_BR||_infinity <= ||W_i||_1*||e_BR||_infinity` uses the signed integer lift of each factor, not large canonical residues. Arbitrary functions can have much larger norms than threshold functions with the same number of outputs. For the [Scaled codec](../../crates/primus_encoding/src/scaled.rs), let `epsilon=t_out*Delta_Q−Q`; a sufficient recovery condition for integer output y and total ring error e is `abs(epsilon*y+t_out*e)<Q/2`. NTRU must additionally include return scaling/rounding and KS error relative to `y*Delta_q` at q. Finite observations at `t_out=2` do not validate a larger output domain.

`PbsMessageConfig` defaults to equal input/output moduli, and explicit output overrides remain valid configuration choices. An override changes the encoding and available error margin; codec construction alone does not validate the new joint budget. Scaled threshold flags also do not have the Rounded t=4 encoding used by Boolean PBS. Reconsumption requires the receiving operation's actual encoding and input-domain contract.

### CBS, one-hot and lookup consumption

Ordinary CBS has three independent roles: selector input encoding at q, integer gadget output under Q, and the candidate ring-message encoding under Q. The independent `t_ring` passed to `context.accumulator_client(accumulator_secret, t_ring)` prepares the candidate domain at Q; it is not a gadget-output message modulus. A compiled custom function binds every scalar of the output basis; equal level counts do not establish basis compatibility. A custom predicate uses the same single BR as the identity program. Neither compilation nor a successful CMux observation proves the budget for another function or candidate distribution.

The [one-hot contract](../../crates/primus_tfhe_ntru/src/one_hot.rs) uses `S=N/M`, `A=N/(2MW)` and `u_bar=m*S+W*e mod 2N`, requiring `−A<=e<A`. For current `N=1024,M=4,W=4`, A=32 and the physical exponent error lies in `[−128,128)`. This includes fresh-input noise, encoding and per-mask switching. The server cannot check this secret-dependent guard from shape information. Fourier's coefficient-halving reverse trace has rounding error; NTT's modular inverse-of-two contract does not replace it.

The [lookup layout](../../crates/primus_tfhe_ntru_lut/src/lookup_table.rs) uses low d chunks to select coefficients (`K=M^d`) and high c−d chunks to select among `P=M^(c−d)` polynomials per output. Aggregate controls encrypt `X^(−m_i*M^i)`; they rotate the selected data polynomial without ordinary PBS plateau repetition. Noise tolerance comes first from one-hot CBS and then from the product chain, not from that absence of repetition. Table sharing/pruning depends on the function and changes actual selection work. Storage and plan statistics are not a noise analysis.

Classic and sparse are alternative BR implementations available to all four backends' ordinary PBS, ManyLUT, MVB and CBS. NTRU also supports either BR for one-hot and high-precision evaluation. Sparse requires its fixed-weight binary secret and matching material; it cannot be substituted for a dense binary/ternary key. Sparse lookup needs an independent NLEV[1] public-lift key only when the compiled plan contains a reachable Lift; classic can use its initializer. The [material guide](../../crates/primus_tfhe_ntru_lut/README.md#evaluation-and-workspace) describes binding. API availability does not establish numerical evidence for every combination; the former large-parameter diagnostic did not exercise NTRU sparse CBS.

## Scope of paired parameter entries

The following small catalogue describes **experimental u64** pairings available from each backend's `experimental` module. It pairs existing key profiles with the actual teaching domains and explicit algorithm/order. It is not a list of production security presets or a promise that other functions have the same error budget. u32, ternary and alternate engines/orders remain expressible through explicit parameters; this guide does not claim current test coverage for them. Silently converting bases between word widths is inappropriate.

All 30 teaching examples start from the corresponding operation config. Prepare
it once, then generate keys with its explicit algorithm and compile the public
function. The examples retain separate client/server stages and reuse buffers
for multiple requests. Numerical construction lives in the backend's `experimental`
module; the examples keep operation choices such as lanes, thresholds, CBS
predicates and lookup functions visible. Historical benchmark and diagnostic
profiles were separate workloads; their evidence does not transfer automatically
to these teaching functions.

| Paired workflow | Key profile / algorithm | Message and operation configuration |
| --- | --- | --- |
| Basic PBS, four backends | Dense n866/N2048, classic binary; GLWE BR→KS | Rounded `t_in=t_out=32`; x,y in 0..4 → z=2*x+y → score=min(z,6) → price=2*score+[score>=4] |
| Boolean circuit, four backends | Same classic n866/N2048 profile as basic | Rounded 4→4; admin OR (member AND NOT revoked) |
| Sparse PBS, four backends | Fixed n728/h32/N1024, sparse copies=3/buckets=64; GLWE BR→KS | Rounded 32→32; same two-PBS scoring pipeline as basic |
| ManyLUT, four backends | Fixed n728/h32/N1024, classic; GLWE BR→KS | Rounded 16→8, inputs 0..8, two outputs, stride 2; (grade=x/2, flag=[x>=5]) → code=2*grade+flag |
| Threshold MVB, four backends | Fixed n728/h32/N1024, classic; GLWE KS→BR | Rounded input 128, inputs 0..64; 17 Scaled outputs at t_out=2 with the example's thresholds |
| Ordinary CBS, four backends | Circuit n800/N1024, classic binary; GLWE BR→KS | Selector Rounded t_in=8, inputs 0..4; predicate F=[m>=2]; select encrypted fee vector then add encrypted extras, Scaled t_ring=8; output basis above |
| Sparse CBS, two GLWE backends | Fixed n728/h32/N1024, sparse copies=3/buckets=64, BR→KS | Same fee-vector selection/addition and message domains as ordinary CBS; GLWE output basis above |
| One-hot, two NTRU backends | Circuit n800/h32/N1024 with external σ=αq24, classic | Selector t_in=8/M=4, Scaled ring candidates t_ring=8; output L=3/W=4, full four-selector batch |
| High-precision lookup, two NTRU evaluators | Same n800/h32 key profile as one-hot, classic, full return material | tau=2, c=8/d=5/o=8; 16-bit input/output; piecewise fee with breakpoints 16384/49152 and maximum 36863 |

All entries use Q50 for NTT, Native64 for Fourier and independent q24 for NTRU. The noise and decomposition tables above are part of each entry, not defaults inferred from N alone. The workflow table refers to existing [examples](#teaching-examples); the existing low-level configuration APIs continue to express general plaintext moduli, independent output moduli and independent chunk counts.

Operation configs are pure numerical descriptions, separate from runtime state:

| Type | Composition and role |
| --- | --- |
| `ModulusConfig<M>` / `LweConfig<M>` | Constant-friendly modulus/dimension/distribution/noise choices; M keeps Native, PowOf2 and Barrett representations distinct; `M::try_from(modulus_config)` prepares a reducer; `LweEncryptionParameters::try_from(lwe_config)` prepares its samplers at setup |
| `BlindRotationMethod` | Classic/Sparse choice with algorithm-specific sparse bucket geometry; no encryption parameters |
| Family `PbsConfig` | LWE domain, accumulator/BSK layout (`bsk_dimension`/`bsk_poly_length`, NTRU `acc_modulus`), ring secret (`bsk_secret_distr`), BR gadget/algorithm, required KS and default input/output messages; GLWE also selects order |
| Family `CbsConfig` | `pbs` common config plus `CbsGadgetConfig`; selector t is `pbs.messages.input_modulus`. Only GLWE KS→BR requires input KS |
| `HighPrecLutConfig` | NTRU CBS as `one_hot` including required return-KS, independent chunk counts and optional coefficient partition; tau derives from one-hot input t |
| `PbsParameters` | Owns checked LWE/ring state, algorithm, required KS and messages. PBS and CBS share KS with independently sampled secrets |
| `CbsGadgetParameters` | Prepared trace/scheme-switch/output gadgets sharing the existing ring sampler Arc |
| `CbsParameters` | One common `PbsParameters` owner, CBS gadgets and selector input codec; no additional ordinary return state |
| `HighPrecLutParameters` | Complete NTRU CBS, required return, checked chunk layout and q/Q codecs; no function enumeration or transforms |
| Parameter preparation | `PbsParameters::try_from_config(pbs)` prepares one common domain. CBS uses `try_from_config(pbs, gadget)` or `try_with_config(parameters, gadget)`; the latter moves prepared state without sampler rebuilding. CBS derives its gadgets and selector encoding from that common domain |

In `PbsConfig`, GLWE uses `bsk_dimension`/`bsk_poly_length` and NTRU uses
`acc_modulus`/`bsk_poly_length`. `bsk_secret_distr` samples the ring secret used
to encrypt BSK ciphertexts and decrypt BR output; the input LWE secret remains
in `small_lwe` or `external_lwe`. GLWE's public `(0, LUT * X^(-b))` initializer
needs no secret and samples no encryption noise. NTRU lifting propagates noise
from its key material. `bsk_gadget` also supplies ring clients' encryption noise.

Each concrete backend defines `experimental::CLASSIC_PBS_U64`,
`SPARSE_PBS_U64`, `CLASSIC_MANY_LUT_U64`, `CLASSIC_THRESHOLD_MVB_U64`,
`CLASSIC_CBS_U64`, plus GLWE's `SPARSE_CBS_U64` or NTRU's
`CLASSIC_ONE_HOT_U64`. Family crates provide shared configuration types;
backend constants use the actual Barrett/Native representation and numerical choices.
These constants have no assessed security or failure-probability guarantee.
They carry their actual BR choice and message domains; there is no registry or
online algorithm/config dispatch.

```rust,ignore
let config = primus_tfhe_ntru_ntt::experimental::CLASSIC_PBS_U64;
let context = primus_tfhe_ntru_ntt::TfheContext::<_, primus_ntt::U64NttTable, _>::try_from_pbs_config(config)?;
let (client, server) = context.try_generate_keys(rng)?;
let secret = client.external_lwe_secret_key();
let encryptor = context.encryptor(secret)?;
let decryptor = context.pbs_decryptor(secret)?;
let lut = context.pbs_lookup_table_compiler()?.compile_fn(|m| (m % 4) as u64)?;
let evaluator = context.evaluator(&server)?;
```

For explicit numerical customization, copy the operation config, override the
relevant fields, then prepare it. For example, NTRU's
`config.key_switching.noise_standard_deviation` changes return-key row noise;
GLWE uses the same field for ring-KS row noise. It does not change fresh input or
BR row noise. Alternatively, compose `PbsConfig` / `CbsConfig` from their raw
fields and call `PbsParameters::try_from_config`. Add CBS with
`CbsParameters::try_from_config(pbs, gadget)` or
`try_with_config(parameters, gadget)` when the common state is already prepared.
These entries retain the concrete modulus representation. Overrides must satisfy
the constructor contracts and require their own security/error analysis; they
do not inherit evidence for the teaching workload.

`PbsMessageConfig::new(t)` defaults to equal input/output moduli.
`from_input_bits(b)` describes 2^b padded inputs and codec t=2^(b+1),
with that same default full output modulus; it does not imply output padding or
PBS reconsumption. Teaching constants use 32→32, 16→8 and 128→2;
MVB uses `context.compile_mvb_fn` and `context.mvb_decryptor` for Scaled outputs; ordinary PBS/ManyLUT use `pbs_lookup_table_compiler` and `pbs_decryptor`. Both share Rounded `encryptor`. `PbsParameters::try_from_config` and `CbsParameters::try_from_config` retain message choices and prepare operation-specific state.
PBS codec modes, function ranges and program capacity remain compilation/binding
conditions; valid construction alone does not certify an operation noise budget.

A backend `TfheContext` owns complete PBS/CBS capabilities and one transform table.
One Box owns complete operation parameters. Move prepared state into
`from_parameters` / `try_from_parameters` or the CBS
counterparts by value; default preparation does not clone the LWE sampler.
`parameters()` always borrows the complete PBS domain, including required KS.
`cbs_parameters()` exposes additional CBS capability through retained gadgets
and input encoding. Adding CBS to PBS moves its
common owner into the complete CBS state, without a second domain or input KS.
Factories reject missing capabilities and check independently supplied material.
Existing ring-sampler Arcs remain shared by BR, trace and scheme-switch.

CBS and one-hot share `CbsConfig`, including required `pbs.key_switching`
and independently sampled input/ring secrets. GLWE KS→BR uses that KS for input
preparation; other CBS paths retain it for downstream returns.
`ServerKey` owns BR/KS; `CircuitBootstrapServerKey` combines one `ServerKey`
with one required `CircuitBootstrapKey`, without duplicating BR.
Complete CBS contexts also provide ordinary PBS. Teaching CBS configs retain
GLWE base-log 8/full levels with sigma=6.4, or NTRU return base-log 3/full levels
at q24 with sigma=3.2; these return choices have no security/DFR claim. CBS prepares `input_codec()` from
`pbs.messages.input_modulus`; a CMux consumer independently chooses t_ring via
`context.accumulator_client(accumulator_secret, t_ring)`. Input clients use the
configured Rounded domain; CBS compilation reads retained input/gadget state via
`compile_cbs_fn` / `compile_cbs_slice`. Default CBS/one-hot evaluators combine
existing operation buffers with common resources and allocate no return scratch.
Gadget output has no ordinary message decoder. Functions remain explicit compilation inputs.

Numerical sources belong to the four concrete backends:
[GLWE NTT](../../crates/primus_tfhe_glwe_ntt/src/experimental.rs),
[GLWE Fourier](../../crates/primus_tfhe_glwe_fourier/src/experimental.rs),
[NTRU NTT](../../crates/primus_tfhe_ntru_ntt/src/experimental.rs) and
[NTRU Fourier](../../crates/primus_tfhe_ntru_fourier/src/experimental.rs).
With a backend enabled, [LUT experimental configs](../../crates/primus_tfhe_ntru_lut/src/experimental.rs)
provide `NTT_CLASSIC_LOOKUP_U64` and `FOURIER_CLASSIC_LOOKUP_U64`.
Each combines the corresponding one-hot `CbsConfig` (including required KS)
with c8/o8 and default d5; lookup reuses that KS without preparing a second copy. `HighPrecLutParameters::try_from_config` returns complete offline state;
`chunk_format()`, `layout()`, `codecs()` and `one_hot()` expose the prepared state.
It checks the uniform radix/bit width, independent chunk counts, coefficient
capacity and one-hot level spacing without enumerating the function. No unused
CMux candidate codec is created. NTT/Fourier lookup Contexts move this state beside a single transform environment. They provide pure integer or chunk compilation, plan-directed paired key generation, integer/chunk clients and evaluator binding. Client factories do not receive a LUT. Default d is `min(c, floor(log2(N)/tau))`, with an explicit override. Integer widths are checked independently of coefficient width; chunk output may exceed a single cleartext word.

### Reusing material and changing a workload

The same keys can serve another compatible public program or message codec without key generation merely for a new t. Reuse still requires the same actual secrets, dimensions, q/Q, key decompositions and transform representation. CBS additionally needs compatible trace/scheme-switch material and exact program/output-basis pairing; lookup may need lift and return keys. Public metadata equality alone does not identify a secret or an NTT root/order.

Changing t, lane count, output domain, CBS function, candidate values or lookup partition changes the error conditions even if the keys remain compatible. It leaves the sampled workload listed above. Changing GLWE order changes the external client domain; changing classic/sparse requires the corresponding BR material and accepted secret distribution. Independent external input/output LWE dimensions remain outside these entries.

### Evidence and remaining gaps

| Evidence | What is available | What it does not establish |
| --- | --- | --- |
| Parameter provenance | Backend operation configs for current examples; dense GLWE α/β and historical numerical choices recorded above | Imported security/DFR claims after changing geometry, noise floors, modulus, sampler, order or algorithm |
| Construction and representation | Existing parameter/table, codec and operation-binding checks; capacities and exact q/Q/basis/layout pairing | Rotation guards, accumulated noise, secret identity or a security level |
| Functional observations | Current example known-result checks and historical fixed-seed observations below; the former TFHE tests and diagnostic have been removed | Worst-case noise, tail probabilities or a target failure rate; paths absent from a diagnostic remain absent |
| Security estimate | **Unassessed for every listed entry** | LWE/GLWE/NTRU hardness under the actual distributions, fixed weight, accepted NTRU keys and exposed evaluation material |
| Complete failure bound | **Unassessed for every listed entry** | Joint per-mask switching, decomposition, sparse bucket accumulation, FFT/trace, gadget-consumer and return errors, including correlation |

Any future supported security/DFR claim must specify its estimator/model and version, exact secret/sampler assumptions, applicable operation/function bounds and error accounting for the complete request. NTRU invertibility/numerical screening and sparse public-map construction need their actual conditioning assumptions. Private-key fixture observations also do not validate a public-key encryption noise distribution. Until such evidence exists, paired entries must remain explicitly experimental arithmetic examples. Setup can reject encoding/layout violations using the existing owning boundary; no unproved probability threshold should be presented as a validator or added to online kernels.

## Historical numerical observations

The removed diagnostic used fixed seeds 42 and 4242. Its recorded scope was:

- PBS/ManyLUT at zero, interior and final messages, then zero again to reuse workspace; Boolean truth tables and an output-reconsumption chain.
- Uniform binary/ternary and fixed-weight classic/sparse keys, both GLWE orders, both word widths and both FFT engines.
- Ordinary CBS at t=4, every gadget coefficient/level/row, and nonconstant CMux candidates; NTRU one-hot at t=8 for every selector, including the default zero selector.
- MVB thresholds with 64 inputs and 17 outputs, including a threshold transition and the endpoint; returned flags used Scaled encoding under the external modulus.
- Complete lookup at 0, 1, 1023, 1024, 0x1234, 16383, 0, including quantized-phase guards and all three output chunks of a nonlinear function.
- Public LUT geometry at N=1024/2048, u32/u64 and native/q24/Barrett moduli, including odd t=255 and non-power-of-two output counts.

This list records historical coverage only. It is neither an executable suite nor
a claim that the current source has passed these checks.

The acceptance thresholds were fixed before parameter experiments. Decoded outputs required circular phase error < q/(4t), half the decoding radius; raw gadget coefficients required error < scalar/8; lookup outputs required error < q24/32=524288. The recorded fractions describe the corresponding budgets, not a noise standard deviation or a failure-rate estimate. CMux coefficients were checked individually. Samples with errors were rejected rather than counted as successful because another seed worked.

Historical observation from 2026-09-28: AMD Ryzen 9 9955HX3D, x86_64 Linux, repository `target-cpu=native`; stable rustc 1.98.0 (88d9e12ae), and nightly 1.100.0 (bff8e12ff) with SIMD. Both configurations passed the matrix registered at that time. After restoring the fixed-weight NTRU profile's original normalized input noise, all NTRU profiles were rerun in both configurations. The table is the maximum over both seeds, applicable secrets/orders and the two configurations. It is not a new validation of the source revision reviewed above or of all teaching functions/domains.

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

These are maxima of finite observations under explicitly selected bounds. They do not establish worst-case noise, a target decryption-failure probability, or security. Current validation commands and retained workspace coverage belong to the [testing guide](testing.md). The deleted TFHE suite and diagnostic are not part of current CI. No latency or memory improvement is inferred from this inventory review.

## Workload and measurement boundaries

Future benchmarks belong to each concrete backend or the high-precision LUT
crate. Each bench file will own its required helpers and measure a named workload
through the recommended public API. Public LUT creation, key generation and
homomorphic evaluation are distinct timing boundaries; setup that is not the
measurement target stays outside the timed iteration. There is no current
centralized TFHE benchmark or parameter-diagnostic entry point.

The historical observations used different domains from the teaching examples.
Fixed-weight PBS diagnostics used t=8 for GLWE and t=16 for NTRU; teaching sparse
examples use t=32. CBS teaching predicates use t_in=8 and t_ring=8, whereas the
identity diagnostic used 4/4. The one-hot benchmark used n728/h32 with the
diagnostic noise, not the teaching n800/h32 profile. The standalone lookup
diagnostic used c7/d5/o3 and classic uniform binary/ternary input secrets;
teaching lookup uses c8/d5/o8 and fixed-weight secrets. Finite observations and
timings cannot be assigned to one undifferentiated profile.

## Teaching examples

TFHE examples fix `Word = u64`, with `U64NttTable` for NTT and `RustFftTable` for Fourier. They retain the existing u64 profiles: Barrett Q50 for TFHE NTT, Native64 for Fourier, and independent PowOf2 q24 for NTRU returns. All 26 TFHE/LUT examples select their matching `experimental` config. Backend examples prepare a complete context directly with `try_from_pbs_config` / `try_from_cbs_config`; high-precision examples construct `NttHighPrecLutContext` / `FourierHighPrecLutContext` directly, without separate backend or resource wiring. Ordinary PBS/ManyLUT clients and compilers derive Rounded codecs from `config.messages`; MVB uses the same message config with Scaled output factories. No codec is supplied in these examples. Family `PbsParameters` own default client preparation and backend contexts delegate to them. Advanced same-key compositions reuse prepared codecs through the family `*_with_codec` factories without changing defaults. CBS/one-hot use `config.pbs.messages.input_modulus` and `config.gadget`; high-precision lookup derives its chunk format from `config.one_hot.pbs.messages.input_modulus` and takes independent counts and optional coefficient partition from `HighPrecLutConfig`. Ordinary CBS examples use t_in=8 and compute the predicate m >= 2 inside the same BR; the former CBS benchmark and parameter diagnostic used an identity t_in=4 workload. CBS/one-hot examples use the same `context.encryptor` and pass only independent t_ring to `context.accumulator_client`; CBS compilation and default evaluators use retained input/gadgets, without codec or resource wiring. This does not establish a noise budget. GLWE basic/CBS/ManyLUT examples fix BR→KS, and factorized MVB fixes KS→BR. The teaching files do not provide a word-width comparison matrix. The LWE basic and NTRU automorphism examples also use u64; the latter retains its small Q27 prime and `log_basis=3` decomposition. Application bytes, indexes and floating-point values keep their own types.

Examples start from typed constants in their backend's `experimental` module and keep workload choices explicit. The workflow appears in `main` before any parameter helpers. Client and server stages appear directly in `main`, identified by comments. Server setup uses public context, encoding and evaluation keys; CBS/one-hot candidates are encrypted by the client. High-precision lookup compiles the public function separately from key generation and evaluation. Each workload makes multiple requests with reused buffers. No example imports code from `benches/` or `tests/`.

| Workflow | Geometry and encoding | Complete examples |
| --- | --- | --- |
| Basic PBS | n=866/N=2048/t32; 2*x+y → min(z,6) → 2*score+[score>=4], x,y in 0..4; two successive PBS calls | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_basic.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_basic.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_basic.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_basic.rs) |
| Boolean access circuit | n=866/N=2048/t4; encrypted admin OR (member AND NOT revoked), affine NOT and two PBS gates | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_boolean.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_boolean.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_boolean.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_boolean.rs) |
| CBS → CMux → ring addition | n=800/N=1024; selector Rounded t8, ring messages Scaled t8; client encrypts fee plans A/B and extras, server selects by [m>=2] then adds extras | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_circuit_bootstrap.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_circuit_bootstrap.rs) |
| MVB thresholds | n=728/h32/N=1024/t128; 64 inputs, 17 outputs with Scaled t_out=2. NTRU compiles at Q and decodes at q24 with separate codecs | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/mvb_thresholds.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_mvb_thresholds.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_mvb_thresholds.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_mvb_thresholds.rs) |
| Sparse PBS | n=728/h32/N=1024/t32; the basic scoring pipeline with sparse BR: three copies, 64 buckets and a fixed-weight secret | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_sparse.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_sparse.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_sparse.rs) |
| Interleaved ManyLUT | n=728/h32/N=1024; one padded Rounded t16 input → Rounded t_out=8 grade=x/2 and flag=[x>=5] → code=2*grade+flag. Classic BR; NTRU compiles at Q and returns at q24 | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_many_lut.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_many_lut.rs); NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_many_lut.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_many_lut.rs) |
| Sparse CBS → CMux → ring addition | n=728/h32/N=1024; same fee-vector pipeline and message domains, using sparse BR and CBS material | GLWE [NTT](../../crates/primus_tfhe_glwe_ntt/examples/ntt_sparse_circuit_bootstrap.rs) / [Fourier](../../crates/primus_tfhe_glwe_fourier/examples/fourier_sparse_circuit_bootstrap.rs) |
| One-hot CBS → CMux | n=800/h32/N=1024/t8; four NGSWs for delta_r=[m=r], select public r=2 using the selector view | NTRU [NTT](../../crates/primus_tfhe_ntru_ntt/examples/ntru_ntt_one_hot.rs) / [Fourier](../../crates/primus_tfhe_ntru_fourier/examples/ntru_fourier_one_hot.rs) |
| High-precision lookup | n=800/h32/N=1024/t8; c8/d5/o8, two-bit chunks, piecewise fee with breakpoints 16384/49152; 16-bit input/output, N=1024 coefficient addresses and 64 logical polynomials per output before sharing/pruning | [NTT](../../crates/primus_tfhe_ntru_lut/examples/ntt_lookup.rs) / [Fourier](../../crates/primus_tfhe_ntru_lut/examples/fourier_lookup.rs) |

All examples are arithmetic demonstrations, not assessed security presets. NTRU consistently uses independent LWE q24 and a separate ring Q; its ordinary return path and MVB scaled-output distinction are visible in the code. The paired entries and remaining explicit configurations reproduce the recorded profiles above; their noise and decomposition choices remain specific to the workflow.

All four backends have separate classic PBS, sparse PBS, interleaved ManyLUT, ordinary CBS and factorized MVB entries. Each example fixes one algorithm: basic, Boolean, ManyLUT, CBS, one-hot, MVB and high-precision use classic BR; the dedicated sparse files use sparse BR. GLWE sparse CBS retains its separate entry. Algorithm choices do not turn each teaching file into another comparison matrix. One-hot and the full high-precision pipeline are NTRU extensions. ManyLUT and factorized MVB are distinct multi-output algorithms.

For NTRU sparse CBS, start from the fixed-weight n800/h32 `CLASSIC_ONE_HOT_U64` CBS config and set `pbs.algorithm = BlindRotationMethod::Sparse { copy_count: 3, bucket_count: 64 }` before context construction. Dense `CLASSIC_CBS_U64` does not satisfy the fixed-weight requirement. One-hot and lookup configs already use h32; their sparse variant changes only `pbs.algorithm` or `one_hot.pbs.algorithm`, respectively. The backend CBS READMEs show the config substitution; the [LUT material guide](../../crates/primus_tfhe_ntru_lut/README.md#evaluation-and-workspace) shows the sparse workflow and explicit public-lift composition.

Boolean gates, bivariate LUTs and odd full-domain LUTs are derived encoding/composition APIs, not additional blind-rotation algorithms. Boolean now has one standalone circuit example per backend. Other composition choices retain their [user guide](../../crates/primus_tfhe/README.md#choosing-an-operation); this list does not claim a standalone example or current automated coverage for every public wrapper or secret distribution.

### Choosing the lookup example width

The two teaching examples use eight two-bit input chunks and eight output chunks (16 bits each), with d=5 and N=1024. Their piecewise fee is x/4 below 16384, 4096+(x-16384)/2 below 49152, and 20480+(x-49152) thereafter. Branch choice depends on high input chunks, and the maximum result 36863 fits 16 output bits. Seven requests cover the breakpoints, endpoints and an interior value. These examples are separate from the historical c7/d5/o3 parameter-diagnostic fixture above.

With output count equal to input count and K=N, the worst-case complete data table costs `c * 4^c * sizeof(Word)` bytes before polynomial sharing and selection pruning. This is public coefficient storage only, excluding plan metadata, keys, evaluators and outputs; the example function can use less:

| Input/output chunks | Input/output bits | Table-selection chunks | Polynomials per output | Data LUT, u32 / u64 |
| ---: | ---: | ---: | ---: | ---: |
| 6 / 6 | 12 / 12 | 1 | 4 | 96 / 192 KiB |
| **8 / 8** | **16 / 16** | **3** | **64** | **2 / 4 MiB** |
| 10 / 10 | 20 / 20 | 5 | 1024 | 40 / 80 MiB |

Eight chunks demonstrate a 16-bit lookup with three high chunks available for table selection at a modest worst-case table size; sharing and pruning depend on the function. Ten chunks work in the sampled trials but raise table storage by 20 times over eight; use them for an explicitly larger workload. Counts remain independent in the API. This is an example-size choice, not an algorithmic precision limit.

The historical 6/8/10 comparison used NTT and RustFFT, u32/u64, seeds 42 and 4242, and inputs `4^c-1`, `floor(2*4^c/3)`, `floor(4^c/3)`, 1 and 0, with output reduced modulo `4^c`; all 120 evaluations decoded correctly. The selected eight-chunk profile was additionally checked with both FFT engines, both words, default and nightly SIMD: two seeds, inputs 0b10_10_10_11_11_00_11_01, 0, 1, 1023, 1024, 65535, 0, and each returned chunk's circular phase error below q24/32. These historical finite checks do not establish a failure probability or current test coverage.

### Example smoke checklist

Compile the teaching targets, then run representative workflows from the changed
families in release mode. Select coverage for the change; these large examples do
not form a mandatory CI matrix.

```sh
cargo check -p 'primus_tfhe*' -p primus_lwe -p primus_ntru --examples --features ntt,rustfft
cargo run --release -p primus_tfhe_glwe_ntt --example ntt_basic
cargo run --release -p primus_tfhe_glwe_fourier --example fourier_circuit_bootstrap --features rustfft
cargo run --release -p primus_tfhe_ntru_ntt --example ntru_ntt_one_hot
cargo run --release -p primus_tfhe_ntru_fourier --example ntru_fourier_mvb_thresholds --features rustfft
cargo run --release -p primus_tfhe_ntru_lut --example ntt_lookup --features ntt
```

The source's known-result checks cover both requests and reused buffers when an
example is run. These examples do not replace the removed test suite, nor do they
cover every word, engine, order or algorithm. New tests should cover independent
contracts with small parameters after the recommended workflows are settled;
examples should not become matrix dispatchers. When a change specifically
concerns the other FFT engine, change the example's table import and
`required-features` together, then restore the documented defaults.

The public examples retain distinct GLWE/NTRU parameter, key and return contracts and distinct NTT/Fourier table types. Within a crate there is one entry per task. Configuration is intentionally local to each file so that users can read and change it directly; there is no example support layer hiding parameters or the workflow.
