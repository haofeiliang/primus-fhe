# Workspace and preparation costs

[Performance guide](README.md) · [Ownership contracts](../development/composition.md#reusing-workspaces) · [Current benchmark commands](../development/testing.md)

Reuse prepared state across requests, but decide cross-stage buffer sharing,
alignment and ownership independently. Smaller storage and fewer allocations
do not by themselves establish lower latency. These historical comparisons
retain the useful costs and counterexamples; detailed migration tables are
available in Git at `bbf235ed`, not maintained as descriptions of current APIs.

Unless noted otherwise, measurements used Ryzen 9 9955HX3D, x86_64 Linux,
rustc 1.98.1 / LLVM 22.1.8, release and repository native CPU flags. Builds and
measurements ran separately. CPU 4/8 are different cache groups on that one
machine. Each timed iteration performs one named operation; setup and diagnostics
are outside timing unless they are the construction being measured. Percentage
changes compare the same workload on the same CPU. Historical functional
parameters and successful decryptions are not security/DFR certificates.

Requested allocation traffic, retained heap, live peak and inline metadata are
different quantities. Heap observations exclude allocator overhead and RSS;
resource-set comparisons include owners moved outside an evaluator. A shorter
object or different owner does not imply that its buffers disappeared. Historical
allocation probes are not current test coverage, and no counter API is required
to consume these results.

## Aggregate scratch addresses

The 2026-10-04 diagnostic GLWE NTT sparse CBS experiment compared using one
aggregate address with alternating two addresses between buckets. The fixture
was u64/n728/h32/N1024/k1, Q1125899906826241, BR logB8/L6, r3/B64, t4,
BR→KS, client/server seed 42, independent input seed 43 and message 1. See the
[historical profile](sparse-layout-and-batching.md#historical-fixtures-and-evidence).

Both policies retained two ordinary Vec buffers and used the **same executable**,
keys, input and workspace. A runtime mask selected A for every bucket or A/B by
bucket parity. Dummy copy overwrote the chosen buffer; aggregation, in-place NTT
and product order were unchanged. Each aggregate was 192 KiB; either experimental
policy retained 581312 bytes versus production's 384704 bytes. Thus alternating
addresses would cost another allocation and 192 KiB, not save memory.

Each process ran ABBA followed by BAAB, 30 samples, 0.5 s warmup and 2 s target
per round. Values are averages of four round means with their ranges, in ms;
they are descriptive summaries, not pooled confidence intervals:

| Process / CPU | Reuse A | Alternate A/B | Change |
| --- | ---: | ---: | ---: |
| First / 4 | 16.370 (16.311–16.420) | 16.366 (16.333–16.397) | -0.025% |
| Second / 8 | 17.016 (16.960–17.074) | 17.029 (17.004–17.054) | +0.076% |
| Fresh / 4 | 16.182 (16.178–16.194) | 16.194 (16.176–16.230) | +0.073% |

Intervals overlapped in every process, with no stable complete-request benefit.
Both arrays had offset 16 modulo 64 and modulo 4096, separated by 200704 bytes;
this was not a controlled alignment or physical-page sweep. Outputs matched
exactly. Hardware counters were unavailable (`perf_event_paranoid=4`), so the
result cannot identify cache writeback, store forwarding or false dependencies.
Keep one aggregate for this path. This says nothing about sharing BR/trace/SS
roles, Fourier, other shapes or parallel requests. The temporary second buffer
and dispatch were removed.

## Alignment and fixed containers

On 2026-09-28, temporary lattice consumers compared identical transformed NTRU
key coefficients borrowed from Vec versus cache-aligned ABox. Both used the same
nightly `1.100.0-nightly (bff8e12ff)` / LLVM 23.1.0, CPU 0, N1024, with default and
Cargo SIMD features measured separately. The representative recheck used
Q998244353/base 2/L15 (u32 NTT), Q1125899906826241/base 8/L6 (u64 NTT), and native
Fourier base 2/L16 or base 8/L8. One coefficient external product was timed;
conversion and equality checks stayed outside. Sampling: 15 samples, 0.3 s
warmup, 1.2 s target, ordinary storage before aligned storage.

| Backend / word | Default Vec → ABox, µs | SIMD Vec → ABox, µs |
| --- | ---: | ---: |
| NTT / u32 | 7.945 → 7.915 | 7.981 → 7.960 |
| NTT / u64 | 5.184 → 5.162 | 5.261 → 5.222 |
| RustFFT / u32 | 10.581 → 10.557 | 10.676 → 10.647 |
| RustFFT / u64 | 6.249 → 6.233 | 6.237 → 6.223 |
| TFHE-FFT / u32 | 7.735 → 7.679 | 7.648 → 7.559 |
| TFHE-FFT / u64 | 4.604 → 4.568 | 4.655 → 4.633 |

These small differences do not justify migrating all keys. Ordinary allocation
already yielded offsets 0/16/32 modulo 64; ABox guaranteed 128-byte alignment on
this target. Order/system drift was not isolated. N1024 polynomial strides
preserve base alignment, while n+1 LWE rows generally do not; aligning an outer
container does not align separately owned inner buffers. No padding or online
conversion follows from this comparison.

The related complete c8/d5/o8 lookup comparison changed only fixed Box/ABox
workspace fields back to Vec/AVec, retaining lengths, alignment and exact
capacity. Both variants used that same nightly SIMD configuration and CPU 0;
Box was measured first. Vec/AVec ranged from about 0.7% faster to 1.6% slower
across NTT and both FFT engines at u32/u64, with identical retained coefficient
heap and no consistent advantage. Keep fixed-length ownership without claiming
a boxed-storage speedup.

An earlier `e55ec2e` lookup at n64/N1024/M4/c7/d5/o3 saved 25 KiB (NTT) or
41 KiB (Fourier) through workspace consolidation. Its pinned SIMD means were
7.084→7.053 ms, 7.985→8.169 ms and 6.289→6.256 ms for NTT/RustFFT/TFHE-FFT.
The RustFFT increase was about 2.3%; retaining AVec only in the product workspace
recovered part, not all, of it. This establishes a memory/latency tradeoff, not a
universal reuse benefit. Both lookup studies predate the current fixed tree and
its parameters; their absolute times cannot be compared as a before/after pair.

## Prepared state and ownership

Sharing immutable preparation has an initial owner cost. The 2026-10-03
comparisons retained ordinary parameters, one derived gadget parameter and one
gadget clone together; reported totals combine inline size and requested heap:

| Study | Three-object storage before → after | Tradeoff |
| --- | ---: | --- |
| NTRU vs `d8eedf4f`, sparse ternary | 2960 → 1336 B | One extra 464-byte initial allocation; gadget bases remain separately owned. |
| NTRU, Gaussian secret sigma 3.2 | 3920 → 1656 B | Reuses larger sampler state; no global interning. |
| RNS shared base, two Q50 limbs | 3888 → 3208 B | Initial Arc/cache storage grows, repeated base clones no longer duplicate it. |

NTRU used u64/N1024/t16, noise 3.2; RNS used k1/N1024, t2,
Q=[1125899906826241,1125899906629633], gamma 2305843009213554689 and logB20.
The online NTRU encryption screen found no established regression; RNS conversion,
BFV and key-switch rechecks were roughly within 1%. These short default-feature
checks support avoiding preparation duplication, not faster encryption or a
general latency bound. Full original fixture and sampling details remain in Git.

A separate NTRU return-workspace change against `a0d5716e` removed unused
return buffers from the historical n800/N1024/c8/d5/o8 lookup evaluator. At u64,
NTT retained heap fell 912520→787464 B and Fourier 1068168→1059968 B. The savings
were respectively `(N+8*(N+1)+8*(n+1))*sizeof(T)` and `(N+1)*sizeof(T)`; work
required by other consumers was not removed. Complete-request changes were
small or changed direction on recheck. Select buffers by actual operation needs;
these numbers are neither current evaluator sizes nor an algorithmic speedup.

Borrowing shared operation resources preserved the complete resource sets'
coefficient heap. The 2026-10-03 GLWE NTT migration against `d566a73a` nevertheless
showed sparse CBS increasing from 16.640/16.730 to 17.037/17.316 ms (BR→KS) and
16.682/16.733 to 17.255/17.328 ms (KS→BR) on CPU 4. CPU 8 did not reproduce it.
Removing an inline hint helped some sparse observations but harmed classic CBS;
that experiment was reverted. A later comparison with `def858ef` on both CPUs
also failed to reproduce the original 3–4% increase. It was not a bisect, and it
does not invalidate the earlier result. Unchanged arithmetic/heap alone cannot
prove performance parity or identify the cause of code-layout sensitivity.

## Complete consumers of reusable state

Two 2026-10-10 API changes were measured with u64, default arithmetic, seed 42,
N1024, Q50 for NTT and Native for Fourier, external q24 for NTRU. Temporary
Criterion consumers ran adjacent before/after binaries on each CPU separately,
30 samples, 1 s warmup and 3 s target. They timed complete requests, excluding
setup, encryption and output allocation.

- **MVB owns prepared PBS state**, compared with `aba0b657`: n728/h32,
  Rounded t_in=128, Scaled t_out=2, D64 and 17 outputs, GLWE KS→BR, input 63.
  No buffer was duplicated; retained evaluator heap was unchanged and inline
  metadata fell by 8 B. GLWE NTT, NTRU NTT and NTRU RustFFT stayed close to their preceding times; GLWE RustFFT fell from 16.304→15.317 ms
  on CPU 4 and 15.828→15.019 ms on CPU 8. The choice simplifies ownership; these
  pairs do not establish a general speedup or sparse/BR→KS result.
- **One-hot four-way consumption**, compared with `21440eab`: n800/h32,
  M4/t8, three base 256 output levels, Scaled candidates t_ring=8 and input 3.
  Four coefficient-repeated records were [0,1,2,3], [1,3,0,2], [3,0,1,2] and
  [2,1,3,0]. Both methods generated only δ1…δ3. Fused k-CMux replaced copying
  C0 plus three serial CMux calls with one transform-domain sum/conversion.
  Classic changes were approximately -1% to +0.5%; sparse r3/B64 changes
  -1.5% to +0.3%, across NTT and both FFT engines. Retained consumption storage
  fell by 8192 B, one N1024/u64 ciphertext. Simpler use and one fewer buffer are
  established; a general latency gain is not.

The fused consumer has its own sum-of-product error budget and, in Fourier,
one conversion after summation. Serial CMux noise estimates and bitwise outputs
cannot be assumed interchangeable. See [one-hot consumption](../development/bootstrapping-contracts.md#one-hot-cbs).

## Public-key sampler reuse

A 2026-10-09/10 study against `fe4111a4` retained the raw LWE generator's explicit
sampling dependencies and inline hint, but rejected GLWE sampler reuse. CPU 4,
u64 binary secrets, Q50/Native64, n800 for BR→KS and n1024 for KS→BR; seeds 42
and 4242. Each iteration allocated and generated all n zero rows, excluding
output destruction and fixture preparation. Two order-reversed pairs used
30 samples, 1 s warmup and 2 s measurement; no FFT was involved.

| Full generation | Raw API + inline, retained | Also reuse order-specific samplers, rejected |
| --- | ---: | ---: |
| Q50 / BR→KS | -0.41% to -0.15% | +0.44% to +1.06% |
| Native64 / BR→KS | -0.17% to +0.57% | -3.10% to -2.50% |
| Q50 / KS→BR | -0.48% to -0.07% | +3.42% to +5.19% |
| Native64 / KS→BR | -2.24% to -2.23% | -3.09% to -2.64% |

Columns use separate original/modified pairs; ranges are observed changes, not
confidence intervals. Sampler reuse saved 624 B of peak requested storage at
Q50 or 7353 B at Native64, beside an 8,396,800-byte n1024 matrix. That small saving
did not justify the repeated Q50 regression. Output rows and subsequent RNG
state matched. CPU 8/SIMD were not timed, and no online PBS/CBS gain follows.

## Preparation data and measurement scope

Three small CSVs preserve complete-constructor comparisons measured on 2026-10-10.
Each uses the host/toolchain above, CPU 4, two saved executables in ABBA order,
30 samples, 1 s warmup and 2 s target, with no concurrent build. Default arithmetic
was used; specialized transform tables could still dispatch native kernels.
Parameters, secrets, caller workspaces and arithmetic domains existed before
timing. Each iteration generated/constructed **and dropped** one complete result.
These are setup costs, not online trace, PBS or CBS acceleration.

| CSV | Rows | Baseline | Workload and interpretation |
| --- | ---: | --- | --- |
| [RNS key sets](data/rns-key-set-preparation.csv) | 5 | `2fa5863d` | CRT/DCRT trace and expansion, DCRT reverse trace; one binding and reusable local scratch. |
| [NTRU trace](data/ntru-trace-preparation.csv) | 3 | `08cc5af4` | NTT, RustFFT, TFHE-FFT trace-key generation; encode secret once. |
| [NTT root construction](data/ntt-root-construction.csv) | 8 | `53a0307a` | Generic/specialized complete N4096 tables, four word/modulus cases. |

`before_r1_us`, `after_r1_us`, `before_r2_us`, `after_r2_us` are Criterion mean
point estimates in microseconds; r2 reverses the order of r1.
`change_r*_percent = 100*(after/before-1)`. No confidence intervals or raw sample
distributions are stored. Allocation columns in the first two CSVs are separate
single-constructor observations with the result retained: `*_allocations` counts
allocation/reallocation requests, `*_allocated_bytes` is requested traffic,
`*_retained_bytes` is live requested storage at return and `*_peak_bytes` its
maximum above the pre-call state. They exclude caller resources, allocator
metadata and RSS. They are not additional timing samples.

### RNS key-set preparation

N1024/u64/k2, sparse ternary secret, sigma 3.2,
Q=[1125899906826241,1125899906629633], logB20/L5, t12289,
gamma 2199023190017. Secret seed 42; generation RNG starts at 4242 and advances
between iterations. Complete constructors include metadata and expansion/reverse
normalization preparation. One checked DCRT encryptor binding replaces log2(N)
identical bindings, reducing ordered-modulus comparisons from O(m log N) to O(m)
for m limbs. CRT checks its coefficient-key layout once; per-degree permutation,
encoding and encryption remain in order, with distinct CRT/DCRT scratch.

All five constructor comparisons improved by about 0.96–1.52% across the two
pairs. CRT saved 18 allocation requests/216 KiB of traffic, DCRT 9/144 KiB.
Retained and peak bytes were unchanged: the old last degree already held the
same scratch beside earlier keys. Local Zeroizing scratch is erased and released
on return/unwind; no online workspace grows. Historical coefficient/RNG captures
matched. Rebuilding this workload requires complete key generation and drop;
the crate's online trace/expansion benches measure different operations.

### NTRU trace preparation

N1024/u64, sparse ternary secret, sigma 3.2, logB10 with all valid levels:
L5 at Q1125899906826241 for NTT, L6 at Native64 for Fourier. Features were
`ntt,rustfft,tfhe-fft`, without Cargo SIMD; secret seed 42 and advancing keygen
RNG seed 4242. Tables, FFT engines and caller gadget workspace were outside timing.
These are not equivalent NTT/Fourier noise budgets.

One secret encoding and two local coefficient buffers replace log2(N) encodings
and 2*log2(N) buffers; degree/row sampling order stays unchanged. Each backend
saved 18 requests and 144 KiB of traffic, with identical retained/peak bytes.
Latency ranged from about -0.06% to +0.37%, establishing no speedup. Buffers remain
Zeroizing and disappear before return; standalone generation retains its own
checks. Historical coefficients and subsequent RNG words matched.

### NTT root preparation

At N4096, the CSV identifies each word, modulus and generic/specialized table.
For D=2N in a prime field, stepping by the sampled primitive root's square visits
the D/2 distinct odd powers, exactly the primitive roots. The prior D-step scan
visited that orbit twice. Scanning D/2 returns the same minimum, with unchanged
random root search and no extra storage. Full construction/drop improved by
about 13–19%; it did not halve the constructor or change online transforms.

The [construction benchmark](../../crates/primus_ntt/benches/bench_ntt.rs) retains
this workload family; use the historical revisions and N4096 cases for an
equivalent comparison. CPU 8, other sizes, u32 NTRU/RNS timing and nightly-feature
latency were outside these three preparation studies. The CSVs remain unchanged;
temporary key-generation probes are not maintained as public benchmark APIs.

## Fixed complete NTRU lookup tree

The current [fixed tree](../development/bootstrapping-contracts.md#fixed-complete-high-precision-lookup)
retains all public polynomials and executes every selection layer. Compared with
`b1a716ff` on 2026-10-10, the compiler no longer hashes/interns polynomials or
maintains a pruned graph. This enforces function-independent work; repeated
functions can require much more storage and evaluation than before.

The controlled comparison used classic u64/n800/h32/N1024/M4/c8/d5/o2,
Q50/NTT or Native/RustFFT and external q24. The map was the low four bits of
SplitMix64(x): add `0x9e3779b97f4a7c15`, then xor shifts 30/27/31 and multipliers
`0xbf58476d1ce4e5b9` / `0x94d049bb133111eb`. Seed 4242, input 43981.
The old compiler confirmed 128 logical and 128 unique polynomials, 42 selection
nodes, no standalone lifts and all eight one-hot inputs. Both versions therefore
executed complete selection work. This is not a pruned-function comparison.

Saved binaries ran consecutively on CPU 4, then CPU 8, features
`ntt,rustfft,tfhe-fft` but only NTT/RustFFT timed, without Cargo SIMD. Criterion:
30 samples, 1 s warmup, 3 s target. `evaluate_to` measured both returned outputs;
all preparation was excluded. Compile/drop included output-major enumeration.
Mean estimates with 95% intervals:

| CPU / backend | Old evaluate → fixed tree, ms | Old compile/drop → fixed tree, µs |
| --- | --- | --- |
| 4 / NTT | 45.769 [45.698,45.844] → 45.063 [44.888,45.245] | 385.33 [385.07,385.57] → 234.82 [234.78,234.86] |
| 4 / RustFFT | 52.778 [52.490,53.080] → 52.947 [52.732,53.205] | 384.14 [383.94,384.32] → 234.66 [234.54,234.84] |
| 8 / NTT | 51.200 [51.062,51.362] → 51.365 [51.226,51.537] | 370.15 [369.85,370.53] → 225.83 [225.77,225.91] |
| 8 / RustFFT | 62.167 [62.018,62.340] → 62.005 [61.818,62.227] | 366.13 [365.96,366.42] → 226.94 [226.90,226.98] |

No evaluation regression was detected here; only CPU 4 NTT showed an improvement.
Compile/drop fell about 38–39%. Public coefficient storage stayed 1 MiB in this
nonrepeating case. Intermediate selection buffers increased from seven to eight
NTRU slots (56→64 KiB), replacing graph slot/liveness metadata with contiguous
child groups. Total peak was not measured. These results do not establish a
universal online gain, repeated-function cost, or latency/noise margins for the
current M16/N4096 cases.
