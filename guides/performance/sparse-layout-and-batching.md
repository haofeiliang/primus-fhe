# Sparse layout, scheduling and input batching

[Performance decisions and measurement method](README.md) · [Baseline and parameters](sparse-baseline.md) · [Arithmetic](sparse-arithmetic.md)

Retain the existing key layout and full-control aggregation. The tile,
first-bucket and streaming prototypes did not establish a sufficient repeatable
complete-request gain. Retain the fixed two-input NTRU LUT window, whose extra
state and full-lookup benefit are measured separately below. These are local
choices, not a general rule to merge or split scratch buffers.

Historical experiments below use Ryzen 9 9955HX3D, rustc 1.98.1, release and the
repository's native CPU flags unless a section says otherwise. Word width,
features, parameters, source baseline and sampling settings stay attached to
individual results; a short-run signal is not a new universal performance claim.

## Coefficient aggregation tiles

**2026-10-04; baseline `501c90ac`. Decision: retain the existing untiled
NTRU and GLWE Fourier aggregation.** The [NTRU pair optimization](sparse-arithmetic.md#ntru-paired-coefficient-aggregation) remains unchanged. These experiments do not justify a general tile policy or an accepted
word-specific replacement. GLWE NTT's existing tile policy was not changed.

### Method and remaining cost

Use the [baseline](sparse-baseline.md#conditions-and-workload-pairing) n728/h32/N1024, r3/B64, t8 sparse PBS fixtures and seeds.
The request includes the ordinary output return, including NTRU Q→q/extraction/KS.
No modulus, basis, key layout, sampling or arithmetic kernel changed. Compare
complete-polynomial tiles of 8, 16 and 32 KiB with a whole control: copy the dummy
once, traverse tiles outside the existing selector-pair loop, then transform the
**completed** aggregate. Each pair reads the corresponding source polynomial
range; an odd last selector still uses the single-input kernel. No encrypted
zero or zero exponent is skipped, and no tile owns a new buffer.

The AMD Ryzen 9 9955HX3D, rustc 1.98.1, repository `target-cpu=native` and default
features plus `rustfft,tfhe-fft` were held fixed. CPU 4 and CPU 8 are on different
CCD/cache groups. Builds/tests ran separately from latency measurements. Power,
frequency and unrelated system activity were not controlled. `perf_event_paranoid=4`
prevented hardware-counter evidence; these timings do not identify cache misses,
writeback latency or DRAM traffic.

A temporary `Instant` probe around each bucket's aggregation, control transform
and external product reconfirmed the remaining u64 cost. These are median stage
sums from up to the last 100 warmed requests, in ms, **not acceptance timings**:

| Backend, u64 | Requests retained | Aggregate | Transform | External product | Aggregate bytes | BR coefficient-array bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ntru / ntt | 100 | 2.885 | 0.276 | 0.425 | 49,152 | 110,493,696 |
| ntru / rustfft | 87 | 3.304 | 0.270 | 0.440 | 65,536 | 147,324,928 |
| glwe / rustfft | 28 | 13.725 | 1.032 | 1.059 | 262,144 | 589,299,712 |

All tables below use freshly rebuilt **uninstrumented** binaries. Early comparisons
were discarded after detecting a reused instrumented library artifact when saved
source was restored with an older mtime. Rebuilding with fresh source timestamps,
checking the build log, and checking both binaries and run logs for probe markers
preceded the replacement measurements. The discarded timings are not mixed into
these tables. Key/input capture and correctness assertions execute outside `b.iter`.

### Whole-control versus constant tiles

CPU 4 screening used 15 samples, 0.3 s warmup and a 1 s measurement target.
Run the whole-control baseline before and after each candidate series. Cells
contain the point mean and Criterion's 95% confidence interval in ms; the two
baseline cells are distinct fresh processes. GLWE uses BR→KS in this screen.

| Backend / word | Whole, first | 8 KiB | 16 KiB | 32 KiB | Whole, last |
| --- | --- | --- | --- | --- | --- |
| glwe / rustfft / u64 | 16.088 [15.803, 16.436] | 19.577 [19.347, 19.825] | 18.484 [18.260, 18.729] | 18.080 [17.882, 18.317] | 15.932 [15.803, 16.089] |
| ntru / ntt / u64 | 4.723 [4.676, 4.784] | 5.280 [5.219, 5.355] | 5.065 [4.999, 5.139] | 4.938 [4.891, 4.997] | 4.704 [4.658, 4.764] |
| ntru / rustfft / u64 | 5.417 [5.264, 5.638] | 5.644 [5.581, 5.721] | 5.362 [5.314, 5.421] | 5.388 [5.324, 5.470] | 5.333 [5.267, 5.414] |

The u64 NTRU NTT and GLWE Fourier candidates regressed; NTRU RustFFT had no
convincing gain. The u32 screen retained the two larger candidates:

| Backend / word | Whole, first | 16 KiB | 32 KiB | Whole, last |
| --- | --- | --- | --- | --- |
| glwe / rustfft / u32 | 20.992 [20.701, 21.354] | 21.798 [21.572, 22.160] | 21.277 [21.065, 21.521] | 20.819 [20.593, 21.177] |
| glwe / tfhe_fft / u32 | 19.930 [19.701, 20.219] | 21.140 [20.841, 21.514] | 20.531 [20.277, 20.883] | 19.890 [19.667, 20.158] |
| ntru / ntt / u32 | 5.044 [4.998, 5.097] | 5.517 [5.465, 5.578] | 5.441 [5.401, 5.488] | 5.109 [5.044, 5.181] |
| ntru / rustfft / u32 | 6.130 [6.071, 6.203] | 5.788 [5.743, 5.841] | 5.730 [5.679, 5.793] | 6.132 [6.027, 6.289] |
| ntru / tfhe_fft / u32 | 5.786 [5.751, 5.828] | 5.513 [5.429, 5.648] | 5.438 [5.384, 5.519] | 5.779 [5.727, 5.843] |

Only the NTRU Fourier u32 constant-tile prototype showed a useful signal. That
alone cannot justify tiling u64, or prove that a word-specific implementation
will preserve the gain.

### Candidate that preserves the u64 whole-control path

The reviewable candidate selected `max(32 KiB / size_of::<T>(), N)` only for u32
and the full control length otherwise, in the same tile loop. NTRU retained its
`NlevIter` and borrowed level ranges. GLWE moved its existing pair traversal into
an inline private bucket helper; tiles used the flat polynomial-batch kernel,
since a tile need not be a whole GGSW. The numerical order within each polynomial
remained unchanged.

CPU 4 used before/after/after/before; CPU 8 reversed that order. Each request used
30 samples, 0.5 s warmup and a 2 s measurement target. Means below are individual
runs; delta compares their arithmetic averages. CI envelopes are the min/max of
individual 95% CIs, **not a pooled confidence interval**.

| CPU / backend / word | Whole means | u32-only tile means | Delta | Whole CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| 4 / glwe / rustfft / u32 | 20.883 / 20.970 | 21.582 / 22.290 | +4.8% | [20.749, 21.184] → [21.399, 22.514] |
| 4 / glwe / tfhe_fft / u32 | 19.836 / 19.910 | 20.173 / 21.146 | +4.0% | [19.668, 20.089] → [20.026, 21.382] |
| 4 / ntru / rustfft / u32 | 6.126 / 6.098 | 6.284 / 6.267 | +2.7% | [6.060, 6.202] → [6.216, 6.333] |
| 4 / ntru / tfhe_fft / u32 | 5.842 / 5.820 | 5.994 / 5.991 | +2.8% | [5.781, 5.903] → [5.932, 6.071] |
| 8 / glwe / rustfft / u32 | 21.466 / 22.561 | 21.256 / 21.280 | -3.4% | [21.286, 22.787] → [21.057, 21.516] |
| 8 / glwe / tfhe_fft / u32 | 19.589 / 19.602 | 20.048 / 20.251 | +2.8% | [19.430, 19.822] → [19.862, 20.538] |
| 8 / ntru / rustfft / u32 | 6.701 / 6.714 | 6.950 / 7.026 | +4.2% | [6.657, 6.771] → [6.864, 7.077] |
| 8 / ntru / tfhe_fft / u32 | 6.432 / 6.403 | 6.590 / 6.902 | +5.1% | [6.352, 6.540] → [6.526, 7.092] |

NTRU's u32 gain did not survive this version; GLWE's result was not consistent
across CPUs/engines. A final NTRU-only check forced the private bucket helper to
inline, leaving the same u32/whole-u64 policy. Symbol inspection confirmed the
out-of-line helper disappeared, but the complete request still did not recover
the constant-tile gain. CPU 4 used the same 30-sample ABBA settings:

| Backend / word | Whole means | Forced-inline candidate means | Delta | Whole CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| ntru / rustfft / u32 | 6.170 / 6.077 | 6.249 / 6.147 | +1.2% | [6.033, 6.223] → [6.108, 6.294] |
| ntru / rustfft / u64 | 5.289 / 5.367 | 5.313 / 5.318 | -0.2% | [5.244, 5.446] → [5.268, 5.377] |
| ntru / tfhe_fft / u32 | 5.822 / 5.851 | 5.977 / 5.884 | +1.6% | [5.752, 5.922] → [5.833, 6.106] |
| ntru / tfhe_fft / u64 | 5.165 / 5.247 | 5.174 / 5.245 | +0.1% | [5.124, 5.312] → [5.126, 5.301] |

These observations do not prove tiling can never help NTRU u32, nor identify the
code-generation difference responsible for the prototype/candidate gap. They do
reject these candidates as a default change. No additional code-generation or
parameter search was retained just to recover one screening result.

### Correctness, resources and stopping point

- All 83 captures from the uninstrumented comparisons matched the corresponding
  key/public-map/input fingerprint and the **complete ciphertext output**, across
  nine request IDs. Every timed fixture also passed its independent decrypt check.
- Three temporary direct-scatter unit oracles passed for NTT and both Fourier
  aggregators, in u32/u64. They covered N=32 and N=1024, nonconsecutive indices,
  empty/odd/even selector lists, mixed signs, exponent 0/N−1/N/2N−1, dummy reset,
  dirty-buffer reuse and short final tiles. The GLWE case used 27 polynomials
  (k=2/L=3), crossing row/level boundaries. All 432 measured oracle calls allocated
  zero times. Those tests were removed with the rejected implementation.
- BR coefficient-array footprints remained 119,701,504 / 110,493,696 bytes for
  NTRU NTT u32/u64, 147,324,928 for either NTRU Fourier word, and 589,299,712 for
  either GLWE Fourier word. Logical coefficient contributions are unchanged;
  tiling revisits index/exponent arrays more often.
- Aggregate storage stayed 52/48 KiB for NTRU NTT u32/u64, 64 KiB for NTRU
  Fourier, and 256 KiB for GLWE Fourier. Existing transformed buffers stayed
  128/64 KiB for NTRU Fourier and 512/256 KiB for GLWE Fourier. These are relevant
  buffers, not total workspace/RSS. No owner, constructor, key or allocation layout
  changed. Constructor/keygen peaks were not remeasured; earlier resource tables
  must not be presented as new peak measurements.

The ordinary PBS screening exit condition was met, so this experiment did **not**
expand into new CBS, one-hot, high-precision LUT, GLWE KS→BR or SIMD performance
matrices. There is no retained execution-path change needing that acceptance
matrix. After source restoration, all-targets check passed for the three
experimental backends and 57 existing tests passed for them plus NTRU LUT (features
`ntt,rustfft,tfhe-fft`, `--lib --tests`). These correctness tests do not substitute
for performance measurements of those consumers.

For reproduction, build separate baseline/candidate `sparse_pbs` executables with
`cargo bench -p <backend> --bench sparse_pbs --features rustfft,tfhe-fft --no-run`,
rebuilding the library after every source restore. Pin each saved binary with
`taskset -c 4` (or `8`), use separate Criterion output directories and the settings
above, and select `/sparse/complete$`; GLWE screening additionally selects
`BootstrapKeyswitch`. Keep setup/capture outside timing and use one complete PBS
per iteration. Reconstruct the tile traversal described above without changing
key layout or pair arithmetic, and revalidate the executable rather than relying
on a previously built artifact. All experimental source, capture hooks and
executables were removed; no new benchmark or permanent test is retained.

## GLWE first-bucket trivial input

**2026-10-04; baseline `575de611`. Decision: retain the general first-bucket
external product.** The algebraic specialization is valid, but this experiment
found no repeatable complete-request gain. No production API, key layout,
workspace, benchmark or test change is retained.

### Preconditions and exact scope

Both GLWE PBS orders enter sparse BR with a freshly initialized accumulator
`(0, …, 0, P)`, where `P = X^(-R(b)) * LUT`. KS→BR first prepares the small LWE,
then the same raw BR kernel overwrites every mask polynomial with zero. Previous
workspace contents and the input order do not change this invariant.

For the current `ApproxSignedBasis`, `init_value_carry(0) = (0, false)`:
non-power-of-two adjustment starts at a strictly positive threshold, while a
native power-of-two basis either extracts a zero carry bit or initializes it to
false. Each decomposer subsequently receives `(0, false)` and emits the same
pair. This holds with both full and truncated levels. See the
[basis initialization](../../crates/primus_decompose/src/primitive/basis.rs) and
[digit/carry kernel](../../crates/primus_decompose/src/primitive/common.rs).
Consequently, in the sum over the `k+1` GLev rows, only the body row contributes.
The actual Fourier transforms/products are finite, so the skipped zero terms
also contribute no approximation error; this was independently checked below.

The temporary candidate kept **all** first-bucket coefficient aggregation,
control transforms, encrypted selections and dummy material. A temporary product
entry reused the existing workspace and processed only the final input/key row
for bucket zero; every subsequent bucket used the original full product. Thus
only zero-mask decomposition, digit transforms and multiply-adds were removed;
output clearing, body work and inverse transforms remained. No scan for zero
coefficients, public empty-bucket skip, altered initial rotation or new scratch
was introduced. This is the prerequisite external-product experiment, **not**
an evaluation of first-bucket GLev storage or body-row-only aggregation.

### First bucket and complete requests

The fixtures use u64, n728/h32/N1024/k1, r3/B64 and unchanged diagnostic parameters:
PBS t8, CBS t4; both orders, NTT and the two Fourier engines. The CPU/toolchain/features
are those above, with timings pinned to CPU 4. No builds/tests overlapped timing.
Each fixture retained the same deterministic client/key/input seeds and verified
its decrypt or CBS CMux result outside timing.

Separate instrumented binaries measured the three first-bucket stages with
`Instant`. Each case supplied 28 observations; rows below give the range of
per-case medians over PBS/CBS and both orders, in **microseconds**, not confidence
intervals. Total includes aggregation, control transform and external product;
probe/code-generation overhead was not subtracted.

| Backend | First bucket total, general → candidate | First external product, general → candidate |
| --- | --- | --- |
| ntt | 195.43–272.11 → 201.03–245.97 | 14.78–16.63 → 9.33–10.32 |
| rustfft | 193.96–255.06 → 187.99–279.94 | 16.27–17.36 → 10.09–10.37 |
| tfhe_fft | 192.43–244.61 → 216.49–236.83 | 14.81–16.79 → 9.22–10.15 |

The local external-product reduction is roughly 5–7 µs against a roughly 16 ms
request: only about 0.03–0.04% of the request's arithmetic budget. Even eliminating
the entire measured first external product would save only about 0.1% at these
parameters; the real candidate still needs its body and inverse transform.
These estimates do not bound unrelated compiler/layout or system effects, and
must not be reported as measured end-to-end speedups.

Fresh **uninstrumented** binaries then ran general/candidate/candidate/general
in separate processes: 30 samples, 0.5 s warmup, 2 s measurement target, one
complete request per iteration. Binary markers and build logs distinguished
these executables from the stage probes. Means and CI envelopes below are in ms;
the delta uses the average of the two means. An envelope spans the individual
95% confidence intervals; it is not a pooled CI. BK means BR→KS, KB means KS→BR.

| Backend / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| ntt / CBS / BK | 16.354 / 17.172 | 16.792 / 18.085 | +4.0% | [16.254, 18.002] → [16.569, 18.900] |
| ntt / CBS / KB | 17.683 / 16.640 | 16.862 / 17.227 | -0.7% | [16.443, 18.382] → [16.575, 17.696] |
| ntt / PBS / BK | 17.019 / 16.606 | 16.625 / 16.595 | -1.2% | [16.308, 17.474] → [16.308, 16.938] |
| ntt / PBS / KB | 16.420 / 16.519 | 16.644 / 16.735 | +1.3% | [16.248, 16.858] → [16.388, 17.028] |
| rustfft / CBS / BK | 16.270 / 16.209 | 16.234 / 16.263 | +0.1% | [16.037, 16.496] → [16.072, 16.497] |
| rustfft / CBS / KB | 16.187 / 16.227 | 16.211 / 16.294 | +0.3% | [15.985, 16.459] → [16.028, 16.476] |
| rustfft / PBS / BK | 16.089 / 16.151 | 16.480 / 16.337 | +1.8% | [15.928, 16.334] → [16.118, 16.743] |
| rustfft / PBS / KB | 17.682 / 16.105 | 16.131 / 15.966 | -5.0% | [15.950, 17.921] → [15.792, 16.303] |
| tfhe_fft / CBS / BK | 15.971 / 15.921 | 15.728 / 15.834 | -1.0% | [15.751, 16.209] → [15.518, 16.060] |
| tfhe_fft / CBS / KB | 18.805 / 16.022 | 15.899 / 15.940 | -8.6% | [15.858, 21.050] → [15.720, 16.179] |
| tfhe_fft / PBS / BK | 16.277 / 15.614 | 15.991 / 15.982 | +0.3% | [15.442, 16.638] → [15.798, 16.214] |
| tfhe_fft / PBS / KB | 17.475 / 15.619 | 15.868 / 15.771 | -4.4% | [15.427, 17.649] → [15.600, 16.103] |

The apparent larger reductions in some KB averages came with substantial baseline
run-to-run variation; the last general run overlapped or beat the candidate.
Other requests were neutral or regressed. The candidate therefore does not meet
the repeatable complete-request criterion. Frequency/background activity was
uncontrolled and hardware counters remained unavailable; no cache or scheduling
cause is inferred. A smaller bucket count was not used to amplify the effect.

### Correctness, resources and exit

- 48 uninstrumented captures over all 12 request IDs matched the corresponding
  key/public-map/input fingerprint and complete PBS/CBS output, including Fourier
  gadget output. Every fixture also passed its decrypt/CMux oracle.
- Two temporary focused tests covered u32/u64, N=32, k=1/2, full/truncated bases,
  nonzero and zero bodies, and synthesized dummy-only/one/three-selector buckets
  with exponents 0/N−1/N/2N−1. All 864 first-product comparisons were coefficient
  exact against the general product; the measured pairs allocated zero times.
  Each case subsequently reused both workspaces for a full product on the new
  accumulator. The existing raw sparse tests independently checked phase and
  direct negacyclic rotation; CBS tests checked gadget scales and CMux consumption.
- Zero initialization and all later digits/carries were checked by scalar and
  batch decomposition for every valid base-log/retained-level combination under
  the tested u32/u64 NTT primes and native domains, starting with dirty buffers.
- Key arrays stayed 441,974,784 bytes for NTT and 589,299,712 for each Fourier
  engine. Aggregate scratch remained 192 KiB for NTT and 256 KiB for Fourier,
  with the latter's existing 256 KiB transformed control buffer. These are array
  footprints, not memory traffic or the complete workspace. All owners and
  constructors stayed unchanged; no new keygen, construction-peak or RSS
  measurement is claimed.

The candidate passed 36 tests including the two temporary oracles. After restoring
the original source and removing the oracles/capture hooks, all-targets check and
34 existing GLWE backend tests passed (`rustfft,tfhe-fft`, `--lib --tests`). No new
CI case or unused public product method is retained. No u32/SIMD performance or
second-CPU acceptance matrix was added once the u64 complete-request test failed.
First-bucket GLev storage, omitted-row aggregation/transforms and their sampling/
noise effects remain untested follow-ups; they must not inherit a speedup claim
from this valid but too small external-product simplification. NTRU was unchanged.

To reproduce, add a temporary body-row product beside the existing NTT/Fourier
GGSW product, retaining its clearing, carry initialization and inverse transform;
in sparse BR call it only for bucket zero. Build separate uninstrumented
`sparse_pbs` and `circuit_bootstrap` binaries for both GLWE backends with
`--features rustfft,tfhe-fft`, rebuilding restored sources with fresh timestamps.
Select `u64/.*sparse.*complete$`, pin to CPU 4 and use the Criterion settings above.
Keep stage probes/capture setup outside measured complete requests and retain
first-bucket material so the key and noise distribution are unchanged.

## Streaming control aggregation and external product

**2026-10-04; baseline `dbf84a66`. Decision: retain the existing GLWE NTT
pipeline.** A single-level prototype gave a small u64 PBS signal but regressed
u32. A second prototype kept approximately the original aggregation tile size;
it removed the obvious u32 regression without producing a consistent gain
across the complete PBS/CBS workloads. Neither prototype, scratch-access hook
nor a public streaming API is retained. This is a GLWE NTT result, not a rejection
of every possible NTRU/Fourier or word-specific streaming implementation.

### Remaining cost and controlled change

The same diagnostic n728/h32/N1024/k1, r3/B64 fixtures, seeds and toolchain were
used. PBS t8 includes its return; CBS t4 includes its projection/scheme switch.
NTT u64 uses Q=1125899906826241 and base-log 8/L6; u32 uses base-log 2 with
Q=132120577/L13 for PBS and Q=998244353/L15 for CBS. The setup and correctness
checks stay outside timing. No build or numerical test overlapped measurement.

Fresh stage probes on CPU 4 gave these median sums over 28 observations per case,
in ms. They locate the remaining work and are not acceptance timings:

| u64 request / order | Aggregation | Control NTT | External product |
| --- | ---: | ---: | ---: |
| PBS / BK | 14.306 | 1.123 | 0.985 |
| PBS / KB | 14.206 | 1.127 | 0.987 |
| CBS / BK | 13.953 | 1.023 | 0.962 |
| CBS / KB | 14.078 | 1.119 | 0.983 |

The original pipeline completes the whole coefficient GGSW, transforms it in
place and then consumes it. The first prototype instead initializes the input
polynomial's decomposition once, completes one GLWE control level from its
dummy and all rotated selections, transforms that level and immediately adds
its product with the matching digit to the NTT accumulator. It propagates carries
across levels, visits mask rows then body, and inverse-transforms only after all
rows. Pair/single arithmetic, source-key layout and every encrypted entry remain
unchanged; no first-bucket or public-empty-bucket shortcut is mixed in.

This reschedules work without reducing the number of decompositions or
transforms. In u64/k1 a level is 16 KiB, matching the existing aggregation tile;
in u32/k1 it is 8 KiB. The second prototype therefore aggregates consecutive levels
up to approximately 16 KiB before transforming and consuming them in order.
A tile contains complete GLWE levels and stops at a GLev row boundary; odd L
leaves a short final tile. This does not exactly reproduce the original u32 tile
partition, which can span two rows.

Both prototypes reuse a prefix of the original aggregate allocation. Its owner
and capacity remain unchanged, separating scheduling from a later buffer-size
experiment. Temporary access to the existing external-product scratch avoids
allocating another adjusted polynomial, carry buffer, digit or accumulator.
This access is experiment scaffolding, not a proposed stable workspace API.

### Complete requests

All acceptance runs used freshly built uninstrumented binaries, verified free of the stage marker.
The initial runs use 30 samples, 0.5 s warmup and a 2 s measurement target, with
one complete request per iteration. CPU 4 uses general/candidate/candidate/general;
CPU 8 reverses that order. The longer confirmation uses 50 samples, 1 s warmup
and an 8 s target, again in separate fresh processes. CPU/cache groups and the
uncontrolled frequency/background activity are as above; hardware counters
remain unavailable (`perf_event_paranoid=4`). No cache/writeback cause is claimed.

All following values are ms. Each pair lists the two run means in chronological
order within that implementation. Delta compares their averages. A CI envelope
spans the two individual 95% intervals and is not a pooled confidence interval.
BK denotes BR→KS; KB denotes KS→BR.

Single-level prototype, u64, CPU 4 (30 samples):

| Word / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| u64 / CBS / BK | 16.511 / 16.565 | 16.332 / 16.461 | -0.9% | [16.332, 16.822] → [16.162, 16.684] |
| u64 / CBS / KB | 16.604 / 16.690 | 16.483 / 16.323 | -1.5% | [16.402, 16.947] → [16.174, 16.710] |
| u64 / PBS / BK | 16.383 / 16.384 | 16.107 / 16.198 | -1.4% | [16.208, 16.602] → [15.956, 16.432] |
| u64 / PBS / KB | 16.551 / 16.615 | 16.155 / 16.343 | -2.0% | [16.363, 16.854] → [15.964, 16.599] |

Single-level prototype, u64, CPU 8 (30 samples, reversed order):

| Word / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| u64 / CBS / BK | 17.315 / 17.290 | 17.247 / 17.258 | -0.3% | [17.071, 17.600] → [17.045, 17.515] |
| u64 / CBS / KB | 17.329 / 17.401 | 17.226 / 17.322 | -0.5% | [17.120, 17.687] → [17.037, 17.604] |
| u64 / PBS / BK | 17.299 / 17.377 | 17.157 / 17.098 | -1.2% | [17.109, 17.651] → [16.905, 17.387] |
| u64 / PBS / KB | 17.542 / 17.483 | 17.148 / 17.128 | -2.1% | [17.262, 17.848] → [16.930, 17.377] |

Single-level prototype, u64, CPU 4 (50 samples, reversed order):

| Word / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| u64 / CBS / BK | 16.514 / 16.482 | 16.281 / 16.354 | -1.1% | [16.374, 16.624] → [16.178, 16.478] |
| u64 / CBS / KB | 17.116 / 16.512 | 16.437 / 16.835 | -1.1% | [16.416, 17.414] → [16.346, 16.988] |
| u64 / PBS / BK | 16.426 / 16.420 | 16.135 / 16.135 | -1.8% | [16.323, 16.536] → [16.032, 16.247] |
| u64 / PBS / KB | 16.612 / 16.552 | 16.399 / 16.210 | -1.7% | [16.441, 16.717] → [16.105, 16.501] |

The u64 PBS improvement is a small repeatable signal in these fixtures,
roughly 1–2%; CBS varies more and has overlapping intervals. It must not be
reported as a uniform PBS/CBS improvement. The same single-level prototype
regresses u32, CPU 4 (30 samples):

| Word / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| u32 / CBS / BK | 26.978 / 25.539 | 27.044 / 27.443 | +3.8% | [25.250, 27.343] → [26.758, 27.815] |
| u32 / CBS / KB | 25.575 / 25.605 | 26.899 / 26.960 | +5.2% | [25.246, 25.967] → [26.564, 27.407] |
| u32 / PBS / BK | 21.733 / 21.985 | 23.222 / 23.940 | +7.9% | [21.511, 22.278] → [22.991, 24.655] |
| u32 / PBS / KB | 21.866 / 21.814 | 22.772 / 24.961 | +9.3% | [21.555, 22.122] → [22.512, 26.431] |

The approximately 16 KiB, row-bounded prototype, CPU 4 (30 samples):

| Word / request / order | General means | Candidate means | Delta | General CI envelope → candidate CI envelope |
| --- | --- | --- | --- | --- |
| u32 / CBS / BK | 25.374 / 25.202 | 25.488 / 25.588 | +1.0% | [24.947, 25.725] → [25.126, 25.940] |
| u32 / CBS / KB | 26.206 / 25.281 | 25.237 / 25.833 | -0.8% | [25.014, 27.303] → [24.977, 26.132] |
| u32 / PBS / BK | 21.811 / 21.873 | 21.908 / 21.839 | +0.1% | [21.560, 22.219] → [21.613, 22.196] |
| u32 / PBS / KB | 21.881 / 21.907 | 21.896 / 21.649 | -0.6% | [21.603, 22.280] → [21.378, 22.150] |
| u64 / CBS / BK | 16.579 / 18.181 | 16.783 / 16.392 | -4.6% | [16.396, 18.635] → [16.211, 17.002] |
| u64 / CBS / KB | 16.584 / 16.698 | 17.006 / 16.806 | +1.6% | [16.394, 16.930] → [16.592, 17.236] |
| u64 / PBS / BK | 16.511 / 16.798 | 16.420 / 16.296 | -1.8% | [16.314, 17.116] → [16.121, 16.661] |
| u64 / PBS / KB | 16.479 / 16.608 | 16.332 / 16.339 | -1.3% | [16.295, 16.859] → [16.114, 16.579] |

Keeping the larger u32 tile removes the clear single-level regression, but does
not establish a general speedup: u32 PBS is essentially neutral, u64 PBS retains
only a small signal and u64 CBS KB regresses in this comparison. The last general
CBS BK run also drifts substantially; its average reduction is not evidence of
a reliable CBS improvement. A separate u64-only production dispatch was not
implemented or accepted, and these measurements do not predict its code generation.
The evidence does not justify introducing a new streaming interface and replacing
the current pipeline; the narrow u64 signal is recorded for a future focused design.

### Numerical checks, resources and exit

The temporary small-parameter oracle first scatters every selector coefficient
into its independently computed negacyclic destination, then compares the
streamed result with the existing full GGSW external product. It covers u32/u64,
N32/64, k1/2, full and truncated bases, nonconsecutive input indices, empty/odd/even
buckets, exponents 0/N−1/N/2N−1, wrap/rounding boundaries, trivial and nontrivial
inputs, and dirty scratch reused for subsequent products. Each prototype passed
1,152 exact full-product comparisons with zero allocations; every aggregated
level was also checked directly. The tiled variant additionally covers two-level
blocks and an odd final level. Existing raw phase/rotation, PBS, interleaved
outputs, CBS gadget/CMux and factorized tests passed.

All 96 uninstrumented fixture captures across eight request IDs matched the
key/public-map/input fingerprint and complete output exactly. Decrypt/CMux
assertions passed outside timing. Paired runs regenerated identical key material
from the same seeds; neither the noise parameters nor the arithmetic order changed.

Coefficient key arrays, all constructors and workspace owners are unchanged.
The aggregate allocations remain 192 KiB (u64), 208 KiB (u32 PBS) and 240 KiB
(u32 CBS); using only a prefix is not a measured retained-memory reduction.
There is no source-key byte reduction, new keygen timing, construction live-peak
measurement or claim about actual memory traffic. Buffer shrinking is untested.

Both prototypes passed 17 backend tests including the temporary oracle;
restored sources passed the 16 existing tests and all-targets check. No candidate
code or CI workload remains. NTRU, Fourier and nightly SIMD streaming performance
were not evaluated.

To reproduce, use the original `sparse_pbs` and `circuit_bootstrap` fixtures;
build and save a separate binary per implementation with
`cargo bench -p primus_tfhe_glwe_ntt --bench <target> --no-run`.
Implement the described row/level traversal with existing scratch, preserving
selector, decomposition and summation order. Follow the [common method](README.md#measurement-method),
pin to CPU 4/8, select `u64/.*sparse.*complete$` or `u(32|64)/.*sparse.*complete$`,
and use the stated Criterion settings.

## Layout and batch admission review

The 2026-10-05 source review at `344be16b` produced no timing or implementation
change. Its two questions were subsequently tested: [tile-major source keys](#glwe-ntt-tile-major-source-key)
were rejected, while [the internal LUT input pair](#ntru-lut-paired-blind-rotation)
was retained. The earlier admission review is not an outstanding experiment.

### Key layout

GLWE NTT reads approximately 16 KiB aggregate tiles from an entry-major key;
corresponding u64/k1/L6/N1024 tiles start 192 KiB apart. This motivated the
controlled transpose below, preserving the same sampled coefficients, arithmetic
and views. The stride alone did not prove a cache/TLB bottleneck. Whole-control
Fourier/NTRU paths have different traversal requirements; their layout was not
changed by this experiment.

### Batch consumers

| Consumer | Current computation | Relevance to bucket-wise batching of different inputs |
| --- | --- | --- |
| Interleaved ManyLUT and factorized MVB | One input BR supplies several outputs | Output count is not the number of independent BR requests. |
| NTRU one-hot CBS | One input BR supplies several selectors | Selector count is not an input batch size. |
| NTRU LWE return batches | Extraction/conversion and key switching after BR | Existing return batching does not supply a BR batch scheduler. |
| High-precision LUT selector preparation | Different input chunks each require one-hot BR | A real potential internal consumer, subject to pruning and buffer/latency choices. |

The implemented LUT window follows `LookupTableStats::one_hot_chunk_count`,
retains pruning and selector omission, and keeps at most two independent BR
accumulators. Output count is not an input batch size. External request queues,
implicit threads and a general batch API were not introduced or measured.

## GLWE NTT tile-major source key

Measured on 2026-10-05 against `4e2639ce` (7-I, following the 7-E admission
review). **Retain the existing entry-major key.** The candidate is numerically
consistent and shows a small CBS signal, but complete-request gains are not
consistent enough to justify a new storage/API contract. In the longer runs,
CPU 4 means improve by 0.54%–1.87%, while CPU 8 PBS means regress by
0.95%–1.37%. Several intervals overlap and the short comparisons fluctuate.
This is an admission decision for this prototype and these workloads, not proof
that tile-major storage cannot help another profile or machine.

### Layout and controlled work

Only GLWE NTT u64 changes. The existing loop visits a 16 KiB aggregate tile and
then all selector pairs; corresponding source tiles are 192 KiB apart in the
representative GGSW. The prototype transposes each bucket's selectors from
`[entry][flat GGSW coefficient]` to `[tile][entry][tile coefficient]` and leaves
its dummy as one contiguous GGSW at the end. With `m` selectors, tile start `s`
and actual tile length `l`, entry `j` starts at `s*m + j*l`; the final tile is
not padded. Bucket lengths and all logical GGSW row/level/component orders stay
the same. u32 retains entry-major storage and its original aggregation kernel.

Generation samples exactly the same coefficients in the same order, then copies
one bucket's selectors into reusable temporary scratch and transposes them back
into the final allocation. It never retains two complete keys. Online arithmetic
is unchanged: dummy copy, whole-bucket bias and pair accumulation from 7-G,
7-F fallback for small groups or insufficient headroom, selector order, tile size, normalization,
NTT and external-product counts. Source-key coefficient reads are not reduced;
only their physical order changes. There is no online allocation or additional
workspace owner. The temporary API replaces the contiguous bucket `GgswIter`
with bucket indices plus explicit reconstruction into a caller-owned GGSW;
interpreting the new layout through the old iterator would be incorrect.
All these source and API changes were removed after the comparison.

Profiles are the existing GLWE `sparse_pbs` and `circuit_bootstrap` benchmarks,
both PBS orders: n=728, h=32, r=3, B=64, k=1, N=1024,
Q=1125899906826241, BR logB=8/L=6. Each GGSW has 24576 u64 coefficients;
there are 2184 selectors and 64 dummies. PBS uses t=8 and CBS t=4. Existing
client/key/input seeds and other decompositions are unchanged. These remain
arithmetic diagnostics, not assessed security parameters.

### Complete-request timing

The same Ryzen 9 9955HX3D and rustc 1.98.1/native release configuration is used,
without workspace SIMD features. Logical CPU 4 belongs to the 96 MiB L3 group;
CPU 8 to the 32 MiB group. Builds, correctness runs and resource probes are
separate from timing. Each saved baseline/candidate executable runs in a fresh
process and Criterion directory. CPU 4 uses baseline/candidate/candidate/baseline;
CPU 8 reverses that order. One iteration is one complete preallocated PBS or CBS;
keygen, LUT construction, validation and capture stay outside timing. There are
no phase timers in either online executable.

The short screen uses 30 samples, 0.5 s warmup and a 2 s measurement target;
the longer confirmation uses 50 samples, 1 s warmup and an 8 s target for every
request on both CPUs. BK means `BootstrapKeyswitch`; KB means
`KeyswitchBootstrap`. Values are milliseconds; paired entries are the two run
means. Change compares the averages of those means. The 95% CI envelopes span
the two independent intervals and are not a pooled confidence interval.

Short screen:

| CPU / request / order | Entry-major means | Tile-major means | Change | 95% CI envelopes, entry → tile |
| --- | ---: | ---: | ---: | --- |
| 4 / CBS / BK | 14.889 / 14.994 | 14.791 / 15.469 | +1.26% | [14.825, 15.111] → [14.721, 15.845] |
| 4 / CBS / KB | 15.286 / 15.207 | 14.818 / 15.252 | -1.39% | [15.123, 15.393] → [14.751, 15.502] |
| 4 / PBS / BK | 14.927 / 15.643 | 14.747 / 14.696 | -3.69% | [14.836, 15.757] → [14.625, 14.840] |
| 4 / PBS / KB | 15.063 / 16.376 | 14.978 / 14.924 | -4.89% | [14.993, 16.519] → [14.853, 15.081] |
| 8 / CBS / BK | 16.436 / 15.904 | 15.523 / 17.074 | +0.79% | [15.696, 16.886] → [15.409, 17.536] |
| 8 / CBS / KB | 16.074 / 15.842 | 15.552 / 15.650 | -2.24% | [15.677, 16.365] → [15.476, 15.852] |
| 8 / PBS / BK | 15.694 / 15.978 | 15.409 / 16.208 | -0.17% | [15.586, 16.163] → [15.325, 16.396] |
| 8 / PBS / KB | 15.819 / 16.024 | 15.549 / 16.732 | +1.38% | [15.679, 16.310] → [15.469, 16.930] |

Longer confirmation:

| CPU / request / order | Entry-major means | Tile-major means | Change | 95% CI envelopes, entry → tile |
| --- | ---: | ---: | ---: | --- |
| 4 / CBS / BK | 15.166 / 15.058 | 14.891 / 14.898 | -1.44% | [14.981, 15.256] → [14.806, 14.988] |
| 4 / CBS / KB | 15.427 / 15.638 | 15.524 / 14.960 | -1.87% | [15.341, 15.737] → [14.875, 15.786] |
| 4 / PBS / BK | 14.894 / 14.980 | 14.881 / 14.833 | -0.54% | [14.824, 15.072] → [14.744, 14.968] |
| 4 / PBS / KB | 15.013 / 15.105 | 14.964 / 14.983 | -0.57% | [14.932, 15.212] → [14.862, 15.080] |
| 8 / CBS / BK | 15.720 / 15.750 | 15.608 / 15.594 | -0.85% | [15.622, 15.845] → [15.508, 15.700] |
| 8 / CBS / KB | 15.908 / 16.011 | 15.731 / 15.691 | -1.56% | [15.815, 16.109] → [15.605, 15.818] |
| 8 / PBS / BK | 16.140 / 15.719 | 15.884 / 16.412 | +1.37% | [15.641, 16.225] → [15.672, 16.512] |
| 8 / PBS / KB | 16.208 / 15.823 | 15.642 / 16.693 | +0.95% | [15.733, 16.301] → [15.553, 16.810] |

The short CPU 4 PBS gains shrink considerably in the longer comparison, while
CPU 8 PBS reverses or keeps a mixed signal. CBS means generally improve by about
1%–2%, with run variation. Frequency and unrelated system activity were not
controlled. No cache/TLB counters were collected (`perf_event_paranoid=4`), and
these timings do not identify a cache, bandwidth or instruction-level cause.
The small, inconsistent online result is insufficient for this layout change.

### Construction cost and correctness

A separate single-thread resource probe uses the same BR profile, client seed
42 and sparse-key seed 4242. Context, client and a correctly sized generator
exist before measurement; the key remains alive afterward. The allocator records
requested allocation sizes and the maximum simultaneous live-byte increase
above the pre-call state, accounting for releases. This is neither allocation
traffic nor RSS, and excludes allocator overhead and preexisting resources.
It measures the sparse BR key, not the whole server bundle.

| Resource | Entry-major | Tile-major |
| --- | ---: | ---: |
| Final coefficient storage | 441974784 B (421.5 MiB) | same |
| Retained requested-byte increase | 441992920 B | same |
| Construction live peak above the starting state | 442002016 B | 451439200 B |
| Allocation calls in sparse-key construction | 13 | 14 |
| Additional temporary transpose scratch | 0 | 9437184 B (9 MiB) |

The fixed map has at most 48 selectors per bucket. Scratch is allocated once
and released before returning; its exact 9 MiB increase explains the measured
peak difference. Map/metadata ownership and online workspace sizes are unchanged.
Separate construction probes, in baseline/candidate/candidate/baseline order on
each CPU, give the following milliseconds. These few observations are diagnostic
ranges, not precise keygen speedup estimates.

| CPU | Entry-major sparse-key generation | Tile-major sparse-key generation | Isolated conversion range |
| --- | ---: | ---: | ---: |
| 4 | 439.629 / 413.673 | 428.896 / 431.116 | 28.234–28.625 |
| 8 | 401.683 / 405.883 | 424.612 / 422.876 | 31.669–32.656 |

Isolated conversion times one pass over an already allocated key buffer with
one preallocated bucket scratch, including both copies of every selector and
excluding allocation, encryption and dummy copies. The original diagnostic key
is dropped before the timed conversion. Moving sampled values does not depend
on whether the initial buffer is entry- or tile-major; this probe measures the
copy/transposition cost, while full keygen includes its actual placement between
bucket encryptions and allocation costs.

All **68 setup captures across four request IDs** match within each ID:
canonical logical-key fingerprint, full public map, complete input and complete
output (LWE for PBS, NTT GGSW for CBS). A separate untimed generation check
restores and compares every transposed selector coefficient against the sampled
bucket scratch for all four fixtures before scratch reuse. Decryption and
actual CBS CMux consumption pass. The adapted u128 scatter oracle checks exact
aggregation, including zero exponents and odd tails. One temporary small-layout
test checks unique logical coefficients, empty buckets, dummies, complete/short
tiles, crossings of GGSW rows/levels, and dirty reconstruction outputs.

The candidate passes 18 backend tests including existing allocation-free reuse;
the restored backend passes its original 17 tests. No new test, benchmark,
public API or README change remains. The final all-targets check/clippy,
formatting and sparse PBS/CBS benchmark compilation pass. No u32 performance,
SIMD performance, alternate decomposition/tile size or other backend layout is
measured here. Temporary instrumentation, resource probes, binaries and raw
measurement directories are removed; this record and the local plan retain the
experiment's outcome.

For reproduction, build/save executables from `4e2639ce` and the selector-only
transpose described above with
`cargo bench -p primus_tfhe_glwe_ntt --bench sparse_pbs --bench circuit_bootstrap --no-run`.
Run each binary pinned with `taskset -c 4` or `8`, a fresh `CRITERION_HOME`, and
filter `u64/.*sparse.*complete$`. Use
`--bench --sample-size 30 --warm-up-time 0.5 --measurement-time 2 --noplot`
for the short screen and 50/1/8 for confirmation. Keep coefficient/output
captures and allocator probes outside measured iterations and separate from
timing processes. Do not interpret this rejected prototype as an implemented
storage option or a reason to alter the accepted 7-F/7-G arithmetic.

## NTRU LUT paired blind rotation

Measured 2026-10-05 against production `4e2639ce`. **Retain fixed input pairs**
for sparse high-precision NTRU LUT evaluation, for NTT and both Fourier engines,
at u32/u64. NTT was measured first; Fourier was admitted only after a separate
comparison. This is one synchronous evaluator processing its existing chunks,
not an external batch service or a change to ordinary single-input PBS.

The existing `pipeline` fixture uses n800/h32/N1024, r3/B64, q=PowOf2(2^24),
t=8/M=4, c8/d5/o8, and unchanged circuit/return parameters. The public polynomial,
dense seed-42 map and shared-middle-chunk map require 8, 8 and 6 BRs respectively.
All three include projection, selector conversion/aggregation, table selection,
low-chunk rotation and LWE return in each timed `evaluate`. Output count is not
the input window size. The coefficient key, map, input, lookup table, BR count,
selector omissions, mixed NLEV/NGSW projection and return schedule are unchanged.

The only numerical scheduling change is
`bucket -> source-control group -> input`. Each input keeps its own aggregate,
current and exponents; transforms and external products run serially using the
original scratch. Three current/product buffers suffice by swapping their owners.
Fourier also reuses its original transformed aggregate and FFT engine. NTT uses
the accepted lazy u64 pair or canonical u32 pair; Fourier u64 keeps the accepted
four-way kernel and u32 keeps pairs. No new multi-input arithmetic kernel shares
register loads. Logical key reads and operation counts are not halved. The
measurements are consistent with better source-key locality, but no cache/TLB,
DRAM or instruction counters were available to isolate the hardware cause.

The bounded workspace is created only when at least two surviving chunks need
BR. Scoped `OneHotProjection` callbacks consume the first then second result,
reusing the existing nonzero-selector and coefficient-conversion batches. The
callback cannot replace BR state; its input/output and unwind contracts are in
rustdoc. Classic and unpaired tails retain single-input execution. No threads,
queues, second evaluator or all-chunk BR scratch are introduced. See the
[LUT implementation notes](../../crates/primus_tfhe_ntru_lut/IMPLEMENTATION.md#fixed-sparse-input-pairs)
for buffer lifetimes and the unchanged selector formulas.

### Complete evaluation

Same machine/toolchain/features as above, pinned to CPU 4 and CPU 8. Criterion
flat sampling, one complete lookup per iteration, fresh process and
`CRITERION_HOME` for each pass; builds/tests did not overlap timings. Allocation
and key/output capture probes run only in untimed setup. Frequency/background
activity remained uncontrolled. Values below are means, milliseconds,
**serial → paired**, not confidence bounds or a universal speedup guarantee.

Screen: 30 samples, 0.5 s warmup, 2 s target; CPU 4 ran serial then paired,
CPU 8 paired then serial. Both words and all three workloads are included.

| CPU | Backend / word | Polynomial: serial → pair, ms | Dense: serial → pair, ms | Shared: serial → pair, ms | Reduction range |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 | ntt / u32 | 62.768 → 49.505 | 63.504 → 48.481 | 43.717 → 32.280 | 21.1–26.2% |
| 4 | ntt / u64 | 44.049 → 36.550 | 44.263 → 37.972 | 25.787 → 21.319 | 14.2–17.3% |
| 4 | rustfft / u32 | 60.832 → 48.980 | 62.430 → 50.684 | 43.877 → 35.179 | 18.8–19.8% |
| 4 | rustfft / u64 | 43.911 → 36.900 | 45.402 → 38.954 | 29.687 → 24.447 | 14.2–17.7% |
| 4 | tfhe_fft / u32 | 54.948 → 43.201 | 56.073 → 44.720 | 39.325 → 30.884 | 20.2–21.5% |
| 4 | tfhe_fft / u64 | 40.982 → 34.237 | 42.486 → 35.487 | 27.727 → 22.284 | 16.5–19.6% |
| 8 | ntt / u32 | 64.564 → 47.629 | 66.569 → 49.330 | 45.181 → 32.982 | 25.9–27.0% |
| 8 | ntt / u64 | 48.657 → 39.678 | 50.693 → 41.003 | 29.125 → 22.535 | 18.5–22.6% |
| 8 | rustfft / u32 | 63.253 → 49.588 | 66.233 → 51.244 | 45.996 → 35.781 | 21.6–22.6% |
| 8 | rustfft / u64 | 48.082 → 37.771 | 49.998 → 39.462 | 33.315 → 25.384 | 21.1–23.8% |
| 8 | tfhe_fft / u32 | 58.280 → 44.385 | 59.278 → 45.645 | 42.081 → 31.793 | 23.0–24.4% |
| 8 | tfhe_fft / u64 | 45.537 → 35.350 | 47.125 → 36.622 | 31.302 → 23.532 | 22.3–24.8% |

Confirmation: 50 samples, 1 s warmup, 5 s target, u64; reverse the screen's
order on each CPU. All 36 screen and 18 confirmation comparisons have
nonoverlapping bootstrap mean CIs in the favorable direction. These within-run
CIs do not control between-run system variation. The following main matrices
precede the final, separately checked NTT projection-inlining hint.

| CPU | Backend / word | Polynomial: serial → pair, ms | Dense: serial → pair, ms | Shared: serial → pair, ms | Reduction range |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 | ntt / u64 | 43.553 → 36.488 | 46.430 → 38.202 | 26.031 → 20.943 | 16.2–19.5% |
| 4 | rustfft / u64 | 43.615 → 36.968 | 45.411 → 38.854 | 29.621 → 24.441 | 14.4–17.5% |
| 4 | tfhe_fft / u64 | 41.440 → 34.074 | 42.755 → 35.710 | 28.154 → 22.365 | 16.5–20.6% |
| 8 | ntt / u64 | 49.084 → 39.381 | 50.465 → 41.106 | 29.015 → 22.328 | 18.5–23.0% |
| 8 | rustfft / u64 | 49.318 → 37.645 | 50.012 → 39.211 | 32.988 → 25.490 | 21.6–23.7% |
| 8 | tfhe_fft / u64 | 45.448 → 35.156 | 46.907 → 37.577 | 31.120 → 23.323 | 19.9–25.1% |

The earlier NTT-only stage prototype also ran two serial and two candidate
passes per CPU (30/0.5/2). Polynomial/dense/shared mean ranges, serial vs pair:
CPU 4: 42.706–43.471 / 36.618–36.646; 44.275–44.951 / 37.969–38.267;
26.019–26.039 / 21.130–21.470 ms. CPU 8: 49.311–49.441 / 39.229–39.282;
50.436–50.820 / 41.181–41.184; 29.290–29.337 / 22.502–22.792 ms. The staged
prototype interfaces were then replaced by the scoped callback API.

### Single input, odd tail and projection inlining

Temporary polynomial-only variants use c1/d1/o8 (one BR) and c7/d5/o8
(seven BRs: three pairs plus a serial tail). Input 43981 is masked to their
respective two-bit-chunk domains. Same keys/parameters, 30/0.5/2 sampling,
serial/paired on CPU 4 and paired/serial on CPU 8:

| CPU | Backend / word | Single BR: serial → candidate, ms | Seven BRs: serial → pair, ms |
| --- | --- | ---: | ---: |
| 4 | ntt / u32 | 8.491 → 8.388 | 54.351 → 43.502 |
| 4 | ntt / u64 | 7.357 → 7.453 | 39.206 → 33.893 |
| 4 | rustfft / u32 | 8.289 → 8.212 | 53.297 → 44.464 |
| 4 | rustfft / u64 | 6.761 → 6.788 | 38.728 → 33.612 |
| 4 | tfhe_fft / u32 | 7.576 → 7.544 | 48.291 → 39.427 |
| 4 | tfhe_fft / u64 | 6.624 → 6.587 | 36.539 → 31.256 |
| 8 | ntt / u32 | 9.638 → 9.215 | 56.842 → 44.008 |
| 8 | ntt / u64 | 8.666 → 8.747 | 44.229 → 36.724 |
| 8 | rustfft / u32 | 8.668 → 8.743 | 55.458 → 45.066 |
| 8 | rustfft / u64 | 7.432 → 7.408 | 42.798 → 35.026 |
| 8 | tfhe_fft / u32 | 8.036 → 8.026 | 50.864 → 41.467 |
| 8 | tfhe_fft / u64 | 7.111 → 7.850 | 40.521 → 32.654 |

Seven-input evaluation improves on both CPUs. The single-input TFHE FFT/u64
CPU-8 candidate had a noisy 7.850 ms observation (mean CI 7.651–8.060 ms),
versus 7.111 ms baseline. Do not erase that observation or interpret its roughly
10% gap as a reproduced regression: an isolated 50/1/5 repeat used ABBA on
CPU 4 and BAAB on CPU 8. A=serial, B=paired implementation; no input pair is
actually scheduled for this geometry. Repeated means are listed separately:

| CPU | Backend / u64 | Serial passes, ms | Candidate passes, ms |
| --- | --- | ---: | ---: |
| 4 | NTT | 7.462 / 7.587 | 7.598 / 7.496 |
| 4 | TFHE FFT | 6.604 / 6.580 | 6.638 / 6.636 |
| 8 | NTT | 8.830 / 8.792 | 8.888 / 8.909 |
| 8 | TFHE FFT | 7.149 / 7.155 | 7.185 / 7.189 |

The large Fourier observation does not repeat. The small roughly 0.5–0.7%
Fourier difference remains in this data; this work makes no single-input
speedup claim. The NTT repeat suggested a roughly 1% CPU-8 cost after splitting
BR from projection. Retain one local `#[inline]` on NTT's private projection
method to preserve specialization in single-input calls; no arithmetic or extra
interface is added. A 50/1/3 ABBA CPU-8 check then gives serial
8.725/8.740 ms and final 8.757/8.725 ms (about +0.1% by the two-pass averages).
CPU 4 gives final 7.474 vs serial 7.493 ms. No substantial single-window change
is established by these observations.

The same hint was checked against the paired implementation before the hint,
including complete LUT work. The first u64 probe gave, polynomial/dense/shared,
CPU 8 before/final: 39.242/39.180, 40.807/40.827, 22.367/22.061 ms;
CPU 4: 36.542/36.555, 38.131/39.576, 21.271/21.724 ms. The latter two final
observations were noisy (dense mean CI 39.053–40.137 ms). A further 50/1/3
comparison covers both words, before/final on CPU 4 and final/before on CPU 8.
It preserves the large gain over serial; inlining itself is not advertised as
a general paired-evaluation speedup:

| CPU | Word | Polynomial: before → final, ms | Dense: before → final, ms | Shared: before → final, ms |
| --- | --- | ---: | ---: | ---: |
| 4 | u32 | 46.908 → 46.925 | 48.228 → 49.091 | 31.595 → 32.247 |
| 4 | u64 | 36.085 → 36.633 | 37.987 → 37.917 | 21.161 → 21.099 |
| 8 | u32 | 47.611 → 47.434 | 48.466 → 48.735 | 32.622 → 32.594 |
| 8 | u64 | 39.282 → 39.124 | 40.728 → 40.650 | 22.525 → 22.351 |

### Resources and validation

The extra requested heap is exactly `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)`.
The additional state survives evaluator construction; projection batches and
transform/product scratch are shared. Measurements below include the complete
evaluator's requested heap and its constructor's incremental live peak, excluding
preexisting contexts/keys/public tables, outputs, inline object/stack storage,
allocator metadata and RSS. Reallocations update the tracked live size; allocator
implementation transients inside `realloc` are not measured. Both FFT engines
have the same requested-workspace counts in this fixture.

| Backend / word | BR levels | Extra retained / peak bytes | Extra KiB | Source coefficient key, unchanged |
| --- | ---: | ---: | ---: | ---: |
| NTT / u32 | 15 | 71936 | 70.25 | 144.375 MiB |
| NTT / u64 | 6 | 63744 | 62.25 | 115.5 MiB |
| Fourier / u32 | 16 | 76032 | 74.25 | 154 MiB |
| Fourier / u64 | 8 | 80128 | 78.25 | 154 MiB |

Polynomial and dense workloads have identical workspace sizes. The following
values are **serial → pair**, bytes; shared-middle-chunk values are smaller
because pruning and output sharing are still active.

| Backend / word | Polynomial/dense retained | Polynomial/dense peak | Shared retained | Shared peak |
| --- | ---: | ---: | ---: | ---: |
| NTT / u32 | 515332 → 587268 | 515332 → 587268 | 392452 → 464388 | 392452 → 464388 |
| NTT / u64 | 793864 → 857608 | 793864 → 857608 | 597256 → 661000 | 597256 → 661000 |
| Fourier / u32 | 1188160 → 1264192 | 1192256 → 1268288 | 966976 → 1043008 | 971072 → 1047104 |
| Fourier / u64 | 1131904 → 1212032 | 1140096 → 1220224 | 935296 → 1015424 | 943488 → 1023616 |

For c1/d1/o8, retained/peak bytes are identical on both sides: NTT u32
212228/212228; NTT u64 302344/302344; Fourier u32 540992/545088; Fourier u64
542080/550272. No pair state is allocated. Every measured evaluation reports
zero online allocations. Sparse key construction, coefficient count and logical
layout are unchanged; this experiment measures evaluator-construction peak,
not key-generation peak. `estimate_workspace` remains a partial direct-LUT
estimate and explicitly excludes this BR state.

All **238 setup captures across 30 request IDs**, including the initial NTT
prototype and inlining checks, agree within each ID: logical source-key
fingerprint/bytes, full public bucket maps and complete input/output LWE arrays.
Decrypted outputs and phase errors match. Existing small-ring tests now compare
both aggregation inputs against an independent u128 scatter sum, and compare
paired NLEV/NGSW with each input's serial result (including both FFT engines).
They cover group/pair tails, empty buckets, zero exponents, guard endpoints,
callback order, wrong second-input shape, projection failure/recovery and
allocation-free reuse. Existing LUT cases exercise pruning, mixed selector
roles, no-BR/single/odd paths, independent lift and return-tile boundaries.
No new test function or benchmark target is added.

The final three-crate suite passes **39 ordinary and 39 nightly SIMD tests**.
All-targets check, ordinary/SIMD strict clippy, warning-free rustdoc, compiler-only
LUT check, formatting and the restored public pipeline's bench compilation pass.
SIMD latency, other CPUs/architectures, alternate bases/r/B/N and external request
batching are not measured. No new parameter/security recommendation follows.
Temporary probes, snapshots, scripts, binaries and raw timing files are removed;
public benches/examples retain their prior workload and API. The local plan is
updated separately and is not a repository dependency.

### Reproduction

Build/save the baseline at `4e2639ce` and the retained implementation with
`cargo bench -p primus_tfhe_ntru_lut --bench pipeline --features ntt,rustfft,tfhe-fft --no-run`.
Run the saved executables with `taskset -c 4` or `8`, a fresh `CRITERION_HOME`,
and `lookup/.*/u(32|64)/sparse/.*/evaluate$`, then
`--bench --sample-size 30 --warm-up-time 0.5 --measurement-time 2 --noplot`.
For u64 confirmation use 50/1/5 and reverse the order. Timed calls use only the
public evaluator; setup remains outside `b.iter` timing.

To reconstruct the temporary tail probes, change the benchmark's CONFIG to
c1/d1/o8 or c7/d5/o8, mask INPUT to `M^c-1`, skip the c8-only unique-polynomial
count assertion, and select only the polynomial `.../c*_d*_o8/evaluate` IDs.
No such environment switch or configuration option remains in the public bench.
Capture output/keys and measure constructor live allocations only outside the
timed loop; keep hardware/compiler/features and key seeds equal across variants.
