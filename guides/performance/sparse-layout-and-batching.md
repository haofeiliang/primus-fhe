# Sparse layout, scheduling and input batching

[Performance guide](README.md) · [Arithmetic](sparse-arithmetic.md) · [Workspace costs](workspace-measurements.md) · [Current benchmark commands](../development/testing.md#tfhe-benchmarks)

Retain the bounded two-input NTRU sparse BR schedule used by high-precision LUT
and the existing source-key layout and full-control aggregation. The tested
tiles, first-bucket product, streaming pipeline, tile-major key and shared
projection did not justify their additional contracts or costs. These decisions
apply to the measured workloads; they do not establish that such designs can
never help another profile.

## Historical fixtures and evidence

The experiments below ran on 2026-10-04/05, Ryzen 9 9955HX3D, x86_64 Linux,
rustc 1.98.1 / LLVM 22.1.8, release and repository native CPU flags. No Cargo
`simd` feature was enabled; transform libraries could still select SIMD kernels.
Fourier enabled RustFFT and TFHE-FFT. CPU 4 and CPU 8 belong to the same machine's
96 MiB and 32 MiB L3 groups. Compare implementations **within** each CPU; their
absolute times are not interchangeable samples.

The diagnostic PBS/CBS profile uses n728/h32/N1024, GLWE k1, three replicas and
64 buckets, t8 for PBS and t4 for CBS. NTT Q is 132120577 for u32 PBS,
998244353 for u32 CBS, and 1125899906826241 for u64; Fourier uses Native32/64.
Full BR bases have logB2 for u32 and logB8 for u64. GLWE KS uses the same full
basis; NTRU return uses q=2^24 and logB3/L8. Accumulator sigma is 6.4 for GLWE
and 0.7 for NTRU; fixed-weight external sigma is 3.2*q/16384, NTRU return sigma
is 3.2. Other CBS decompositions remain fixed within each comparison. Historical
profiles are in `test-support/tfhe/src/parameters/{glwe,ntru}.rs` at `4e2639ce`;
these functional fixtures are not security recommendations. Client/key and input
seeds were 42 and 43 where independently paired.

Each uninstrumented Criterion iteration measured one complete request into
prepared buffers. Setup, keys, tables, encryption and correctness captures were
outside timing. Builds and diagnostic probes ran separately. Frequency and
background activity were not controlled, and hardware counters were unavailable;
timings do not identify cache misses, writeback stalls or DRAM traffic. Stage
measurements only locate work. Detailed original tables and deleted prototype
reports are preserved in Git at `bbf235ed`; temporary candidate sources, binaries
and raw Criterion distributions are not retained. Reconstructing an experiment
requires its stated revision and workload, not renaming a current benchmark ID.

## Coefficient aggregation tiles

**Baseline `501c90ac`; retain untiled NTRU and GLWE Fourier aggregation.** The
candidate copied the dummy once, traversed complete-polynomial tiles outside the
selector-pair loop, and transformed only the completed aggregate. It preserved
pair arithmetic, odd tails and all encrypted entries. Aggregate allocation and
key storage were unchanged, but tile traversal revisited index/exponent arrays.
GLWE NTT's existing tiling was outside this experiment.

A CPU 4 screen (15 samples, 0.3 s warmup, 1 s target) compared 8/16/32 KiB tiles
with a whole control. u64 NTRU NTT and GLWE Fourier regressed; NTRU RustFFT u64
had no convincing gain. Constant 32 KiB tiles reduced u32 NTRU RustFFT from about
6.13 to 5.73 ms and TFHE-FFT from 5.78 to 5.44 ms. That signal did not survive
the candidate which tiled only u32 and preserved the whole-control u64 path.

The latter used two processes per implementation, ABBA on CPU 4 and BAAB on
CPU 8, 30 samples, 0.5 s warmup and 2 s target. Changes compare the averages of
the two run means; positive is slower:

| u32 backend | CPU 4 | CPU 8 |
| --- | ---: | ---: |
| GLWE RustFFT | +4.8% | -3.4% |
| GLWE TFHE-FFT | +4.0% | +2.8% |
| NTRU RustFFT | +2.7% | +4.2% |
| NTRU TFHE-FFT | +2.8% | +5.1% |

Forcing the NTRU helper inline still gave +1.2%/+1.6% for u32 RustFFT/TFHE-FFT
on CPU 4, with roughly unchanged u64 results. The prototype/candidate gap has
no demonstrated hardware or compiler cause. No buffer reduction accompanied
these changes: aggregates remained 52/48 KiB for NTRU NTT u32/u64, 64 KiB for
NTRU Fourier and 256 KiB for GLWE Fourier. The rejected candidate was not
extended to CBS, one-hot, lookup, GLWE KS→BR or SIMD latency matrices.

## GLWE first-bucket trivial input

**Baseline `575de611`; retain the general product.** Both GLWE PBS orders
initialize the sparse BR accumulator to `(0,...,0,P)`, with the body already
rotated. Zero masks decompose into zero digits under the tested full/truncated
signed bases. A body-row-only first external product is therefore valid, but
it leaves all bucket aggregation, control transforms, body work and inverse
transforms intact. It is not a test of smaller first-bucket key storage or
omitted-row aggregation.

For u64 PBS/CBS, both orders, NTT/RustFFT/TFHE-FFT on CPU 4, the first product
fell from roughly 15–17 µs to 9–10 µs. Saving 5–7 µs against a roughly 16 ms
request is only 0.03–0.04% of its arithmetic budget. Uninstrumented ABBA runs
(30 samples, 0.5 s warmup, 2 s target) showed neutral, slower and faster means;
the larger apparent improvements coincided with drifting baseline runs. No
repeatable complete-request benefit was established.

Keys and workspaces were unchanged; no allocation or layout saving offsets the
extra product entry/dispatch. The specialization was removed. Body-row-only
material generation, other word widths' latency and a second CPU were not
measured and cannot inherit a speedup claim from this stage result.

## Streaming control aggregation and external product

**Baseline `dbf84a66`; retain the GLWE NTT pipeline.** The prototype aggregated,
transformed and consumed one GLWE control level at a time, carrying decomposition
state across levels and inverse-transforming after all rows. It changed the
schedule, not the number of transforms or products. Pair arithmetic, source
layout and dummy/selector contributions were unchanged.

At k1/N1024 a level is 16 KiB for u64 but 8 KiB for u32. The single-level
schedule produced a small, repeatable u64 PBS signal of roughly 1–2%, while u64
CBS results overlapped or varied and u32 complete requests regressed by 3.8–9.3%.
A second candidate grouped complete levels up to about 16 KiB, stopping at row
boundaries. This removed the clear u32 regression but did not establish a
consistent PBS/CBS improvement:

| Row-bounded candidate, CPU 4 | BR→KS | KS→BR |
| --- | ---: | ---: |
| u32 PBS | +0.1% | -0.6% |
| u32 CBS | +1.0% | -0.8% |
| u64 PBS | -1.8% | -1.3% |
| u64 CBS | -4.6% | +1.6% |

The -4.6% mean includes substantial baseline drift. Screening used ABBA on
CPU 4, BAAB on CPU 8, 30 samples/0.5 s/2 s; single-level u64 confirmation used
50 samples/1 s/8 s. The table uses the screen's two-run averages. Both candidates
kept the original aggregate allocation and reused existing product scratch:
192 KiB for u64, 208 KiB for u32 PBS, 240 KiB for u32 CBS. Using its prefix did
not reduce retained memory. The new scratch access/streaming interface was not
justified; shrinking buffers or adding a u64-only dispatch was not measured.
No conclusion transfers to NTRU/Fourier streaming or SIMD latency.

## GLWE NTT tile-major source key

**Baseline `4e2639ce`; retain entry-major storage.** This u64 prototype
transposed each bucket's selectors from `[entry][GGSW coefficient]` to
`[tile][entry][tile coefficient]`, leaving the dummy contiguous. It replaced the
192 KiB source stride between corresponding 16 KiB tiles, without reducing
logical key reads, aggregation work or transforms. Final tiles were unpadded.
The existing contiguous GGSW iterator could no longer describe each selector;
the prototype needed explicit reconstruction and a different storage contract.

Both PBS orders and CBS used the diagnostic u64 fixture. Long confirmation
used 50 samples, 1 s warmup, 8 s target and two runs per implementation, ABBA on
CPU 4 and BAAB on CPU 8. Entries are changes in the average run means:

| Request / order | CPU 4 | CPU 8 |
| --- | ---: | ---: |
| CBS / BR→KS | -1.44% | -0.85% |
| CBS / KS→BR | -1.87% | -1.56% |
| PBS / BR→KS | -0.54% | +1.37% |
| PBS / KS→BR | -0.57% | +0.95% |

Several intervals overlapped; larger short-screen PBS gains did not persist.
The small CBS signal and mixed PBS results did not justify a new layout/API.
The 421.5 MiB coefficient key stayed the same size, but generation needed one
additional 9 MiB temporary bucket buffer: requested live peak rose from
442002016 to 451439200 bytes. Isolated transposition cost 28.2–28.6 ms on CPU 4
and 31.7–32.7 ms on CPU 8; sparse key generation was roughly 0.4 s. These few
setup observations are not precise keygen speedup estimates. No online storage
was added, and u32/Fourier/NTRU layouts were unchanged.

The tile, first-product, streaming and source-layout experiments checked exact
outputs against their respective unchanged algorithms, with independent
small-ring scatter/decomposition checks where applicable. These historical
checks support their numerical comparisons, not current test coverage or a
noise/security certificate. The rejected code and its temporary checks are gone.

## NTRU LUT paired blind rotation

**Baseline `4e2639ce`; retain fixed input pairs.** The schedule is
`bucket -> source-control group -> input`: each input keeps its own aggregate,
current ciphertext and exponents, while transforms/products execute serially
through shared scratch. It does not halve logical key reads or arithmetic, add
threads, or change ordinary single-input PBS. ManyLUT, MVB and one-hot outputs
from one input are not independent BR inputs; high-precision LUT chunks are.

The current fixed tree prepares all c input chunks. Pair state is allocated only
for sparse BR with c>=2; classic and an odd final input run singly. Scoped
projection consumes the first then second result before reuse. See the
[NTT](../../crates/primus_tfhe_ntru_ntt/src/circuit_bootstrap/one_hot/pair.rs) and
[Fourier](../../crates/primus_tfhe_ntru_fourier/src/circuit_bootstrap/one_hot/pair.rs)
contracts. Sharing source traversal does not authorize sharing the two mutable
accumulators or their errors.

The measured LUT used n800/h32/N1024, r3/B64, q24, t8/M4, c8/d5/o8, key seed42
and input seed43. External sigma was about 34.3287, ring sigma 0.7 and return
sigma 3.2. The polynomial map `x*x+3*x+7 mod 2^16`, dense seed42 map and a
shared-middle-chunk map required 8, 8 and 6 BRs under the historical pruned
compiler. All output chunks, projection, selection, rotations and return were
timed. **Pruning/deduplication is no longer used**; these timings do not measure
the current M16/N4096 complete-tree workload.

Each comparison used a fresh process and fixed CPU, flat sampling, one complete
lookup per iteration. Screening used 30 samples/0.5 s/2 s, serial then paired
on CPU 4 and reversed on CPU 8. Confirmation used u64, 50 samples/1 s/5 s,
reversing those orders. Confirmation means in milliseconds:

| CPU / backend | Polynomial: serial → pair | Dense: serial → pair | Shared: serial → pair |
| --- | ---: | ---: | ---: |
| 4 / NTT | 43.553 → 36.488 | 46.430 → 38.202 | 26.031 → 20.943 |
| 4 / RustFFT | 43.615 → 36.968 | 45.411 → 38.854 | 29.621 → 24.441 |
| 4 / TFHE-FFT | 41.440 → 34.074 | 42.755 → 35.710 | 28.154 → 22.365 |
| 8 / NTT | 49.084 → 39.381 | 50.465 → 41.106 | 29.015 → 22.328 |
| 8 / RustFFT | 49.318 → 37.645 | 50.012 → 39.211 | 32.988 → 25.490 |
| 8 / TFHE-FFT | 45.448 → 35.156 | 46.907 → 37.577 | 31.120 → 23.323 |

The u32 screen improved by 18.8–27.0% across these engines/CPUs/workloads.
All 36 screen and 18 confirmation comparisons had nonoverlapping within-run
mean intervals in the favorable direction; they do not control inter-process
variation. Seven-input probes retained gains with a serial tail. A single-input
TFHE-FFT/u64 CPU 8 run initially rose from 7.111 to 7.850 ms; an ABBA/BAAB
50-sample recheck reduced that to roughly 0.5–0.7%, with no pair actually run.
A local NTT projection inline hint reduced the analogous CPU 8 single-input
difference to about +0.1%. No single-input speedup or general inlining benefit
is claimed. Key/map/input and complete ciphertext captures matched serial work.

Additional pair storage is `(L_BR+1)*N*sizeof(T) + n*sizeof(usize)`: one aggregate,
one current ciphertext and exponents. Transform/product scratch and projection
batches remain shared; no second key or FFT engine is needed. On the measured
x86_64 fixture:

| Backend / word | BR levels | Extra retained bytes | KiB |
| --- | ---: | ---: | ---: |
| NTT / u32 | 15 | 71936 | 70.25 |
| NTT / u64 | 6 | 63744 | 62.25 |
| Fourier / u32 | 16 | 76032 | 74.25 |
| Fourier / u64 | 8 | 80128 | 78.25 |

Constructor incremental peak increased by the same amounts, excluding existing
keys/context, public tables, caller outputs and allocator overhead. Single-input
geometry added no pair state. This bounded storage cost was accepted for the
recorded complete-request gains. Other sizes/bases, SIMD latency and external
request batching were not measured; source locality remains an explanation to
test, not a demonstrated counter result.

## Shared projection withdrawn

The 2026-10-05/06 NTRU one-hot prototype against `09e5f1b8` shared the first
reverse-trace stage after each BR. For K coefficient outputs and N=2^ell, this
reduces automorphisms from K*ell to `1+K*(ell-1)`, saving only K-1 calls. It adds
a second shifted term per output and retains two N-coefficient nodes across
scheme switches: 8/16 KiB at N1024 for u32/u64. Keys do not grow, but the new
projection API, node lifetime and correlated-error contract require maintenance.
The current path projects each output independently; its applicable
[normalization and error conditions](../development/bootstrapping-contracts.md#normalized-reverse-trace)
are retained separately from this withdrawn design.

The same host/toolchain, CPU 4/8, N1024/M4/c8/d5/o8 classic/sparse pruned LUTs
were used. NTT and TFHE-FFT final comparisons covered both words, ordinary and
shared tables; RustFFT appeared only in the earlier prototype screen. The
24 final-version sparse comparisons had 19 faster means and a median change
of -0.79%. They include repeated configurations and selective longer rechecks
(20 samples/0.3 s/2 s, then 30/0.6 s/5 s), so this is not a cross-workload speedup
estimate. Classic had no stable gain: CPU 8 NTT/u32/shared rechecks ranged from
-5.58% to +6.42%. Stage projection reductions of 5.36–12.02% did not translate
into a sufficient repeatable complete-request benefit.

The implementation was withdrawn because the small, uncertain gain did not
justify storage and interface/error-contract costs. This does not establish
permanent invalidity or cover the current complete tree, GLWE CBS or deeper
sharing. The old report, two CSVs and oracle remain recoverable at `bbf235ed`;
no independent research toolchain is maintained for the removed prototype.
