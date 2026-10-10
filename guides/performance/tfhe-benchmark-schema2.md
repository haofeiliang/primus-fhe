# TFHE benchmark schema 2: initial process baseline

> Archive note (2026-10-10): the TFHE benchmark suite and report tools were removed. Commands and source paths below refer to historical revisions; the last complete suite is available at `8d7c4b1a`. Measurements remain evidence for their recorded versions, not current validation.

2026-10-07. This is a small validation of the centralized benchmark/report workflow,
not evidence of a production algorithm change. The implementation uses the same
numerical kernels and profiles. New grouping, executable layout and uniform flat
sampling require a fresh baseline; do not divide these values by historical reports.

## Scope and provenance

Six workloads, three independent processes each, serial execution with reversed
case order in round 2. CPU 4 only, AMD Ryzen 9 9955HX3D, physical core 4/socket 0,
SMT siblings 4/20. Governor `powersave`, `amd-pstate-epp`, preference
`balance_performance`, limits 1,480,264–5,460,527 kHz. These are recorded policies,
not a fixed measured clock. No claim is made about CPU 8 or machine-wide throughput.

Stable rustc 1.98.1 (48a229cea), LLVM 22.1.8, x86_64 Linux, repository native CPU
flags. Features: `ntt,fourier,rustfft,tfhe-fft,validation`; no workspace `simd`.
Each process uses 20 samples, 0.5 s warmup and 2 s requested measurement, overriding
the schema-2 defaults of 30/3/5. One iteration is one complete named workload.
Compilation, key generation, table/workspace preparation and verification are
outside online timing. Construction measures public LUT creation **and drop**.

Base revision: `d4ac98d5ddcbec90371c2afc1cf829e93455f8dd`, with the uncommitted
benchmark migration. Source snapshot SHA-256 (before this report and final documentation/
measurement-tool cleanup): `3c98a201b97d3035b296a6ef603e0ad1ab0f5dbfd572916ae4e4c11a633b73e6`.
Lockfile SHA-256: `e5afdee4b9b72ca350682e3953bc05f9701fe6584c2c371c48e99628e6d334a9`.
Frozen numerical executables were used throughout; no build overlapped sampling.

| Executable | SHA-256 |
| --- | --- |
| `pbs` | `1ee6175106b50afe0b8338823ccbb9b2eff3f45a3008a076fccff5f060aea867` |
| `sparse_pbs` | `4f11ae00cae3eb6241b4ae4ee1ecdfa5d042acea41d48a7f2f77231d56ab8bf2` |
| `high_precision_lut` | `dc2ad710273d47dcb2017aff1d671637d6f3f173fe5e812bf33bf3b12955bac4` |

## Whole-request mean latency

Values are milliseconds. Every independent round is retained, including adverse
variation. This table is not a confidence interval across machines or processes.
Per-process mean/median/standard deviation and confidence bounds are in the generated
CSV; Criterion HTML is retained with each raw run.

| Workload | Round 1 | Round 2 | Round 3 |
| --- | ---: | ---: | ---: |
| GLWE NTT fixed-weight classic PBS | 13.380038 | 13.181167 | 13.096106 |
| GLWE NTT fixed-weight sparse PBS | 14.441446 | 14.428877 | 14.729867 |
| GLWE RustFFT binary shortint PBS | 8.175727 | 8.168346 | 8.210810 |
| GLWE TFHE-FFT binary shortint PBS | 6.349149 | 6.466656 | 6.443292 |
| NTT high-precision LUT creation + drop | 0.969485 | 0.973567 | 0.971009 |
| NTT high-precision LUT evaluation | 49.223017 | 48.017762 | 48.848260 |

The fixed-weight NTT pair uses n728/h32/N1024, Q=1125899906826241,
BR/KS base log 8 with six retained levels and two dropped bits, sigma 6.4,
`KeyswitchBootstrap`, padded t8. Sparse uses three copies and 64 buckets.
Its paired mean changes are +7.93%, +9.47%, +12.48% (positive means slower).
This is the existing arithmetic fixture, not the paper's candidate profile.

The Fourier pair uses binary n866/N2048, Native64, padded t32 and
`KeyswitchBootstrap`; BR is (23,1), ring KS is (3,5), with the existing normalized
noise profile. TFHE-FFT mean changes relative to RustFFT are −22.34%, −20.83%,
−21.53% in these processes. Both entries are in one binary. Actual private FFT
algorithm selections are unavailable through the table API; the report flags
`fft_algorithm_unobserved`, recording planner policy and permutation fingerprints.
An equal fingerprint does not prove equal algorithm selection. These observations
do not justify changing the suite's primary engine or generalize to CBS/LUT.

The high-precision fixture uses the public polynomial `x*x+3*x+7 mod 2^16`, eight
two-bit inputs/outputs, five coefficient-selection chunks, n800/h32/N1024 and classic
BR. External q=2^24, ring Q=1125899906826241; BR log 8/full, ring sigma 0.7;
return KS (3,8) with sigma 3.2. Per-output distinct-polynomial counts are
1,1,1,1,1,4,16,64. This fixture's repeated subtable structure is not a general
arbitrary-function performance guarantee; dense/shared alternatives remain registered.

## Reproduction and verification

Current commands, exact ID discovery and paired-report options live in the
benchmark README (`../../benchmarks/tfhe/README.md`, historical source).
Select the six rows above and use `--rounds 3 --samples 20 --warmup 0.5 --measurement 2`.
Local raw evidence is under `target/benchmark-results/20261007T062206Z-77cca503/`;
artifact metadata and source patch/archive are in `round2-final-artifacts/`, and
CSV/Markdown summaries in `round2-summary/` and `round2-engine-summary/` beside it.
These ignored local artifacts are not part of the repository.

All 18 processes completed with correctness probes and matching numerical metadata.
HTML generation and CSV/Markdown joining by full Criterion ID succeeded. The four
small reporting tests cover units, ratio direction, missing/failed/duplicate pairs,
CPU separation and FFT layout mismatch. The full 150-case dual-engine inventory
has no truncated or duplicate IDs. Separately, 22 representative smoke cases passed
across all seven operation targets; large-profile LUT construction checks and the
four backends' small-parameter Boolean tests passed. No full performance matrix or
security/failure-probability estimation was performed.
