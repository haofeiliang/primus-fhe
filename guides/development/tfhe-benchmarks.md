# TFHE benchmark baseline and storage check

The [workload guide](../../crates/primus_tfhe/BENCHMARKS.md) owns target purposes
and timing boundaries; the [parameter matrix](tfhe-parameters.md) owns the
numerical profiles. This report records the current measurements, not production
security recommendations or a performance comparison between equal-security systems.

## Scope and enumeration cost

The cleanup starts from `e76ed14`. It changes benchmark harnesses, parameters
and documentation, not production algorithms or APIs. It retains binary,
ternary, fixed-weight classic/sparse, both GLWE orders, both words and both FFT
engines. Duplicate wrappers/ManyLUT measurements and the legacy two-CMux reference
are removed; the real ternary algorithm remains. CBS owns NTRU one-hot timing.
The lookup pipeline now uses public APIs instead of production-source includes.

| Target | Previous IDs | Current IDs |
| --- | ---: | ---: |
| `primus_tfhe/lookup_table` | 12 | 18 |
| `primus_tfhe_glwe_fourier/circuit_bootstrap` | 8 | 16 |
| `primus_tfhe_glwe_fourier/mvb` | 40 | 80 |
| `primus_tfhe_glwe_fourier/pbs` | 96 | 40 |
| `primus_tfhe_glwe_fourier/sparse_pbs` | 20 | 24 |
| `primus_tfhe_glwe_fourier/ternary_pbs` | 10 | merged into pbs |
| `primus_tfhe_glwe_ntt/circuit_bootstrap` | 4 | 8 |
| `primus_tfhe_glwe_ntt/mvb` | 27 | 40 |
| `primus_tfhe_glwe_ntt/pbs` | 48 | 20 |
| `primus_tfhe_glwe_ntt/sparse_pbs` | 10 | 12 |
| `primus_tfhe_glwe_ntt/ternary_pbs` | 5 | merged into pbs |
| `primus_tfhe_ntru_fourier/circuit_bootstrap` | 4 | 12 |
| `primus_tfhe_ntru_fourier/mvb` | 10 | 28 |
| `primus_tfhe_ntru_fourier/pbs` | 64 | 20 |
| `primus_tfhe_ntru_fourier/sparse_pbs` | 24 | 16 |
| `primus_tfhe_ntru_lut/pipeline` | 30 | 10 |
| `primus_tfhe_ntru_ntt/circuit_bootstrap` | 2 | 6 |
| `primus_tfhe_ntru_ntt/mvb` | 5 | 14 |
| `primus_tfhe_ntru_ntt/pbs` | 32 | 10 |
| `primus_tfhe_ntru_ntt/sparse_pbs` | 12 | 8 |

There are 20 → 18 targets and 463 → 382 IDs. The previous executables spent
36.83 s collectively running `--list`, including unconditional key generation,
encryption and correctness checks. The current executables took about 0.02 s
on the same machine: Criterion lists names without invoking the callbacks that
create cached fixtures. This is a setup/enumeration improvement, not a claim
about cryptographic execution speed.

Full `--test` smoke passed all 382 IDs with default features (114.83 s) and
nightly SIMD (115.52 s), including key generation. These are unpinned wall times
for functional checks, not a feature-speed comparison; compilation is excluded.
Only selected IDs initialize fixtures. Dense large-parameter benchmarks remain
opt-in and do not add work to the ordinary small-parameter test suite.

The old pipeline used n64/c7/d5/o3, only u64, base8 return keys and sigma0.7 in
all roles. Current n800/c8/d5/o8 changes both table volume and online work; old
latencies are historical, not a before/after ratio. NTRU PBS likewise replaces
q=Q/base9 with independent q24 and backend-specific bases/noise.

## Measurement conditions

Measured on 2026-09-28, AMD Ryzen 9 9955HX3D, x86_64 Linux, logical CPU 0,
repository `target-cpu=native`. Main-workload baseline: stable rustc 1.98.0
(88d9e12ae), LLVM 22.1.8, default features, release bench profile. Storage
comparison: the same nightly rustc 1.100.0-nightly (bff8e12ff), LLVM 23.1.0,
for both default and SIMD configurations. FFT dependencies may use SIMD even
without the workspace feature.

Each measurement uses 15 samples, 300 ms warmup and a 1.2 s target measurement
time, sequentially without concurrent compilation/benchmarks. Criterion can
extend measurement time for slow key generation. Tables below are mean point
estimates; do not interpret small differences as stable improvements. The main
baseline covers 78 IDs across the retained workflow categories. GLWE rows use
BootstrapKeyswitch; the other order remains smoke-covered.

Reproduce a selected ID with the source target named in the workload guide:

```sh
taskset -c 0 cargo bench -p primus_tfhe_ntru_lut --bench pipeline -- \
  '^lookup/ntt/u32/n800_N1024/c8_d5_o8/complete$' \
  --sample-size 15 --warm-up-time 0.3 --measurement-time 1.2 --noplot \
  --save-baseline cleanup12
```

Criterion saves estimates and confidence intervals under `target/criterion`.
Record exact parameters and features when making a later comparison; do not
reuse historical baseline names across different geometries.

## Main-workload means

Times are milliseconds per iteration. PBS is binary n866/N2048/t32; sparse PBS
is n728/h32/N1024/t8; CBS is classic n800/N1024/t4; MVB produces all 17 threshold
outputs from D64. Different bases/moduli prevent an equal-security backend ranking.

| Family / backend / word | PBS | Sparse PBS | CBS | MVB, 17 outputs |
| --- | ---: | ---: | ---: | ---: |
| glwe/ntt/u32 | 16.937 | 22.051 | 23.824 | 18.644 |
| glwe/ntt/u64 | 7.191 | 17.372 | 14.836 | 13.446 |
| glwe/rustfft/u32 | 19.883 | 22.483 | 34.591 | 29.596 |
| glwe/rustfft/u64 | 8.422 | 16.117 | 19.215 | 17.256 |
| glwe/tfhe_fft/u32 | 15.571 | 21.501 | 28.949 | 24.533 |
| glwe/tfhe_fft/u64 | 6.461 | 15.855 | 16.154 | 14.113 |
| ntru/ntt/u32 | 17.340 | 5.462 | 6.879 | 11.386 |
| ntru/ntt/u64 | 16.611 | 5.525 | 4.676 | 15.892 |
| ntru/rustfft/u32 | 34.376 | 7.359 | 11.841 | 16.653 |
| ntru/rustfft/u64 | 21.068 | 7.456 | 5.712 | 16.229 |
| ntru/tfhe_fft/u32 | 26.444 | 6.958 | 10.287 | 15.072 |
| ntru/tfhe_fft/u64 | 17.010 | 6.909 | 4.540 | 15.272 |

NTRU one-hot and complete lookup means (ms):

| Backend / word | Full M4 one-hot | Nonzero M−1 one-hot | c8/d5/o8 lookup | LUT compile/drop |
| --- | ---: | ---: | ---: | ---: |
| ntt/u32 | 8.009 | 7.627 | 75.785 | 0.647 |
| ntt/u64 | 5.205 | 4.997 | 52.598 | 0.644 |
| rustfft/u32 | 14.017 | 13.161 | 117.929 | 0.418 |
| rustfft/u64 | 6.462 | 6.237 | 63.701 | 0.410 |
| tfhe_fft/u32 | 11.310 | 10.918 | 97.786 | same native compilation as RustFFT |
| tfhe_fft/u64 | 4.951 | 4.841 | 51.362 | same native compilation as RustFFT |

Sparse server-key generation at u64, n728/h32/N1024 (ms; returned-key drop
excluded), and public native LUT compilation/drop (µs):

| Operation | NTT | RustFFT | TFHE-FFT |
| --- | ---: | ---: | ---: |
| glwe sparse keygen | 387.196 | 548.492 | 537.756 |
| ntru sparse keygen | 214.438 | 256.575 | 251.439 |

Native u32, t255/k4/N1024 public LUT compile/drop: 0.848 µs.

Native u64, t255/k4/N1024 public LUT compile/drop: 0.916 µs.

## Retained heap and online allocation

Bytes requested by the complete lookup fixture, measured separately from timing.
Context/transform tables, input ciphertexts, allocator metadata, stack and peak
transient keygen memory are excluded. Client/server keys are a combined row;
workspace and caller outputs are separate. All six configurations observed zero
online allocations. The public LUT contains 8×64×1024 coefficients.

| Backend / word | Client+server keys | Public LUT | Workspace | Outputs |
| --- | ---: | ---: | ---: | ---: |
| ntt/u32 | 76273288 | 2097152 | 553992 | 25824 |
| ntt/u64 | 92550336 | 4194304 | 877584 | 51456 |
| rustfft/u32 | 132855432 | 2097152 | 1102856 | 25824 |
| rustfft/u64 | 105895472 | 4194304 | 1033232 | 51456 |
| tfhe_fft/u32 | 132855432 | 2097152 | 1102856 | 25824 |
| tfhe_fft/u64 | 105895472 | 4194304 | 1033232 | 51456 |

## Aligned-key recheck

A temporary lattice harness repeated one NTRU coefficient external product with
identical transformed key data borrowed as either Vec-backed or cache-aligned
ABox-backed slices. Setup/conversion/drop were outside timing, and the two
outputs were checked equal before measurement. N1024 uses Q30/base2/L15 for u32
NTT and Q50/base8/L6 for u64; native Fourier uses base2/L16 and base8/L8. These
are the new circuit/lookup internal decompositions, not the previous base9
fixture. Coefficients were deterministic arithmetic data, not encrypted keys.

Means in microseconds, ordinary Vec → aligned ABox:

| Backend / word | Default | SIMD |
| --- | ---: | ---: |
| ntt/u32 | 7.945 → 7.915 | 7.981 → 7.960 |
| ntt/u64 | 5.184 → 5.162 | 5.261 → 5.222 |
| rustfft/u32 | 10.581 → 10.557 | 10.676 → 10.647 |
| rustfft/u64 | 6.249 → 6.233 | 6.237 → 6.223 |
| tfhe_fft/u32 | 7.735 → 7.679 | 7.648 → 7.559 |
| tfhe_fft/u64 | 4.604 → 4.568 | 4.655 → 4.633 |

The small differences do not justify migrating every key container. The ordinary
allocator produced base offsets of 0, 16 or 32 modulo 64 in these runs; aligned-vec
guarantees CACHELINE_ALIGN=128 on this target. This is a container comparison,
not a controlled offset sweep. Vec was measured before ABox, so order/system
drift is not isolated; sub-percent differences are not a stable speedup claim.

Reproduce from the existing lattice `ntru_ntt` / `ntru_fourier` external-product
fixtures by using the bases above and preparing
`AVec::<_, ConstAlign<CACHELINE_ALIGN>>::from_iter(CACHELINE_ALIGN, key.as_ref().iter().copied()).into_boxed_slice()`
outside timing, then borrow each through the same NTT/Fourier NGSW slice view.
Use the same nightly compiler and fixed CPU for default and SIMD runs. The
temporary harness is removed rather than making containers a permanent matrix.

N1024 polynomial strides preserve base alignment. LWE rows have n+1 coefficients
and generally do not; aligning an outer vector does not align separately owned
inner allocations. Capacity and alignment are separate: fixed buffers are
constructed at their final lengths, while resizable workspaces retain Vec/AVec
capacity. No padding, representation change or extra online conversion is
introduced by the current storage policy.

## Fixed-workspace container recheck

A second temporary variant changed only the NTRU external-product workspace's
fixed Box/ABox fields back to Vec/AVec, retaining lengths, initial capacity,
alignment, shared-workspace reuse, key data and all numerical parameters. This
is the same isolated container question as the historical RustFFT investigation.
The comparison uses complete c8/d5/o8 lookup on nightly SIMD for both variants,
with the same CPU and sampling settings; Box was measured first.

| Backend / word | Current Box/ABox (ms) | Temporary Vec/AVec (ms) |
| --- | ---: | ---: |
| ntt/u32 | 69.046 | 68.575 |
| ntt/u64 | 51.882 | 52.699 |
| rustfft/u32 | 115.140 | 116.080 |
| rustfft/u64 | 62.972 | 63.192 |
| tfhe_fft/u32 | 96.293 | 96.059 |
| tfhe_fft/u64 | 50.875 | 50.798 |

Both variants decoded every sampled output correctly and allocated nothing
online. Retained requested workspace heap was identical: buffers already have
exact capacity, and the changed container metadata is inline rather than a new
coefficient allocation. Vec/AVec was about 0.7% faster to 1.6% slower across these
cases, without a consistent advantage. Keep fixed-length ownership and serial
workspace reuse; claim neither a boxed-storage speedup nor an alignment benefit.
The temporary source variant was restored byte-for-byte before final validation.

The larger current public table and deeper output work explain why its retained
memory and latency differ from the historical n64/c7/d5/o3 run. That workload
change is independent of alignment, capacity or container metadata.
