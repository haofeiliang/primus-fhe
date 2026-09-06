# Lattice benchmarks for TFHE and RNS GLWE

Run each target independently to locate regressions without measuring every
backend. These benchmarks isolate lattice operations; full blind rotation,
key switching, and PBS must also be measured in their owning TFHE/scheme crates.

| Target | Path and operations |
| --- | --- |
| `glwe_fourier` | GGSW external product and monomial CMUX, RustFFT and TFHE FFT |
| `glwe_ntt` | GGSW coefficient-output/NTT-output external product and monomial CMUX |
| `ntru_fourier` | NGSW external product and monomial CMUX, RustFFT and TFHE FFT |
| `ntru_ntt` | NGSW external product and monomial CMUX |
| `rns_glev` (`rns`) | CRT/BigUint GLev products and CRT accumulation |
| `rns_ggsw` (`rns`) | CRT GLWE × DCRT GGSW external product |
| `extraction` | GLWE/NTRU compact sample extraction and inverse GLWE extraction |

NGSW and NLev use the same scalar gadget kernel. The NGSW product case measures
that kernel without duplicating the NLev wrapper. NTT-output GGSW measures the
path used by scheme switching when the caller keeps transformed output.
Monomial CMUX is the blind-rotation operation; binary and multi-control CMUX
are not additional baseline cases.

## Parameters and interpretation

`support/mod.rs` defines the shared `(log N, L)` cases: `(10, 3)` as a baseline,
`(11, 3)` for polynomial-length scaling, and `(10, 2)` for decomposition-length
scaling. All use `log B = 8`. GLWE adds `(10, 3, k = 2)` to its baseline `k = 1`.
This varies one layout parameter at a time, rather than a Cartesian product.
The NTT modulus supports at most three decomposition levels at this radix.
These are arithmetic workloads, not recommended cryptographic parameters.

Fourier uses native-torus `u64`; NTT uses `u32`, `q = 132120577`. Both FFT
backends receive the same deterministic coefficient data transformed into their
own evaluation orders. Comparisons between them are meaningful for this fixed
workload. Comparisons across GLWE/NTRU or Fourier/NTT explain implementation
costs, not equal-security PBS performance. Choosing a TFHE architecture requires
scheme-level measurements with matched security and correctness targets.

Extraction uses the corresponding native `u64` and explicit-modulus `u32`
arithmetic. It measures partial and full active dimensions through the compact
API, zero/nonzero GLWE indices, and non-aligned inverse-extraction padding.
Inputs remain full-sized; a compact key is assumed to have a zero suffix.
The output is coefficient-domain, so FFT and NTT tables are unnecessary.

## Timing contract

One Criterion iteration is one complete public operation. Data generation,
tables, gadget transforms, and allocations occur outside timing. Required
accumulator clearing and output conversion remain inside the operation.
Throughput counts logical output elements, including the LWE body for sample
extraction. It is not an operation count or an equal-byte comparison.

Product fixtures are dense arithmetic data, not sampled bit encryptions. They
meet numerical range and representation requirements; the benchmark measures
algebraic evaluation rather than selection correctness or noise. Fixed input,
key, and scratch reuse produces a warm-working-set baseline. Full blind rotation
must separately measure sequential access to distinct bootstrapping-key gadgets;
these microbenchmarks cannot predict key bandwidth or cold-cache PBS latency.

Use primitive-crate benchmarks to isolate decomposition, FFT/NTT and multiply-add
costs; use these targets to measure their composition and layout; verify any
optimization in the corresponding top-level TFHE path. RNS gadget products have separate targets below; complete RNS key switching
remains in `primus_glwe_rns`.

## RNS workloads

The two RNS targets isolate operations used by `primus_glwe_rns`, without
introducing a dependency from lattice back to the scheme crate:

- `rns_glev/crt_add_assign` isolates the inner product called by ordinary DCRT
  key switching and CRT/DCRT automorphism. Repeated accumulation stays canonical;
  no extra output reset is included in timing.
- `rns_glev/crt_to` and `big_uint_to` use the same polynomial in two input
  representations and check matching results before timing. The latter receives
  a precomposed BigUint input; the timing difference helps assess opportunities
  to reuse that representation. It does not include producing or storing it.
- `rns_ggsw/crt_to_dcrt` measures the full matrix product, including per-component
  CRT recomposition and gadget accumulation. The output remains in DCRT form.

`support/rns.rs` uses the ordered primes from the existing RNS key-switching
benchmark. Baseline: `N=1024, k=1, m=2, log B=20`, retaining all decomposition
levels. Additional cases separately change `N` to 2048, `k` to 2, `m` to 4, or
`log B` to 10. Increasing `m` also changes the BigUint width and required level
count; IDs report the actual `L`. The four-modulus case treats Q and P primes
as one base, not as a hybrid key-switching algorithm.

Deterministic independent residues exercise full-width CRT recomposition, and
gadget data is transformed before timing. These are arithmetic fixtures, not
sampled encrypted keys. Throughput counts output residues, `(k+1)*m*N`.
Run the existing `primus_glwe_rns` `key_switching` and `automorphism` targets to
check whether lattice improvements benefit the complete operation. These new
cases do not isolate hybrid mod-down, basis extension, or key streaming.

## Commands

Run from the workspace root:

```sh
cargo bench -p primus_lattice --bench glwe_fourier
cargo bench -p primus_lattice --bench glwe_ntt
cargo bench -p primus_lattice --bench ntru_fourier
cargo bench -p primus_lattice --bench ntru_ntt
cargo bench -p primus_lattice --bench extraction
cargo bench -p primus_lattice --features rns --bench rns_glev
cargo bench -p primus_lattice --features rns --bench rns_ggsw
# Select one parameter group or operation using Criterion's regex filter.
cargo bench -p primus_lattice --bench glwe_ntt -- 'n1024/k1/logb8/l3'
# Exercise every fixture once without collecting timing statistics.
cargo bench -p primus_lattice --bench glwe_fourier --bench glwe_ntt --bench ntru_fourier --bench ntru_ntt --bench extraction -- --test
# Dependency SIMD configuration; replace the target to select another path.
cargo +nightly bench -p primus_lattice --bench ntru_ntt --features simd
```

Use the same host, toolchain, features and build settings for regression
comparisons. NTT dispatch is CPU-dependent. Case names and data differ from the
former `cmux`, `external_product`, and `gadget_product` targets; collect new
baselines. Short smoke measurements validate execution, not performance claims.
