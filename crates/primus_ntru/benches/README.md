# primus_ntru validation and benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Tests and benchmarks

```sh
cargo test -p primus_ntru --features rustfft,tfhe-fft
cargo clippy -p primus_ntru --all-targets --features rustfft,tfhe-fft -- -D warnings
cargo +nightly test -p primus_ntru --features simd,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench encryption --features rustfft,tfhe-fft
cargo bench -p primus_ntru --bench lwe_return
cargo bench -p primus_ntru --bench primitives --features rustfft,tfhe-fft -- 'ntt/n4096/logb3'
cargo bench -p primus_ntru --bench constant_gadget --features rustfft
cargo bench -p primus_ntru --bench ternary_cmux --features rustfft,tfhe-fft
```

`encryption` measures ordinary encryption and undecoded phase extraction. `primitives` measures key switching, automorphism, trace/reverse trace, three coefficient projections, expansion of an eight-coefficient prefix and scheme switching (output B=2^8, L=3) at `N = 1024/4096/8192`, with `B = 2^3/2^10` and the maximum supported level count. Both use `u64`, sparse ternary secrets and sigma 3.2; NTT uses `q = 1_125_899_906_826_241`, and Fourier covers both FFT backends. `constant_gadget` retains constant NLev and eight-control NGSW generation. Setup, tables, key generation and allocations stay outside timed closures. Add `-- --test` for fixture smoke checks; those checks do not measure performance or establish decryptability.

`lwe_return` isolates Q→q, extraction and LWE key switching for several coefficients of one NTRU polynomial, comparing individual returns with shared conversion and tiled returns. It uses N1024/n728, q=2^24 and logB=3, covering u32/u64 with explicit NTT and native source moduli; k=1, 3 and 17 cover a singleton, a typical ManyLUT batch and tile tails. Inputs are seeded canonical coefficients. Keys and workspace are prepared only for selected IDs, outside timing.

`ternary_cmux` compares one fused rotation against two binary CMUXes, with real encrypted controls, u32/u64 and reusable scratch at `N=1024`, for NTT and both FFT backends. Fourier setup reports phase error against independent coefficient convolution outside timing.

NTT scalar products use the existing CPU dispatch and optional dependency SIMD support. No ISA choice is added to the public NTRU API. Compare timings only within matched workloads; these backends do not share equal-security parameters.
