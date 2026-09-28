# primus_ntru validation and benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Tests and benchmarks

```sh
cargo test -p primus_ntru
cargo clippy -p primus_ntru --all-targets -- -D warnings
cargo +nightly test -p primus_ntru --features simd
cargo bench -p primus_ntru --bench encryption
cargo bench -p primus_ntru --bench primitives -- 'ntt/n4096/logb3'
cargo bench -p primus_ntru --bench constant_gadget
cargo bench -p primus_ntru --bench ternary_cmux
```

`encryption` measures ordinary encryption and undecoded phase extraction. `primitives` measures key switching, automorphism, trace/reverse trace, three coefficient projections, expansion of an eight-coefficient prefix and scheme switching (output B=2^8, L=3) at `N = 1024/4096/8192`, with `B = 2^3/2^10` and the maximum supported level count. Both use `u64`, sparse ternary secrets and sigma 3.2; NTT uses `q = 1_125_899_906_826_241`, and Fourier covers both FFT backends. `constant_gadget` retains constant NLev and eight-control NGSW generation. Setup, tables, key generation and allocations stay outside timed closures. Add `-- --test` for fixture smoke checks; those checks do not measure performance or establish decryptability.

`ternary_cmux` compares one fused rotation against two binary CMUXes, with real encrypted controls, u32/u64 and reusable scratch at `N=1024`, for NTT and both FFT backends. Fourier setup reports phase error against independent coefficient convolution outside timing.

NTT scalar products use the existing CPU dispatch and optional dependency SIMD support. No ISA choice is added to the public NTRU API. Compare timings only within matched workloads; these backends do not share equal-security parameters.
