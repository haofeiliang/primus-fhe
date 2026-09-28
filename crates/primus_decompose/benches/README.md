# primus_decompose validation and benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Measurement scope

```text
cargo test -p primus_decompose
cargo bench -p primus_decompose --bench decompose
cargo +nightly test -p primus_decompose --features simd
```

The benchmarks separate basis construction from online decomposition. Generic primitive and BigUint batches process 4096 coefficients, including initialization and every retained level. Primitive cases cover scalar and no-copy/adjusted batch paths. BigUint cases cover compact output with fixed strides and the general fallback, plus one matched full-width output case.

The `decompose/pbs/` group retains representative external-product decomposition profiles; current complete TFHE workloads are documented separately in [TFHE benchmarks](../../primus_tfhe/BENCHMARKS.md): GLWE/NTRU × NTT/Fourier, u32/u64, and N=1024/2048. `init` measures initialization, `levels` measures every retained level with initial carries cloned outside timing, and `full` measures both together. Each iteration decomposes one polynomial, not an entire external product or PBS. Fixed inputs are checked against scalar initialization and each scalar digit/carry before timing. The separately timed stages are diagnostics; their sum is not a measurement of `full`.

Criterion uses 20 samples, a 1-second warm-up and a 5-second measurement. SIMD benchmark commands are in the bench source. Workspace builds already use `target-cpu=native` via [`.cargo/config.toml`](../../../.cargo/config.toml).
