# Factor benchmark coverage

Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

`shoup_factor` measures canonical precomputed Shoup multiplication for u32 and u64: output multiplication, in-place multiplication, multiply-add and multiply-subtract. It directly covers the `FactorSliceOps` kernels used by lattice scalar/factor ciphertext operations, including each RNS modulus block.

The usual NTT moduli, multiplier 17, input sequence and lengths match the explicit-modulus cases in `primus_modulus/benches/slice_arithmetic.rs`. An additional u64 modulus `2^63 - 1` checks performance near the upper end of Shoup's supported range; factor arithmetic does not require prime moduli. Lengths 1024/4096 measure polynomial-sized buffers; 1025 includes a SIMD tail. Compare the corresponding broadcast scalar and factor operations to assess precomputation benefits. Factor construction is outside timing, so this does not measure its break-even reuse count. Repeated in-place results remain canonical without copying/reset.

```sh
cargo bench -p primus_factor --bench shoup_factor
cargo bench -p primus_factor --bench shoup_factor -- --test
cargo +nightly bench -p primus_factor --bench shoup_factor --features simd
```

Criterion uses 20 samples, a 1-second warm-up and a 5-second measurement. Build both variants before measuring, pin them to the same CPU and alternate baseline/candidate runs. Stable and nightly builds must be compared separately. The three accelerated u64 operations share a native kernel path when AVX-512F/DQ are available; u32 and multiply-subtract provide unchanged controls.

The [Shoup evaluation](../../../docs/shoup-simd-evaluation.md) records code generation, numerical validation, paired measurements and the RNS/trace caller results.

The prior u64-only fixture used a different modulus, factor and case names. Collect a new baseline. Use the same host/toolchain/features as the modulus benchmarks; default builds may also be auto-vectorized. Lazy multiplication and single-value factor operations are outside this canonical-slice baseline.
