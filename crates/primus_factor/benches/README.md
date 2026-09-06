# Factor benchmark coverage

`shoup_factor` measures canonical precomputed Shoup multiplication for u32 and
u64: output multiplication, in-place multiplication, multiply-add and
multiply-subtract. It directly covers the `FactorSliceOps` kernels used by
lattice scalar/factor ciphertext operations, including each RNS modulus block.

Moduli, multiplier 17, input sequence and lengths match the explicit-modulus
cases in `primus_modulus/benches/slice_arithmetic.rs`. Lengths 1024/4096 measure
polynomial-sized buffers; 1025 includes a SIMD tail. Compare the corresponding
broadcast scalar and factor operations to assess precomputation benefits.
Factor construction is outside timing, so this does not measure its break-even
reuse count. Repeated in-place results remain canonical without copying/reset.

```sh
cargo bench -p primus_factor --bench shoup_factor
cargo bench -p primus_factor --bench shoup_factor -- --test
cargo +nightly bench -p primus_factor --bench shoup_factor --features simd
```

The prior u64-only fixture used a different modulus, factor and case names.
Collect a new baseline. Use the same host/toolchain/features as the modulus
benchmarks; default builds may also be auto-vectorized. Lazy multiplication
and single-value factor operations are outside this canonical-slice baseline.
