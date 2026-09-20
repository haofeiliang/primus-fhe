# Modulus benchmark coverage

Part of the experimental [Primus FHE](../../../README.md) workspace; APIs and numerical contracts may change incompatibly.

- `scalar_moduli`: single-value arithmetic across modulus implementations.
- `barrett_scalar`: canonical/lazy Barrett multiplication and reduction.
- `slice_moduli`: existing Compact/Uint add/sub and Native/PowOf2 add, elementwise multiplication, and dot products.
- `barrett_slice`: canonical/lazy elementwise multiplication, dot products, and batch inversion.
- `signed_encoding`: bounded signed-to-residue conversion for Native/PowOf2/Barrett, u32/u64, at lengths 1024 and 16384. One iteration fills one slice of mixed signed coefficients in [-38, 38]; allocation and input generation are excluded.
- `signed_dot_product`: Native/Barrett u32/u64 dot products with identical ternary secrets in signed and pre-encoded form, at lengths 16, 1024, 1025, and 4096. Each iteration computes one dot product; allocation and secret encoding are excluded. This isolates arithmetic from the sampling and matrix allocation measured by `primus_lwe`'s `public_key` generation benchmark.
- `slice_arithmetic`: Native/Barrett u32/u64 subtraction, negation, broadcast scalar multiplication, scalar multiply-add, and in-place add/sub. Barrett output-add is included; Native output-add remains in `slice_moduli`.

`slice_arithmetic` targets the kernels called by lattice ciphertext arithmetic. Its explicit moduli match `primus_factor/benches/shoup_factor.rs`: 132120577 for u32 and 1125899906826241 for u64, with multiplier 17 and matching deterministic input data. Compare broadcast scalar multiplication against the corresponding precomputed-factor operation, not against elementwise slice multiplication. Lattice scalar multiply-subtract uses scalar negation followed by the same multiply-add kernel, so it does not need a second identical kernel benchmark.

Lengths 1024 and 4096 cover polynomial-sized buffers; 1025 also exercises SIMD tails and packed ciphertext lengths. Native u64 inputs cover the full word range except u64::MAX. Repeated canonical in-place operations require no reset. One iteration processes one slice; allocation, input generation and factor precomputation are excluded. Throughput counts elements, not bytes. These are warm repeated-buffer measurements, not full ciphertext/RNS traversal timings.

```sh
cargo bench -p primus_modulus --bench slice_arithmetic
cargo bench -p primus_modulus --bench slice_arithmetic -- --test
cargo +nightly bench -p primus_modulus --bench slice_arithmetic --features simd
```

Keep machine, features and toolchain fixed for comparisons. SIMD dispatch and ordinary compiler vectorization are distinct; the default build is not a promise of scalar-only machine code. No new PowOf2/Compact/Uint matrix or single-value negation benchmark is added for the current Native/Barrett lattice workloads; their existing comparisons remain available.
