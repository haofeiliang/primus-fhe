# primus_distr

English | [简体中文](README.zh_CN.md)

`primus_distr` provides the discrete probability distributions and batch
sampling helpers used by [Primus FHE](../../README.md). It covers binary and
ternary secrets, centered discrete Gaussian noise, modular and signed output
representations, CRT batch layouts, and statistical diagnostics.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API,
> sampling algorithms, and numerical contracts are unstable and may change
> incompatibly at any time.

## Main distributions

| Type | Output and role |
| --- | --- |
| `BinaryDistr` | Uniform samples from `{0, 1}` |
| `SparseTernaryDistr<T>` | Samples from `{0, 1, -1}` with probabilities `1/2`, `1/4`, and `1/4`; the caller supplies the representation of `-1` |
| `DiscreteGaussian<T>` | Centered Gaussian samples encoded as canonical unsigned residues modulo a caller-supplied modulus |
| `SignedDiscreteGaussian<T>` | Centered Gaussian samples represented directly by a signed integer type |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | Explicit portable 64-bit cumulative-distribution-table backends |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | Explicit discrete Ziggurat backends for larger supports |

All sampler types implement `rand::distr::Distribution`. Batch helpers require
an RNG implementing both `rand::Rng` and `rand::CryptoRng`.

## Example

```rust
use primus_distr::{SignedDiscreteGaussian, sample_crt_gaussian_values};
use rand::{SeedableRng, rngs::StdRng};

let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
let moduli = [97_u64, 193];
let poly_length = 8;
let mut rng = StdRng::seed_from_u64(7);

let samples = sample_crt_gaussian_values(
    poly_length,
    &moduli,
    &gaussian,
    &mut rng,
);

assert_eq!(samples.len(), poly_length * moduli.len());
assert!(samples[..poly_length].iter().all(|&x| x < moduli[0]));
assert!(samples[poly_length..].iter().all(|&x| x < moduli[1]));
```

## Gaussian construction and representations

The `DiscreteGaussian` and `SignedDiscreteGaussian` facades use a default tail
cut of 12 standard deviations. Construction rejects non-finite parameters,
standard deviations below `MIN_STANDARD_DEVIATION`, supports that cannot be
represented by the selected output type, and modular supports that do not fit
below the supplied modulus.

The facades select the portable CDT backend when the truncated support fits its
255-magnitude table and otherwise use the Ziggurat backend. Construct an
explicit `*CDTSampler` or `*Ziggurat` when the tail cut or backend must be
chosen directly.

`DiscreteGaussian::new(sigma, modulus_minus_one)` returns values in
`[0, modulus_minus_one]`. A negative logical sample `-x` is encoded as
`modulus_minus_one - x + 1`. `SignedDiscreteGaussian::new(sigma)` instead
returns positive, zero, and negative values directly.

## Batch sampling

The crate provides allocating functions and matching `_to` functions that fill
caller-owned slices. Besides uniform binary and sparse or uniform ternary
sampling, helpers support explicit probabilities, fixed Hamming weights,
uniform integer distributions, and discrete Gaussian batches.

CRT batches use modulus-major layout. For polynomial length `N` and component
moduli `q_0, ..., q_(k-1)`, a slice of length `k * N` is arranged as:

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`, `sample_crt_sparse_ternary_values*`, and
`sample_crt_gaussian_values*` draw one logical coefficient and encode that same
coefficient in every component. `sample_crt_uniform_values*` instead uses one
independent `rand::distr::Uniform` distribution per component.

Callers must provide a nonzero polynomial length for nonempty CRT batches and
an output whose length exactly matches the polynomial length times the
component count. Repeated low-level paths use debug-only shape diagnostics;
release callers must establish the layout at the owning parameter or scheme
boundary.

The CRT Gaussian helpers accept a signed distribution and raw modulus values.
They do not validate that every modulus can encode the distribution's complete
truncated support. For a sampler constructed with standard deviation `sigma`
and tail cut `tau`, each modulus must exceed
`max(1, floor(sigma * tau))`; the facade uses `tau = 12`.

## Statistical diagnostics

The `stats` module provides:

- `gaussian_stats`, which centers canonical modular samples and computes their
  mean, population standard deviation, and cumulative magnitude counts;
- `theoretical_cumulative_probs`, which evaluates the matching truncated
  discrete Gaussian cumulative probabilities.

These functions are intended for tests and validation tools rather than
sampling hot paths. Their rustdoc records the exact floating-point and modulus
limits.

## High-precision feature

The optional `high_precision` feature exposes `PreciseCDTSampler` and
`SignedPreciseCDTSampler`, which use 256-bit CDT thresholds and support larger
tables than the portable CDT backend. The facade types do not select these
backends automatically.

```text
cargo test -p primus_distr --features high_precision
```

## Testing and benchmarks

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0)
or the [MIT License](../../LICENSE-MIT), at your option.
