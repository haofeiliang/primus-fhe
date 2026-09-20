# primus_distr

English | [简体中文](README.zh_CN.md)

`primus_distr` provides the discrete probability distributions and batch sampling helpers used by [Primus FHE](../../README.md). It covers binary and ternary secrets, centered discrete Gaussian noise, modular and signed output representations, CRT batch layouts, and statistical diagnostics.

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, sampling algorithms, and numerical contracts are unstable and may change incompatibly at any time.

## Main distributions

| Type | Output and role |
| --- | --- |
| `BinaryDistr` | Uniform samples from `{0, 1}` |
| `SparseTernaryDistr<T>` | Samples from `{0, 1, -1}` with probabilities `1/2`, `1/4`, and `1/4`; the caller supplies the representation of `-1` |
| `DiscreteGaussian<T>` | Centered Gaussian samples encoded as canonical unsigned residues modulo a caller-supplied modulus |
| `SignedDiscreteGaussian<T>` | Centered Gaussian samples represented directly by a signed integer type |
| `CDTSampler<T>` / `SignedCDTSampler<T>` | Explicit portable 64-bit cumulative-distribution-table backends |
| `DiscreteZiggurat<T>` / `SignedDiscreteZiggurat<T>` | Explicit discrete Ziggurat backends for larger supports |

The scalar sampler types above implement `rand::distr::Distribution`. Batch helpers require an RNG implementing both `rand::Rng` and `rand::CryptoRng`.

## Secret-key distribution parameters

`SecretKeyDistr` describes binary, ternary, fixed-weight, and Gaussian secret coefficient distributions; it is a parameter enum, not a sampler. Its constructors check probabilities and weights for the complete logical key. Gaussian parameters are checked by the selected Gaussian sampler constructor. Each cryptosystem determines which variants it supports.

Use `SecretKeyDistr::binary(one_probability)` or `SecretKeyDistr::ternary(negative_one_probability, one_probability)` for custom probabilities; construction checks that each is finite and in `[0, 1]` and that ternary probabilities sum to at most one. `SecretKeyDistr::gaussian(standard_deviation)` constructs `Gaussian { standard_deviation }`, with validation deferred to the Gaussian sampler. Parameterless variants are used directly. Whole-key sampler construction also checks probabilities when variants are constructed directly.

Fixed-weight constructors distinguish total weight from a fixed composition:

| Constructor | Distribution |
| --- | --- |
| `fixed_hamming_weight_binary(length, weight)` | Exactly `weight` ones at uniformly selected positions |
| `fixed_hamming_weight_ternary(length, weight)` | Exactly `weight` nonzero positions with independent uniform signs |
| `fixed_composition_ternary(length, negative_weight, positive_weight)` | Exact separate counts of negative and positive ones |

These constructors reject excessive weights and sum overflow immediately. The length is not retained, and raw enum construction remains possible, so sampling boundaries still validate the actual output length.

`SecretKeySampler<T>::new(distribution)` prepares one set of Gaussian tables and binary/ternary probability thresholds for both output representations. `T` is the unsigned type; signed output uses `T::SignedInteger`. Use `sample_signed(length, rng)` / `sample_signed_to(output, rng)` for signed keys, or `sample_encoded(length, modulus_minus_one, rng)` / `sample_encoded_to(output, modulus_minus_one, rng)` for canonical residues. The `_to` methods overwrite caller storage without allocating. Fixed weights apply to the complete output; invalid lengths are rejected before writing or sampling. Whole-key samplers do not implement scalar `Distribution` because fixed weights correlate coefficients.

`maximum_magnitude()` returns an inclusive unsigned sample bound. Gaussian support must fit the signed companion type at construction; binary and ternary sampling conservatively return one. Encoded sampling requires `modulus_minus_one >= maximum_magnitude()`, with `T::MAX` denoting the native modulus. This is a caller contract, checked once by LWE, GLWE, RNS GLWE and NTRU parameter constructors, rather than on every batch. Parameters retain the sampler for reuse.

The underlying `SignedDiscreteGaussian::maximum_magnitude()` also respects custom backend tail cuts. Neither the shared secret-key sampler nor the signed Gaussian sampler stores a ciphertext modulus.

Custom-probability and fixed-weight binary/ternary vector helpers also have `_to` variants. Encoded samplers emit residues directly; they do not first allocate a signed vector. Sampling algorithms may change RNG consumption and seeded output across versions; empty sampling is not generally guaranteed to consume no randomness. Custom ternary sampling rounds each probability down to a multiple of `2^-64`, caps the total nonzero mass at one for floating-point boundary rounding.

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

The `DiscreteGaussian` and `SignedDiscreteGaussian` facades use a default tail cut of 12 standard deviations. Construction rejects non-finite parameters, standard deviations below `MIN_STANDARD_DEVIATION`, supports that cannot be represented by the selected output type, and modular supports that do not fit below the supplied modulus.

The facades select the portable CDT backend when the truncated support fits its 255-magnitude table and otherwise use the Ziggurat backend. Construct an explicit `*CDTSampler` or `*Ziggurat` when the tail cut or backend must be chosen directly.

`DiscreteGaussian::new(sigma, modulus_minus_one)` returns values in `[0, modulus_minus_one]`. A negative logical sample `-x` is encoded as `modulus_minus_one - x + 1`. `SignedDiscreteGaussian::new(sigma)` instead returns positive, zero, and negative values directly.

## Batch sampling

`DiscreteGaussian` and `SignedDiscreteGaussian` provide `sample_vec(length, rng)` and `sample_to(output, rng)`. Both select the backend once per batch. The former initializes a new vector directly from samples; the latter overwrites caller storage without allocating. Both preserve the output and RNG consumption of repeated scalar `Distribution::sample` calls, including no RNG consumption for empty batches. The existing `sample_gaussian_values*` helpers delegate to these methods. Scalar `sample(rng)` remains available through `Distribution`.

The crate provides allocating functions and matching `_to` functions that fill caller-owned slices. Besides uniform binary and sparse or uniform ternary sampling, helpers support explicit probabilities, fixed Hamming weights, uniform integer distributions, and discrete Gaussian batches.

CRT batches use modulus-major layout. For polynomial length `N` and component moduli `q_0, ..., q_(k-1)`, a slice of length `k * N` is arranged as:

```text
[a_0 mod q_0, ..., a_(N-1) mod q_0,
 a_0 mod q_1, ..., a_(N-1) mod q_1,
 ...]
```

`sample_crt_uniform_binary_values*`, `sample_crt_sparse_ternary_values*`, and `sample_crt_gaussian_values*` draw one logical coefficient and encode that same coefficient in every component. `sample_crt_uniform_values*` instead uses one independent `rand::distr::Uniform` distribution per component.

Callers must provide a nonzero polynomial length for nonempty CRT batches and an output whose length exactly matches the polynomial length times the component count. Repeated low-level paths use debug-only shape diagnostics; release callers must establish the layout at the owning parameter or scheme boundary.

The CRT Gaussian helpers accept a signed distribution and raw modulus values. They do not validate that every modulus can encode the distribution's complete truncated support. For a sampler constructed with standard deviation `sigma` and tail cut `tau`, each modulus must exceed `max(1, floor(sigma * tau))`; the facade uses `tau = 12`.

## Statistical diagnostics

The `stats` module provides:

- `gaussian_stats`, which centers canonical modular samples and computes their mean, population standard deviation, and cumulative magnitude counts;
- `theoretical_cumulative_probs`, which evaluates the matching truncated discrete Gaussian cumulative probabilities.

These functions are intended for tests and validation tools rather than sampling hot paths. Their rustdoc records the exact floating-point and modulus limits.

## High-precision feature

The optional `high_precision` feature exposes `PreciseCDTSampler` and `SignedPreciseCDTSampler`, which use 256-bit CDT thresholds and support larger tables than the portable CDT backend. The facade types do not select these backends automatically.

```text
cargo test -p primus_distr --features high_precision
```

## Testing and benchmarks

```text
cargo test -p primus_distr
cargo bench -p primus_distr --bench gen_sampler
cargo bench -p primus_distr --bench sample_gaussian
cargo bench -p primus_distr --bench sample_secret_key
```

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
