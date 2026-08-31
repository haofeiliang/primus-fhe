use std::slice::IterMut;

use itertools::Itertools;
use num_traits::ConstZero;
use primus_integer::{FheInt, FheUint, SignedInteger, UnsignedInteger};
use rand::{
    distr::{Bernoulli, Distribution, Uniform},
    seq::SliceRandom,
};

use crate::{DiscreteGaussian, SignedDiscreteGaussian};

/// Sample a binary vector whose values are `T`.
pub fn sample_uniform_binary_values<T, R>(length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_uniform_binary_values_to(&mut v, rng);
    v
}

/// Sample a binary vector whose values are `T`.
pub fn sample_uniform_binary_values_to<T, R>(result: &mut [T], rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let s = [T::ZERO, T::ONE];

    let (chunks, remainder) = result.as_chunks_mut::<32>();
    for chunk in chunks {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b1) as usize];
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in remainder {
        *elem = s[(r & 0b1) as usize];
        r >>= 1;
    }
}

/// Samples binary values with the configured probability of sampling `1`.
///
/// # Panics
///
/// Panics if `one_probability` is not finite or does not belong to `[0, 1]`.
pub fn sample_binary_values_with_probability<T, R>(
    length: usize,
    one_probability: f64,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let distribution = Bernoulli::new(one_probability)
        .expect("binary one probability must be finite and in [0, 1]");
    distribution
        .sample_iter(rng)
        .take(length)
        .map(|is_one| if is_one { T::ONE } else { T::ZERO })
        .collect()
}

/// Samples a binary vector containing exactly `hamming_weight` ones.
///
/// # Panics
///
/// Panics if `hamming_weight` exceeds `length`.
pub fn sample_fixed_hamming_weight_binary_values<T, R>(
    length: usize,
    hamming_weight: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    assert!(
        hamming_weight <= length,
        "binary Hamming weight must not exceed the output length"
    );
    let mut result = vec![T::ZERO; length];
    result[..hamming_weight].fill(T::ONE);
    result.shuffle(rng);
    result
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_sparse_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![T::ZERO; length];
    sample_sparse_ternary_values_to(&mut v, minus_one, rng);
    v
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_sparse_ternary_values_to<T, R>(result: &mut [T], minus_one: T, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let s = [T::ZERO, T::ZERO, T::ONE, minus_one];

    let (chunks, remainder) = result.as_chunks_mut::<16>();
    for chunk in chunks {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
    let mut r = rng.next_u32();
    for elem in remainder {
        *elem = s[(r & 0b11) as usize];
        r >>= 2;
    }
}

/// Samples uniformly from `{-1, 0, 1}`.
pub fn sample_uniform_ternary_values<T, R>(minus_one: T, length: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length];
    sample_uniform_ternary_values_to(&mut result, minus_one, rng);
    result
}

/// Fills `result` uniformly from `{-1, 0, 1}`.
pub fn sample_uniform_ternary_values_to<T, R>(result: &mut [T], minus_one: T, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let values = [minus_one, T::ZERO, T::ONE];
    let mut random = 0;
    let mut remaining_pairs = 0;
    for output in result.iter_mut() {
        loop {
            if remaining_pairs == 0 {
                random = rng.next_u32();
                remaining_pairs = 16;
            }
            let value_index = (random & 0b11) as usize;
            random >>= 2;
            remaining_pairs -= 1;
            if value_index != 3 {
                *output = values[value_index];
                break;
            }
        }
    }
}

/// Samples ternary values with explicit probabilities for `-1` and `1`.
///
/// # Panics
///
/// Panics if either probability is invalid or their sum exceeds one.
pub fn sample_ternary_values_with_probabilities<T, R>(
    minus_one: T,
    length: usize,
    minus_one_probability: f64,
    one_probability: f64,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    assert!(
        minus_one_probability.is_finite()
            && one_probability.is_finite()
            && (0.0..=1.0).contains(&minus_one_probability)
            && (0.0..=1.0).contains(&one_probability)
            && minus_one_probability <= 1.0 - one_probability,
        "ternary probabilities must be finite, non-negative, and sum to at most one"
    );

    let nonzero_probability = one_probability + minus_one_probability;
    let zero_probability = 1.0 - nonzero_probability;
    let zero = Bernoulli::new(zero_probability).expect("validated zero probability");
    let negative = (nonzero_probability > 0.0).then(|| {
        Bernoulli::new(minus_one_probability / nonzero_probability)
            .expect("validated conditional negative-one probability")
    });

    (0..length)
        .map(|_| {
            if zero.sample(&mut *rng) {
                T::ZERO
            } else if negative
                .as_ref()
                .is_some_and(|distribution| distribution.sample(&mut *rng))
            {
                minus_one
            } else {
                T::ONE
            }
        })
        .collect()
}

/// Samples a ternary vector with exact counts of `-1` and `1`.
///
/// # Panics
///
/// Panics if the weights overflow or their sum exceeds `length`.
pub fn sample_fixed_hamming_weight_ternary_values<T, R>(
    minus_one: T,
    length: usize,
    minus_one_weight: usize,
    one_weight: usize,
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let nonzero_weight = minus_one_weight
        .checked_add(one_weight)
        .expect("ternary Hamming weights must fit in usize");
    assert!(
        nonzero_weight <= length,
        "ternary Hamming weights must not exceed the output length"
    );

    let mut result = vec![T::ZERO; length];
    result[..minus_one_weight].fill(minus_one);
    result[minus_one_weight..nonzero_weight].fill(T::ONE);
    result.shuffle(rng);
    result
}

/// Sample a vector of `length` values from a uniform distribution.
pub fn sample_uniform_values<T, R>(length: usize, distr: &Uniform<T>, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_iter(rng).take(length).collect()
}

/// Fill `result` with samples from a uniform distribution (in-place).
pub fn sample_uniform_values_to<T, R>(result: &mut [T], distr: &Uniform<T>, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .iter_mut()
        .zip(distr.sample_iter(rng))
        .for_each(|(a, b)| *a = b);
}

/// Sample a vector of `length` values from a discrete Gaussian distribution.
pub fn sample_gaussian_values<T, R>(
    length: usize,
    distr: &DiscreteGaussian<T>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    distr.sample_iter(rng).take(length).collect()
}

/// Fill `result` with samples from a discrete Gaussian distribution (in-place).
pub fn sample_gaussian_values_to<T, R>(result: &mut [T], distr: &DiscreteGaussian<T>, rng: &mut R)
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .iter_mut()
        .zip(distr.sample_iter(rng))
        .for_each(|(a, b)| *a = b);
}

/// Sample a CRT-layout binary vector.
///
/// Generates `length` binary values and replicates them across `moduli_count`
/// slots, producing a vector of `length * moduli_count` elements in
/// CRT-interleaved order.
pub fn sample_crt_binary_values<T, R>(length: usize, moduli_count: usize, rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_binary_values_to(&mut result, length, rng);

    result
}

/// Fill `result` with CRT-layout binary values (in-place).
///
/// Samples `length` binary values into the first chunk, then copies them
/// into each subsequent chunk of `length` elements.
pub fn sample_crt_binary_values_to<T, R>(result: &mut [T], length: usize, rng: &mut R)
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let (v, w) = result.split_at_mut(length);

    sample_uniform_binary_values_to(v, rng);

    w.chunks_exact_mut(length)
        .for_each(|s| s.copy_from_slice(v));
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_crt_ternary_values<T, R>(length: usize, moduli_minus_one: &[T], rng: &mut R) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let moduli_count = moduli_minus_one.len();
    let mut result = vec![T::ZERO; length * moduli_count];

    sample_crt_ternary_values_to(&mut result, length, moduli_minus_one, rng);

    result
}

/// Sample a ternary vector whose values are `T`.
pub fn sample_crt_ternary_values_to<T, R>(
    result: &mut [T],
    length: usize,
    moduli_minus_one: &[T],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert_eq!(result.len(), moduli_minus_one.len() * length);

    if result.is_empty() {
        return;
    }

    let mut iters: Vec<IterMut<'_, T>> = result
        .chunks_exact_mut(length)
        .map(|s| s.iter_mut())
        .collect();

    'outer: loop {
        let mut r = rng.next_u32();
        for _ in 0..16 {
            match r & 0b11 {
                0 | 1 => {
                    for iter in iters.iter_mut() {
                        if let Some(value) = iter.next() {
                            *value = T::ZERO;
                        } else {
                            break 'outer;
                        }
                    }
                }
                2 => {
                    for iter in iters.iter_mut() {
                        if let Some(value) = iter.next() {
                            *value = T::ONE;
                        } else {
                            break 'outer;
                        }
                    }
                }
                3 => {
                    for (iter, &modulus_minus_one) in iters.iter_mut().zip(moduli_minus_one) {
                        if let Some(value) = iter.next() {
                            *value = modulus_minus_one;
                        } else {
                            break 'outer;
                        }
                    }
                }
                _ => unreachable!(),
            }
            r >>= 2;
        }
    }
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values<T, R>(
    length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) -> Vec<T>
where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    let mut result = vec![T::ZERO; length * uniform_distrs.len()];

    sample_crt_uniform_values_to(&mut result, length, uniform_distrs, rng);

    result
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values_to<T, R>(
    result: &mut [T],
    length: usize,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    result
        .chunks_exact_mut(length)
        .zip_eq(uniform_distrs)
        .for_each(|(s, u)| {
            s.iter_mut()
                .zip(u.sample_iter(&mut *rng))
                .for_each(|(a, b)| {
                    *a = b;
                });
        });
}

/// Sample a uniform vector whose values are `T`.
pub fn sample_crt_uniform_values_iter_mut<T, R>(
    iters: Vec<IterMut<'_, T>>,
    uniform_distrs: &[Uniform<T>],
    rng: &mut R,
) where
    T: FheInt,
    R: rand::Rng + rand::CryptoRng,
{
    iters.into_iter().zip(uniform_distrs).for_each(|(s, u)| {
        s.zip(u.sample_iter(&mut *rng)).for_each(|(a, b)| {
            *a = b;
        });
    });
}

/// Samples a Gaussian vector in modulus-major CRT layout.
///
/// Every modulus must canonically encode the complete truncated support. This
/// precondition is not checked and must be established by the caller's
/// parameter construction.
pub fn sample_crt_gaussian_values<T, R>(
    length: usize,
    moduli: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) -> Vec<T>
where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    let moduli_count = moduli.len();
    let mut result = vec![T::ZERO; length * moduli_count];
    sample_crt_gaussian_values_to(&mut result, length, moduli, gaussian, rng);

    result
}

/// Fills a slice with Gaussian samples in modulus-major CRT layout.
///
/// Every modulus must canonically encode the complete truncated support. This
/// precondition is not checked and must be established by the caller's
/// parameter construction.
///
/// In debug builds, this function checks that `length` is nonzero and that
/// `result.len()` equals `length * moduli.len()`.
pub fn sample_crt_gaussian_values_to<T, R>(
    result: &mut [T],
    length: usize,
    moduli: &[T],
    gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    rng: &mut R,
) where
    T: FheUint,
    R: rand::Rng + rand::CryptoRng,
{
    debug_assert!(length > 0, "CRT polynomial length must be nonzero");
    debug_assert_eq!(
        result.len(),
        length * moduli.len(),
        "CRT Gaussian output length must equal length times the modulus count"
    );
    if result.is_empty() {
        return;
    }

    for coefficient in 0..length {
        let sample = gaussian.sample(rng);
        if sample >= <<T as UnsignedInteger>::SignedInteger as ConstZero>::ZERO {
            let residue: T = sample.cast_to_unsigned();
            for value in result.iter_mut().skip(coefficient).step_by(length) {
                *value = residue;
            }
        } else {
            for (value, &modulus) in result
                .iter_mut()
                .skip(coefficient)
                .step_by(length)
                .zip(moduli)
            {
                *value = <T as UnsignedInteger>::wrapping_add_signed(modulus, sample);
            }
        }
    }
}
