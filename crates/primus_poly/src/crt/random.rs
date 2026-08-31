use num_traits::Signed;
use primus_data::DataMut;
use primus_distr::SignedDiscreteGaussian;
use primus_integer::{FheUint, SignedInteger, UnsignedInteger};
use primus_reduce::{ExplicitModulus, ReduceAddAssign};
use rand::distr::{Distribution, Uniform};

use super::CrtPolynomial;

impl<T: FheUint> CrtPolynomial<Vec<T>> {
    /// Generates a CRT polynomial with shared uniform binary coefficients.
    #[must_use]
    #[inline]
    pub fn random_uniform_binary<R>(poly_length: usize, moduli_count: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_uniform_binary_values(
            poly_length,
            moduli_count,
            rng,
        ))
    }

    /// Generates a sparse ternary CRT polynomial.
    ///
    /// Each logical coefficient is shared by every modulus component and has
    /// probabilities `P(0) = 1/2` and `P(1) = P(-1) = 1/4`.
    /// `moduli_minus_one[i]` encodes `-1` in component `i`.
    #[must_use]
    #[inline]
    pub fn random_sparse_ternary<R>(poly_length: usize, moduli_minus_one: &[T], rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_sparse_ternary_values(
            poly_length,
            moduli_minus_one,
            rng,
        ))
    }

    /// Generate a random uniform [`CrtPolynomial<Vec<T>, T>`].
    #[must_use]
    #[inline]
    pub fn random_uniform<R>(poly_length: usize, uniform_distrs: &[Uniform<T>], rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_uniform_values(
            poly_length,
            uniform_distrs,
            rng,
        ))
    }

    /// Generate a random gaussian [`CrtPolynomial<Vec<T>, T>`].
    #[must_use]
    #[inline]
    pub fn random_gaussian<R>(
        poly_length: usize,
        moduli_value: &[T],
        gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_gaussian_values(
            poly_length,
            moduli_value,
            gaussian,
            rng,
        ))
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Fills this polynomial with shared uniform binary coefficients.
    #[inline]
    pub fn random_uniform_binary_assign<R>(&mut self, poly_length: usize, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_uniform_binary_values_to(self.as_mut_slice(), poly_length, rng)
    }

    /// Fills this polynomial with shared sparse ternary values.
    ///
    /// Each logical coefficient has probabilities `P(0) = 1/2` and
    /// `P(1) = P(-1) = 1/4`. `moduli_minus_one[i]` encodes `-1` in component
    /// `i`.
    #[inline]
    pub fn random_sparse_ternary_assign<R>(
        &mut self,
        poly_length: usize,
        moduli_minus_one: &[T],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_sparse_ternary_values_to(
            self.as_mut_slice(),
            poly_length,
            moduli_minus_one,
            rng,
        )
    }

    /// Fill with random uniform values.
    #[inline]
    pub fn random_uniform_assign<R>(
        &mut self,
        poly_length: usize,
        uniform_distrs: &[Uniform<T>],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_uniform_values_to(
            self.as_mut_slice(),
            poly_length,
            uniform_distrs,
            rng,
        )
    }

    /// Fill with random discrete gaussian values.
    #[inline]
    pub fn random_gaussian_assign<R>(
        &mut self,
        poly_length: usize,
        moduli_value: &[T],
        gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_gaussian_values_to(
            self.as_mut_slice(),
            poly_length,
            moduli_value,
            gaussian,
            rng,
        )
    }

    /// Adds the same discrete Gaussian sample to every CRT residue of each coefficient.
    ///
    /// Each modulus must canonically encode the complete truncated support of
    /// `gaussian`. In debug builds, this method checks that the backing storage
    /// contains exactly one polynomial per modulus.
    #[inline]
    pub fn add_random_gaussian_assign<R, M>(
        &mut self,
        poly_length: usize,
        gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
        moduli: &[M],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: Copy + ExplicitModulus<ValueT = T> + ReduceAddAssign<T>,
    {
        debug_assert!(poly_length > 0, "CRT polynomial length must be nonzero");
        debug_assert_eq!(
            self.crt_poly_length(),
            poly_length * moduli.len(),
            "CRT polynomial storage length must equal polynomial length times the modulus count"
        );

        let values = self.as_mut_slice();
        for coefficient in 0..poly_length {
            let sample = gaussian.sample(rng);
            if !sample.is_negative() {
                let residue = sample.cast_to_unsigned();
                for (value, &modulus) in values
                    .iter_mut()
                    .skip(coefficient)
                    .step_by(poly_length)
                    .zip(moduli)
                {
                    debug_assert!(residue < modulus.value());
                    modulus.reduce_add_assign(value, residue);
                }
            } else {
                for (value, &modulus) in values
                    .iter_mut()
                    .skip(coefficient)
                    .step_by(poly_length)
                    .zip(moduli)
                {
                    debug_assert!(sample.unsigned_abs() < modulus.value());
                    let residue = modulus.value().wrapping_add_signed(sample);
                    modulus.reduce_add_assign(value, residue);
                }
            }
        }
    }
}
