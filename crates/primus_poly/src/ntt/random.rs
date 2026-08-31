use primus_data::{DataMut, DataOwned};
use primus_integer::FheUint;
use primus_reduce::Modulus;
use rand::distr::{Distribution, Uniform};

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates an [`NttPolynomial`] whose point values are uniform modulo `modulus`.
    #[must_use]
    #[inline]
    pub fn random<M, R>(poly_length: usize, modulus: M, rng: &mut R) -> Self
    where
        M: Modulus<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let uniform_distr = modulus.uniform_distribution();
        Self::random_uniform(poly_length, &uniform_distr, rng)
    }

    /// Generates an [`NttPolynomial`] using a reusable uniform distribution.
    ///
    /// Repeated callers can cache the value returned by
    /// [`Modulus::uniform_distribution`] and pass it here.
    ///
    /// # Correctness
    ///
    /// `uniform_distr` must match the modulus of the NTT representation.
    #[must_use]
    #[inline]
    pub fn random_uniform<R>(poly_length: usize, uniform_distr: &Uniform<T>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(uniform_distr.sample_iter(rng).take(poly_length).collect())
    }
}

impl<S, T> NttPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Fills this polynomial with point values uniform modulo `modulus`.
    #[inline]
    pub fn random_assign<M, R>(&mut self, modulus: M, rng: &mut R)
    where
        M: Modulus<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let uniform_distr = modulus.uniform_distribution();
        self.random_uniform_assign(&uniform_distr, rng);
    }

    /// Fills this polynomial using a reusable uniform distribution.
    ///
    /// Repeated callers can cache the value returned by
    /// [`Modulus::uniform_distribution`] and pass it here.
    ///
    /// # Correctness
    ///
    /// `uniform_distr` must match the modulus of the NTT representation.
    #[inline]
    pub fn random_uniform_assign<R>(&mut self, uniform_distr: &Uniform<T>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.iter_mut()
            .zip(uniform_distr.sample_iter(rng))
            .for_each(|(a, b)| *a = b);
    }
}
