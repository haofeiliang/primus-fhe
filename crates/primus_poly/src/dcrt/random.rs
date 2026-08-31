use primus_data::DataMut;
use primus_integer::FheUint;
use rand::distr::Uniform;

use super::DcrtPolynomial;

impl<T: FheUint> DcrtPolynomial<Vec<T>> {
    /// Generates a uniformly random [`DcrtPolynomial`] in modulus-major layout.
    ///
    /// `poly_length` is the number of point values in each modulus component;
    /// the returned storage length is `poly_length * uniform_distrs.len()`.
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
}

impl<S, T> DcrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Fills each modulus component with values from its uniform distribution.
    ///
    /// `poly_length` is the number of point values in each component. In debug
    /// builds, the backing length must equal
    /// `poly_length * uniform_distrs.len()`.
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
}
