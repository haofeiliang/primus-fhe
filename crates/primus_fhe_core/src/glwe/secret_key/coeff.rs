//! Single-modulus coefficient-domain GLWE secret key.

use primus_integer::FheUint;
use primus_poly::{PolynomialIter, PolynomialOwned};
use primus_reduce::RingContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{GlweParameters, RingSecretKeyType};

/// Represents a secret key for the Module Learning with Errors (MLWE) cryptographic scheme.
#[derive(Clone)]
pub struct GlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T>,
    pub(crate) poly_length: usize,
    pub(crate) dimension: usize,
    pub(crate) distr: RingSecretKeyType,
}

impl<T: FheUint> Zeroize for GlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for GlweSecretKey<T> {}

impl<T: FheUint> GlweSecretKey<T> {
    /// Creates a new [`GlweSecretKey<T>`].
    #[inline]
    pub fn new(
        key: Vec<T>,
        dimension: usize,
        poly_length: usize,
        distr: RingSecretKeyType,
    ) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        assert!(dimension > 0);
        assert_eq!(key.len(), poly_length * dimension);
        Self {
            key,
            dimension,
            poly_length,
            distr,
        }
    }

    /// Returns the poly length of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the dimension of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the distr of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Returns all coefficient-domain secret-key values.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.key
    }

    /// Iterates over the coefficient-domain secret polynomials.
    #[inline]
    pub fn iter(&self) -> PolynomialIter<'_, T> {
        PolynomialIter::new(&self.key, self.poly_length)
    }

    #[inline]
    pub fn generate<R, M>(params: &GlweParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let dimension = params.dimension();
        let poly_length = params.poly_length();

        let key_len = poly_length * dimension;
        let mut key = PolynomialOwned::zero(key_len);
        let distr = params.secret_key_type();
        match distr {
            RingSecretKeyType::Binary => key.random_binary_assign(rng),
            RingSecretKeyType::Ternary => {
                key.random_ternary_assign(params.cipher_modulus_minus_one(), rng)
            }
            RingSecretKeyType::Gaussian(_) => {
                key.random_gaussian_assign(params.secret_key_distribution().unwrap(), rng)
            }
        };

        Self::new(key.into_owned(), dimension, poly_length, distr)
    }
}
