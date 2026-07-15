//! Single-modulus coefficient-domain GLWE secret key.

use primus_integer::FheUint;
use primus_poly::{PolynomialIter, PolynomialOwned};
use primus_reduce::RingContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    GlweParameters, GlweSecretKeyError, LweSecretKey, LweSecretKeyType, RingSecretKeyType,
};

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

    /// Creates a GLWE secret key by copying an LWE secret key into its prefix
    /// and padding every remaining coefficient with zero.
    ///
    /// The resulting coefficient layout is
    /// `[s_lwe[0], ..., s_lwe[n - 1], 0, ..., 0]`, with total length
    /// `lwe_dimension.next_multiple_of(poly_length)`. The GLWE dimension is
    /// therefore the smallest one that can contain the LWE key. Ternary
    /// negative-one coefficients retain their existing modular
    /// representation, so the LWE and GLWE ciphertext moduli must agree when
    /// the key is used.
    pub fn from_padded_lwe(
        lwe_secret_key: &LweSecretKey<T>,
        poly_length: usize,
    ) -> Result<Self, GlweSecretKeyError> {
        if poly_length < 2 || !poly_length.is_power_of_two() {
            return Err(GlweSecretKeyError::InvalidPolynomialLength { poly_length });
        }

        let lwe_dimension = lwe_secret_key.dimension();
        if lwe_dimension == 0 {
            return Err(GlweSecretKeyError::ZeroLweDimension);
        }
        let capacity = lwe_dimension.checked_next_multiple_of(poly_length).ok_or(
            GlweSecretKeyError::CapacityOverflow {
                lwe_dimension,
                poly_length,
            },
        )?;
        let dimension = capacity / poly_length;

        let mut key = vec![T::ZERO; capacity];
        key[..lwe_dimension].copy_from_slice(lwe_secret_key.as_ref());
        let distr = match lwe_secret_key.distr() {
            LweSecretKeyType::Binary => RingSecretKeyType::Binary,
            LweSecretKeyType::Ternary => RingSecretKeyType::Ternary,
        };
        Ok(Self::new(key, dimension, poly_length, distr))
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
