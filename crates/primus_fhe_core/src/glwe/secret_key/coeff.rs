//! Single-modulus coefficient-domain GLWE secret key.

use num_traits::ConstZero;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Distribution;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CrtGlweParameters, GlweParameters, GlweSecretKeyError, LweSecretKey, LweSecretKeyType,
    RingSecretKeyType,
};

use super::SecretCoefficient;

/// Common secret-key shape exposed by single-modulus and RNS GLWE parameters.
pub trait GlweSecretKeyParameterSet<T: FheUint> {
    /// Returns the GLWE dimension.
    fn secret_key_dimension(&self) -> usize;

    /// Returns the polynomial length.
    fn secret_key_poly_length(&self) -> usize;

    /// Returns the coefficient distribution.
    fn secret_key_distribution_type(&self) -> RingSecretKeyType;
}

impl<T, M> GlweSecretKeyParameterSet<T> for GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn secret_key_dimension(&self) -> usize {
        self.dimension()
    }

    fn secret_key_poly_length(&self) -> usize {
        self.poly_length()
    }

    fn secret_key_distribution_type(&self) -> RingSecretKeyType {
        self.secret_key_type()
    }
}

impl<T, M> GlweSecretKeyParameterSet<T> for CrtGlweParameters<T, M>
where
    T: FheUint,
    M: primus_reduce::FieldContext<T>,
{
    fn secret_key_dimension(&self) -> usize {
        self.dimension()
    }

    fn secret_key_poly_length(&self) -> usize {
        self.poly_length()
    }

    fn secret_key_distribution_type(&self) -> RingSecretKeyType {
        self.secret_key_type()
    }
}

/// Represents a secret key for the Module Learning with Errors (MLWE) cryptographic scheme.
#[derive(Clone)]
pub struct GlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<SecretCoefficient<T>>,
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
        key: Vec<SecretCoefficient<T>>,
        dimension: usize,
        poly_length: usize,
        distr: RingSecretKeyType,
    ) -> Self {
        assert!(poly_length >= 2 && poly_length.is_power_of_two());
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
    /// therefore the smallest one that can contain the LWE key. A ternary LWE
    /// coefficient represented by `cipher_modulus_minus_one` is normalized to
    /// the signed coefficient `-1`.
    pub fn from_padded_lwe(
        lwe_secret_key: &LweSecretKey<T>,
        poly_length: usize,
        cipher_modulus_minus_one: T,
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

        let mut key = vec![SecretCoefficient::<T>::ZERO; capacity];
        let distr = match lwe_secret_key.distr() {
            LweSecretKeyType::Binary => {
                key[..lwe_dimension]
                    .iter_mut()
                    .zip(lwe_secret_key.as_ref())
                    .for_each(|(output, &coefficient)| {
                        *output = coefficient.cast_to_signed();
                    });
                RingSecretKeyType::Binary
            }
            LweSecretKeyType::Ternary => {
                key[..lwe_dimension]
                    .iter_mut()
                    .zip(lwe_secret_key.as_ref())
                    .for_each(|(output, &coefficient)| {
                        *output = if coefficient == cipher_modulus_minus_one {
                            -T::ONE.cast_to_signed()
                        } else {
                            coefficient.cast_to_signed()
                        };
                    });
                RingSecretKeyType::Ternary
            }
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
    pub fn as_slice(&self) -> &[SecretCoefficient<T>] {
        &self.key
    }

    /// Iterates over the coefficient-domain secret polynomials.
    #[inline]
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = &[SecretCoefficient<T>]> + DoubleEndedIterator {
        self.key.chunks_exact(self.poly_length)
    }

    #[inline]
    pub fn generate<R, P>(params: &P, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        P: GlweSecretKeyParameterSet<T>,
    {
        Self::generate_with_distribution(
            params.secret_key_dimension(),
            params.secret_key_poly_length(),
            params.secret_key_distribution_type(),
            rng,
        )
    }

    /// Generates a canonical signed GLWE secret key from its shape and
    /// coefficient distribution.
    pub fn generate_with_distribution<R>(
        dimension: usize,
        poly_length: usize,
        distr: RingSecretKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        assert!(poly_length >= 2 && poly_length.is_power_of_two());
        assert!(dimension > 0);
        let key_len = poly_length * dimension;
        let key = match distr {
            RingSecretKeyType::Binary => primus_distr::sample_binary_values(key_len, rng),
            RingSecretKeyType::Ternary => {
                primus_distr::sample_ternary_values(-T::ONE.cast_to_signed(), key_len, rng)
            }
            RingSecretKeyType::Gaussian(standard_deviation) => {
                primus_distr::SignedDiscreteGaussian::new(standard_deviation)
                    .expect("validated GLWE secret Gaussian distribution")
                    .sample_iter(rng)
                    .take(key_len)
                    .collect()
            }
        };

        Self::new(key, dimension, poly_length, distr)
    }
}
