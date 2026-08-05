//! Single-modulus coefficient-domain GLWE secret key.

use primus_integer::FheUint;
use primus_lattice::GlweSize;
use primus_reduce::RingContext;
use rand::distr::Distribution;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CrtGlweParameters, GlweParameters, RingSecretKeyType};

use super::SecretCoefficient;

/// Common secret-key shape exposed by single-modulus and RNS GLWE parameters.
pub trait GlweSecretKeyParameterSet<T: FheUint> {
    /// Returns the GLWE secret-key layout.
    fn secret_key_size(&self) -> GlweSize;

    /// Returns the coefficient distribution.
    fn secret_key_distribution_type(&self) -> RingSecretKeyType;
}

impl<T, M> GlweSecretKeyParameterSet<T> for GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn secret_key_size(&self) -> GlweSize {
        self.size()
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
    fn secret_key_size(&self) -> GlweSize {
        self.size().glwe_size()
    }

    fn secret_key_distribution_type(&self) -> RingSecretKeyType {
        self.secret_key_type()
    }
}

/// Represents a secret key for the Module Learning with Errors (MLWE) cryptographic scheme.
#[derive(Clone)]
pub struct GlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<SecretCoefficient<T>>,
    pub(crate) glwe_size: GlweSize,
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
        glwe_size: GlweSize,
        distr: RingSecretKeyType,
    ) -> Self {
        assert_eq!(key.len(), glwe_size.mask_len());
        Self {
            key,
            glwe_size,
            distr,
        }
    }

    /// Returns the GLWE layout of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the poly length of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.glwe_size.poly_length()
    }

    /// Returns the dimension of this [`GlweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.glwe_size.dimension()
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
        self.key.chunks_exact(self.glwe_size.poly_length())
    }

    #[inline]
    pub fn generate<R, P>(params: &P, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        P: GlweSecretKeyParameterSet<T>,
    {
        Self::generate_with_distribution(
            params.secret_key_size(),
            params.secret_key_distribution_type(),
            rng,
        )
    }

    /// Generates a canonical signed GLWE secret key from its shape and
    /// coefficient distribution.
    pub fn generate_with_distribution<R>(
        glwe_size: GlweSize,
        distr: RingSecretKeyType,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let key_len = glwe_size.mask_len();
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

        Self {
            key,
            glwe_size,
            distr,
        }
    }
}
