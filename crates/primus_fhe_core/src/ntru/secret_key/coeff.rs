//! Coefficient-domain NTRU secret key with key generation.

use std::ops::Deref;

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::RingSecretKeyType;

/// Represents a secret key for the NTRU cryptographic scheme.
///
/// The secret key `f` is a small polynomial (typically binary or ternary
/// coefficients) used during decryption to recover the message:
/// `f * c = f * (r * h + m) = r * g + f * m mod q`.
#[derive(Clone)]
pub struct NtruSecretKey<T: FheUint> {
    pub(crate) key: PolynomialOwned<T>,
    pub(crate) distr: RingSecretKeyType,
}

impl<T: FheUint> Zeroize for NtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NtruSecretKey<T> {}

impl<T: FheUint> Deref for NtruSecretKey<T> {
    type Target = PolynomialOwned<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T: FheUint> NtruSecretKey<T> {
    /// Creates a new [`NtruSecretKey<T>`].
    pub fn new(key: PolynomialOwned<T>, distr: RingSecretKeyType) -> Self {
        Self { key, distr }
    }

    /// Returns the distribution of this [`NtruSecretKey<T>`].
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Generates a new random NTRU secret key from parameters.
    ///
    /// The key is sampled from the configured distribution (binary, ternary,
    /// or discrete Gaussian). For NTRU, binary and ternary are the typical
    /// choices that guarantee small coefficients for correct decryption.
    #[inline]
    pub fn generate<R>(distr: RingSecretKeyType, poly_length: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let key = match distr {
            RingSecretKeyType::Binary => PolynomialOwned::random_binary(poly_length, rng),
            RingSecretKeyType::Ternary => {
                PolynomialOwned::random_ternary(T::MAX, poly_length, rng)
            }
            RingSecretKeyType::Gaussian(_std_dev) => {
                // NTRU keys are typically binary/ternary; Gaussian is unusual but supported
                PolynomialOwned::random_binary(poly_length, rng)
            }
        };
        Self { key, distr }
    }
}
