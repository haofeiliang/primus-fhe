//! Canonical coefficient-domain NTRU secret key.

use primus_integer::FheUint;
use rand::distr::Distribution;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NtruParameters, SecretCoefficient, SecretKeyDistr};

/// A small signed polynomial `f` shared by all NTRU transform backends.
///
/// Signed coefficients are intentionally stored independently of a ciphertext
/// modulus: `-1` is encoded as `q - 1` for NTT and as the native two's-complement
/// bit pattern for Fourier only when the key is converted to that backend.
#[derive(Clone)]
pub struct NtruSecretKey<T: FheUint> {
    pub(crate) key: Vec<SecretCoefficient<T>>,
    pub(crate) distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for NtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NtruSecretKey<T> {}

impl<T: FheUint> NtruSecretKey<T> {
    /// Creates a coefficient-domain NTRU key from canonical signed values.
    #[inline]
    pub fn new(key: Vec<SecretCoefficient<T>>, distr: SecretKeyDistr) -> Self {
        assert!(!key.is_empty(), "NTRU secret key must not be empty");
        Self { key, distr }
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.key.len()
    }

    /// Returns the distribution used to sample this key.
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the canonical signed coefficients of `f`.
    #[inline]
    pub fn as_slice(&self) -> &[SecretCoefficient<T>] {
        &self.key
    }

    /// Samples a coefficient key from `params`.
    ///
    /// This method does not impose backend-specific invertibility. Use
    /// [`crate::NttNtruSecretKey::generate`] or
    /// [`crate::FourierNtruSecretKey::generate`] when an immediately usable
    /// encryption key is required.
    pub fn generate<R, M>(params: &NtruParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: primus_reduce::RingContext<T>,
    {
        let poly_length = params.poly_length();
        let key = match params.secret_key_distr() {
            SecretKeyDistr::Binary => primus_distr::sample_binary_values(poly_length, rng),
            SecretKeyDistr::Ternary => {
                primus_distr::sample_ternary_values(-T::ONE.cast_to_signed(), poly_length, rng)
            }
            SecretKeyDistr::Gaussian(_) => params
                .secret_key_distribution()
                .expect("Gaussian NTRU key distribution must be precomputed")
                .sample_iter(rng)
                .take(poly_length)
                .collect(),
        };
        Self {
            key,
            distr: params.secret_key_distr(),
        }
    }
}
