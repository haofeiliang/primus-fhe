//! CRT-domain (coefficient, multi-modulus) GLWE secret key.

use primus_integer::FheUint;
use primus_poly::{CrtPolynomialIter, CrtPolynomialIterMut};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CrtGlweParameters, RingSecretKeyType};

/// Represents a CRT-domain secret key for MLWE.
#[derive(Clone)]
pub struct CrtGlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T>,
    pub(crate) distr: RingSecretKeyType,
    pub(crate) rns_poly_len: usize,
}

impl<T: FheUint> Zeroize for CrtGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for CrtGlweSecretKey<T> {}

impl<T: FheUint> CrtGlweSecretKey<T> {
    /// Creates a new [`CrtGlweSecretKey<T>`].
    #[inline]
    pub fn new(key: Vec<T>, distr: RingSecretKeyType, rns_poly_len: usize) -> Self {
        Self {
            key,
            distr,
            rns_poly_len,
        }
    }

    #[inline]
    pub fn zero(dimension: usize, crt_poly_len: usize, distr: RingSecretKeyType) -> Self {
        Self {
            key: vec![T::ZERO; dimension * crt_poly_len],
            distr,
            rns_poly_len: crt_poly_len,
        }
    }

    pub fn key(&self) -> &[T] {
        &self.key
    }

    pub fn key_mut(&mut self) -> &mut Vec<T> {
        &mut self.key
    }

    pub fn iter_crt_poly(&self) -> CrtPolynomialIter<'_, T> {
        CrtPolynomialIter::new(self.key.as_ref(), self.rns_poly_len)
    }

    pub fn iter_crt_poly_mut(&mut self) -> CrtPolynomialIterMut<'_, T> {
        CrtPolynomialIterMut::new(self.key.as_mut_slice(), self.rns_poly_len)
    }

    /// Returns the distr of this [`CrtGlweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    pub fn generate<R, M>(params: &CrtGlweParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();

        let secret_key_type = params.secret_key_type();

        let mut key = vec![T::ZERO; params.secret_key_len()];

        match secret_key_type {
            RingSecretKeyType::Binary => {
                key.chunks_exact_mut(rns_poly_len).for_each(|crt_poly| {
                    primus_distr::sample_crt_binary_values_to(crt_poly, poly_length, rng);
                });
            }
            RingSecretKeyType::Ternary => {
                let moduli_minus_one = params.cipher_moduli_minus_one();
                key.chunks_exact_mut(rns_poly_len).for_each(|crt_poly| {
                    primus_distr::sample_crt_ternary_values_to(
                        crt_poly,
                        poly_length,
                        moduli_minus_one,
                        rng,
                    );
                });
            }
            RingSecretKeyType::Gaussian(_) => {
                let moduli_value = params.cipher_moduli_value();
                let secret_key_distribution = params.secret_key_distribution().unwrap();
                key.chunks_exact_mut(rns_poly_len).for_each(|crt_poly| {
                    primus_distr::sample_crt_gaussian_values_to(
                        crt_poly,
                        poly_length,
                        moduli_value,
                        secret_key_distribution,
                        rng,
                    );
                });
            }
        };

        Self {
            key,
            distr: secret_key_type,
            rns_poly_len,
        }
    }
}
