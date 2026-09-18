//! Single-modulus NTT-domain GLWE secret key with encryption and decryption.

use primus_integer::FheUint;
use primus_lattice::GlweSize;
use primus_modulus::UintModulus;
use primus_ntt::NttTable;
use primus_poly::NttPolynomialIter;
use primus_reduce::{EncodeSigned, FieldContext};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{GlweParameters, SecretKeyDistr};

use super::GlweSecretKey;

mod batch;
mod coefficient;
mod context;
mod decrypt;
mod encrypt;
mod gadget;
mod truncated;
pub use context::NttGadgetEncryptContext;

/// A single-modulus GLWE secret key in NTT form.
/// Key storage is securely erased on drop.
///
/// # Correctness
///
/// Key values must be canonical residues in the NTT representation used by
/// subsequent operations. The key does not store the modulus or table;
/// callers must preserve both when supplying parameters and transform tables.
#[derive(Clone)]
pub struct NttGlweSecretKey<T: FheUint> {
    key: Vec<T>,
    size: GlweSize,
    distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for NttGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGlweSecretKey<T> {}

impl<T: FheUint> Drop for NttGlweSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Creates a new [`NttGlweSecretKey<T>`].
    ///
    /// # Correctness
    ///
    /// `key` must satisfy the representation contract of [`Self`] and encode
    /// a secret key with distribution `distr`; neither property is checked.
    ///
    /// # Panics
    ///
    /// Panics if `key.len()` differs from `size.mask_len()`.
    #[inline]
    #[must_use]
    pub fn new(key: Vec<T>, size: GlweSize, distr: SecretKeyDistr) -> Self {
        assert_eq!(key.len(), size.mask_len(), "NTT secret key layout mismatch");
        Self { key, size, distr }
    }

    /// Returns the coefficient-domain GLWE layout.
    #[inline]
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.size
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.size.poly_length()
    }

    /// Returns the GLWE dimension.
    #[inline]
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.size.dimension()
    }

    /// Returns the secret-key distribution.
    #[inline]
    #[must_use]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    #[inline]
    /// Iterates over the NTT-domain secret polynomials in GLWE component order.
    #[must_use]
    pub fn iter(&self) -> NttPolynomialIter<'_, T> {
        NttPolynomialIter::new(self.key.as_slice(), self.size.poly_length())
    }

    /// Encodes and transforms a signed coefficient-domain secret key.
    ///
    /// # Correctness
    ///
    /// Every signed coefficient in `secret_key` must satisfy `s.unsigned_abs() < q`,
    /// where `q` is `ntt_table.modulus()`; see [`EncodeSigned::encode_signed`].
    ///
    /// # Panics
    ///
    /// Panics if the table polynomial length differs from the key layout.
    #[inline]
    #[must_use]
    pub fn from_coeff_secret_key<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(ntt_table.poly_length(), secret_key.poly_length());
        Self::from_coeff_secret_key_kernel(secret_key, ntt_table)
    }

    /// Requires a matching table length and signed coefficient magnitudes below
    /// its modulus. The final key owns storage before NTT can panic.
    fn from_coeff_secret_key_kernel<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let size = secret_key.glwe_size();
        let poly_length = size.poly_length();
        let mut key = Self {
            key: vec![T::ZERO; size.mask_len()],
            size,
            distr: secret_key.distr(),
        };
        let modulus = UintModulus(ntt_table.modulus());
        for (coefficients, secret) in secret_key.iter().zip(key.key.chunks_exact_mut(poly_length)) {
            modulus.encode_signed_slice_to(coefficients, secret);
            ntt_table.transform_slice(secret);
        }

        key
    }

    /// Samples one signed coefficient key and returns it with its NTT form.
    /// Fixed weights apply to the complete `k * N` coefficient key. Both
    /// representations are erased on drop, including unwinding during generation.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the table length or modulus differs from
    /// `params`. Inherits [`GlweSecretKey::generate`]'s sampling conditions.
    #[must_use]
    pub fn generate_pair<R, M>(
        params: &GlweParameters<T, M>,
        ntt_table: &impl NttTable<ValueT = T>,
        rng: &mut R,
    ) -> (GlweSecretKey<T>, Self)
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        assert_eq!(
            ntt_table.poly_length(),
            params.poly_length(),
            "NTT polynomial length mismatch"
        );
        assert_eq!(
            ntt_table.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );
        let coefficients = GlweSecretKey::generate(params.size(), params.secret_key_sampler(), rng);
        let key = Self::from_coeff_secret_key_kernel(&coefficients, ntt_table);
        (coefficients, key)
    }
}
