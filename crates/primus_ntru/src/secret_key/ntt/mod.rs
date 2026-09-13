//! Exact explicit-modulus NTT NTRU secret key.

use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::NttPolynomialOwned;
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NtruError, NtruParameters, SecretKeyDistr};

use super::NtruSecretKey;

mod context;
mod decrypt;
mod encrypt;
mod gadget;

pub use context::NttNtruGadgetEncryptContext;

/// An NTRU secret key represented by `NTT(f)` and its exact pointwise inverse.
/// Both polynomials are securely erased on drop, including failed conversions.
/// Explicit zeroization clears their lengths and makes the key unusable.
///
/// Operations must use the construction modulus and NTT representation. The key
/// stores neither modulus nor table; matching lengths do not establish this premise.
#[derive(Clone)]
pub struct NttNtruSecretKey<T: FheUint> {
    key: NttPolynomialOwned<T>,
    inv_key: NttPolynomialOwned<T>,
    distr: SecretKeyDistr,
}

impl<T: FheUint> Zeroize for NttNtruSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
        self.inv_key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttNtruSecretKey<T> {}

impl<T: FheUint> Drop for NttNtruSecretKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: FheUint> NttNtruSecretKey<T> {
    fn allocate(poly_length: usize, distr: SecretKeyDistr) -> Self {
        Self {
            key: NttPolynomialOwned::zero(poly_length),
            inv_key: NttPolynomialOwned::zero(poly_length),
            distr,
        }
    }

    /// Returns the polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.key.as_ref().len()
    }

    /// Returns the distribution used to sample the coefficient key.
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Converts a coefficient key to NTT form and computes `NTT(f)^(-1)`.
    ///
    /// # Correctness
    ///
    /// Every coefficient must have unsigned magnitude strictly less than
    /// `modulus.value()`. Conversion uses [`EncodeSigned`](primus_reduce::EncodeSigned),
    /// without general reduction. Keys generated from matching [`NtruParameters`] satisfy this
    /// bound; callers importing keys or changing moduli must establish it.
    ///
    /// # Errors
    ///
    /// Returns [`NtruError::NonInvertibleSecretKey`] if an NTT evaluation of
    /// `f` is not invertible modulo `modulus`.
    pub fn try_from_coeff_secret_key<M, Table>(
        secret_key: &NtruSecretKey<T>,
        modulus: M,
        ntt_table: &Table,
    ) -> Result<Self, NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = secret_key.poly_length();
        assert_eq!(ntt_table.poly_length(), poly_length);
        assert_eq!(ntt_table.modulus(), modulus.value());

        // Establish drop protection before encoding or inversion can fail.
        let mut transformed = Self::allocate(poly_length, secret_key.distr());
        transformed.try_update_from_coeff_secret_key(secret_key, modulus, ntt_table)?;
        Ok(transformed)
    }

    /// Overwrites both buffers after the caller establishes matching lengths,
    /// modulus/table and coefficient bounds. A failed inverse may leave partial
    /// output; it stays private until a later successful attempt overwrites it.
    fn try_update_from_coeff_secret_key<M, Table>(
        &mut self,
        secret_key: &NtruSecretKey<T>,
        modulus: M,
        ntt_table: &Table,
    ) -> Result<(), NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        modulus.encode_signed_slice_to(secret_key.as_slice(), self.key.as_mut());
        ntt_table.transform_slice(self.key.as_mut());

        self.key
            .try_inv_to(&mut self.inv_key, modulus)
            .map_err(|_| NtruError::NonInvertibleSecretKey)?;

        debug_assert!(
            self.key
                .as_ref()
                .iter()
                .zip(self.inv_key.as_ref())
                .all(|(&value, &inverse)| modulus.reduce_mul(value, inverse) == T::ONE)
        );

        Ok(())
    }

    /// Rejection-samples an invertible coefficient key and converts it to NTT
    /// form.
    /// See [`Self::generate_pair`] for error and panic conditions.
    pub fn generate<M, Table, R>(
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Result<Self, NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self::generate_pair(params, ntt_table, rng).map(|(_, transformed_key)| transformed_key)
    }

    /// Rejection-samples an invertible key and returns its signed coefficient
    /// and NTT representations.
    ///
    /// Secret buffers are allocated once, reused across rejected candidates,
    /// and erased on drop, including exhausted searches and unwinding.
    ///
    /// # Errors
    ///
    /// Returns [`NtruError::KeyGenerationExhausted`] if no acceptable key is
    /// found within the bounded search.
    ///
    /// # Panics
    ///
    /// Panics if the NTT table length or modulus differs from the parameters,
    /// or a fixed weight exceeds the polynomial length or its sum overflows.
    pub fn generate_pair<M, Table, R>(
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Result<(NtruSecretKey<T>, Self), NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(ntt_table.poly_length(), params.poly_length());
        assert_eq!(ntt_table.modulus(), params.cipher_modulus().value());

        let mut coefficient_key =
            NtruSecretKey::allocate(params.poly_length(), params.secret_key_distr());
        let mut transformed = Self::allocate(params.poly_length(), params.secret_key_distr());
        let sampler = params.secret_key_sampler();
        for _ in 0..crate::parameter::KEY_GENERATION_ATTEMPTS {
            sampler.sample_signed_to(&mut coefficient_key.key, rng);
            match transformed.try_update_from_coeff_secret_key(
                &coefficient_key,
                params.cipher_modulus(),
                ntt_table,
            ) {
                Ok(()) => return Ok((coefficient_key, transformed)),
                Err(NtruError::NonInvertibleSecretKey) => {}
                Err(error) => return Err(error),
            }
        }
        Err(NtruError::KeyGenerationExhausted)
    }

    /// Rejection-samples an invertible binary prefix padded to the NTRU ring.
    ///
    /// The returned coefficient key has `active_length` coefficients sampled
    /// from the configured binary distribution followed by zeros. This supports
    /// compact extraction into a smaller LWE dimension while retaining an NTRU
    /// key switch.
    ///
    /// Buffers are reused and erased as in [`Self::generate_pair`].
    ///
    /// # Errors
    ///
    /// Returns [`NtruError::KeyGenerationExhausted`] if the search is exhausted.
    ///
    /// # Panics
    ///
    /// Panics unless the parameter distribution is binary and
    /// `active_length` belongs to `1..=N`. Also panics if a fixed Hamming weight
    /// exceeds `active_length`, or the NTT table length or modulus differs from
    /// the parameters.
    pub fn generate_padded_binary_pair<M, Table, R>(
        params: &NtruParameters<T, M>,
        active_length: usize,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Result<(NtruSecretKey<T>, Self), NtruError>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert!(params.secret_key_distr().is_binary());
        assert!((1..=params.poly_length()).contains(&active_length));
        assert_eq!(ntt_table.poly_length(), params.poly_length());
        assert_eq!(ntt_table.modulus(), params.cipher_modulus().value());

        let mut coefficient_key =
            NtruSecretKey::allocate(params.poly_length(), params.secret_key_distr());
        let mut transformed = Self::allocate(params.poly_length(), params.secret_key_distr());
        let sampler = params.secret_key_sampler();
        for _ in 0..crate::parameter::KEY_GENERATION_ATTEMPTS {
            sampler.sample_signed_to(&mut coefficient_key.key[..active_length], rng);
            match transformed.try_update_from_coeff_secret_key(
                &coefficient_key,
                params.cipher_modulus(),
                ntt_table,
            ) {
                Ok(()) => return Ok((coefficient_key, transformed)),
                Err(NtruError::NonInvertibleSecretKey) => {}
                Err(error) => return Err(error),
            }
        }
        Err(NtruError::KeyGenerationExhausted)
    }

    pub(super) fn assert_domain<M, Table>(&self, params: &NtruParameters<T, M>, ntt_table: &Table)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(params.poly_length(), self.poly_length());
        assert_eq!(ntt_table.poly_length(), self.poly_length());
        assert_eq!(ntt_table.modulus(), params.cipher_modulus().value());
    }
}
