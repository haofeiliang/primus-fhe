//! Native-torus Fourier NTRU secret key.

use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_modulus::NativeModulus;
use primus_poly::FourierPolynomialOwned;
use primus_reduce::EncodeSigned;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{NtruError, NtruParameters, SecretKeyDistr};

use super::NtruSecretKey;

mod context;
mod decrypt;
mod encrypt;
mod gadget;

pub use context::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
};

// A tiny complex evaluation makes both fresh encryption and later external
// products numerically unstable even though it is not exactly zero.
const MIN_FOURIER_KEY_NORM_SQUARED: f64 = f64::EPSILON;

/// A native-torus NTRU key represented by `FFT(f)` and its pointwise inverse.
/// Both polynomials are securely erased on drop, including failed conversions.
/// Explicit zeroization clears their lengths and makes the key unusable.
///
/// All Fourier operations must use the FFT table instance supplied at construction;
/// another table of the same length can have a different transform ordering.
#[derive(Clone)]
pub struct FourierNtruSecretKey {
    key: FourierPolynomialOwned,
    inv_key: FourierPolynomialOwned,
    poly_length: usize,
    distr: SecretKeyDistr,
}

impl Zeroize for FourierNtruSecretKey {
    #[inline]
    fn zeroize(&mut self) {
        // Complex64 does not implement Zeroize, so erase its components before
        // clearing each buffer and wiping its full capacity, as Vec::zeroize does.
        for polynomial in [&mut self.key, &mut self.inv_key] {
            for value in polynomial.as_mut() {
                value.re.zeroize();
                value.im.zeroize();
            }
            polynomial.0.clear();
            polynomial.0.spare_capacity_mut().zeroize();
        }
        // Keep the existing domain checks consistent with the cleared buffers.
        self.poly_length = 0;
    }
}

impl ZeroizeOnDrop for FourierNtruSecretKey {}

impl Drop for FourierNtruSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FourierNtruSecretKey {
    fn allocate(poly_length: usize, distr: SecretKeyDistr) -> Self {
        Self {
            key: FourierPolynomialOwned::zero(poly_length / 2),
            inv_key: FourierPolynomialOwned::zero(poly_length / 2),
            poly_length,
            distr,
        }
    }

    /// For N = 2^k, X^N + 1 = (X + 1)^N over F_2. Thus f is a unit
    /// modulo 2^BITS exactly when f(1), the coefficient sum, is odd.
    fn is_unit_mod_two<T: TorusFftValue>(secret_key: &NtruSecretKey<T>) -> bool {
        secret_key
            .as_slice()
            .iter()
            .filter(|&&coefficient| (coefficient.cast_to_unsigned() & T::ONE) == T::ONE)
            .count()
            % 2
            == 1
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the distribution used to sample the coefficient key.
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Converts a native coefficient key to Fourier form and computes the
    /// pointwise complex inverse of `FFT(f)`.
    ///
    /// # Errors
    ///
    /// Returns an error if `f` is not a unit modulo two or if its Fourier
    /// inverse is numerically unstable.
    pub fn try_from_coeff_secret_key<T, Table>(
        secret_key: &NtruSecretKey<T>,
        fft: &mut FftEngine<'_, Table>,
    ) -> Result<Self, NtruError>
    where
        T: TorusFftValue,
        Table: FftTable,
    {
        let poly_length = secret_key.poly_length();
        assert_eq!(fft.poly_length(), poly_length);

        if !Self::is_unit_mod_two(secret_key) {
            return Err(NtruError::NonInvertibleSecretKey);
        }

        let mut transformed = Self::allocate(poly_length, secret_key.distr());
        let mut native_coefficients = Zeroizing::new(vec![T::ZERO; poly_length]);
        transformed.try_update_from_coeff_secret_key(secret_key, &mut native_coefficients, fft)?;
        Ok(transformed)
    }

    /// Converts a unit modulo two into the existing buffers. The caller checks
    /// all lengths and keeps the native scratch under drop protection. A failed
    /// stability check can leave partial inverse data; no key is returned until
    /// a successful attempt has overwritten the complete key and inverse.
    fn try_update_from_coeff_secret_key<T, Table>(
        &mut self,
        secret_key: &NtruSecretKey<T>,
        native_coefficients: &mut [T],
        fft: &mut FftEngine<'_, Table>,
    ) -> Result<(), NtruError>
    where
        T: TorusFftValue,
        Table: FftTable,
    {
        NativeModulus::new().encode_signed_slice_to(secret_key.as_slice(), native_coefficients);
        fft.forward_as_integer(native_coefficients, self.key.as_mut());

        for (&value, inverse) in self.key.as_ref().iter().zip(self.inv_key.as_mut()) {
            let norm_squared = value.norm_sqr();
            if !norm_squared.is_finite() || norm_squared <= MIN_FOURIER_KEY_NORM_SQUARED {
                return Err(NtruError::UnstableFourierInverse);
            }
            *inverse = Complex64::new(1.0, 0.0) / value;
        }

        Ok(())
    }

    /// Rejection-samples a native-ring unit with a stable Fourier inverse.
    /// See [`Self::generate_pair`] for error and panic conditions.
    pub fn generate<T, Table, R>(
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Result<Self, NtruError>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        Self::generate_pair(params, fft, rng).map(|(_, transformed_key)| transformed_key)
    }

    /// Rejection-samples a native-ring unit with a stable Fourier inverse and
    /// returns its signed coefficient and Fourier representations.
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
    /// Panics if the FFT length differs from the parameters,
    /// or a fixed weight exceeds the polynomial length or its sum overflows.
    pub fn generate_pair<T, Table, R>(
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Result<(NtruSecretKey<T>, Self), NtruError>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(fft.poly_length(), params.poly_length());

        let mut coefficient_key =
            NtruSecretKey::allocate(params.poly_length(), params.secret_key_distr());
        let mut transformed = Self::allocate(params.poly_length(), params.secret_key_distr());
        let mut native_coefficients = Zeroizing::new(vec![T::ZERO; params.poly_length()]);
        let sampler = params.secret_key_sampler();
        for _ in 0..crate::parameter::KEY_GENERATION_ATTEMPTS {
            sampler.sample_signed_to(&mut coefficient_key.key, rng);
            if !Self::is_unit_mod_two(&coefficient_key) {
                continue;
            }
            match transformed.try_update_from_coeff_secret_key(
                &coefficient_key,
                &mut native_coefficients,
                fft,
            ) {
                Ok(()) => return Ok((coefficient_key, transformed)),
                Err(NtruError::UnstableFourierInverse) => {}
                Err(error) => return Err(error),
            }
        }
        Err(NtruError::KeyGenerationExhausted)
    }

    /// Rejection-samples a stable binary prefix padded to the NTRU ring.
    ///
    /// The coefficient key contains `active_length` coefficients sampled from
    /// the configured binary distribution followed by zeros. The same key can
    /// therefore be viewed as a smaller external LWE secret after compact
    /// extraction.
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
    /// exceeds `active_length`, or the FFT length differs from the parameters.
    pub fn generate_padded_binary_pair<T, Table, R>(
        params: &NtruParameters<T, NativeModulus<T>>,
        active_length: usize,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Result<(NtruSecretKey<T>, Self), NtruError>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert!(params.secret_key_distr().is_binary());
        assert!((1..=params.poly_length()).contains(&active_length));
        assert_eq!(fft.poly_length(), params.poly_length());

        let mut coefficient_key =
            NtruSecretKey::allocate(params.poly_length(), params.secret_key_distr());
        let mut transformed = Self::allocate(params.poly_length(), params.secret_key_distr());
        let mut native_coefficients = Zeroizing::new(vec![T::ZERO; params.poly_length()]);
        let sampler = params.secret_key_sampler();
        for _ in 0..crate::parameter::KEY_GENERATION_ATTEMPTS {
            sampler.sample_signed_to(&mut coefficient_key.key[..active_length], rng);
            if !Self::is_unit_mod_two(&coefficient_key) {
                continue;
            }
            match transformed.try_update_from_coeff_secret_key(
                &coefficient_key,
                &mut native_coefficients,
                fft,
            ) {
                Ok(()) => return Ok((coefficient_key, transformed)),
                Err(NtruError::UnstableFourierInverse) => {}
                Err(error) => return Err(error),
            }
        }
        Err(NtruError::KeyGenerationExhausted)
    }

    pub(super) fn assert_domain<T, Table>(
        &self,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
    {
        assert_eq!(params.poly_length(), self.poly_length());
        assert_eq!(fft.poly_length(), self.poly_length());
    }
}
