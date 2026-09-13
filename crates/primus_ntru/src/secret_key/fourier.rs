//! Native-torus Fourier NTRU secret key.

use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::{FheUint, SignedInteger};
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, FourierPolynomialOwned, Polynomial, PolynomialOwned};
use primus_reduce::{EncodeSigned, ReduceSub};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{FourierNtruCiphertext, NtruError, NtruParameters, SecretKeyDistr};

use super::NtruSecretKey;

// A tiny complex evaluation makes both fresh encryption and later external
// products numerically unstable even though it is not exactly zero.
const MIN_FOURIER_KEY_NORM_SQUARED: f64 = f64::EPSILON;

/// A native-torus NTRU key represented by `FFT(f)` and its pointwise inverse.
/// Both polynomials are securely erased on drop, including failed conversions.
/// Explicit zeroization clears their lengths and makes the key unusable.
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

    /// Encrypts a polynomial with unsigned plaintext embedding.
    pub fn encrypt<T, Table, R, A>(
        &self,
        message: &Polynomial<A>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) -> FourierNtruCiphertext<Vec<Complex64>>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut result = FourierNtruCiphertext::zero(fft.fourier_length());
        self.encrypt_to(message, &mut result, params, fft, rng, context);
        result
    }

    /// Encrypts a polynomial with unsigned plaintext embedding into `result`.
    pub fn encrypt_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Plaintext {
                values: message.as_ref(),
                embedding: PlaintextEmbedding::Unsigned,
            },
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    /// Encrypts a polynomial with centered plaintext embedding into `result`.
    pub fn encrypt_centered_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Plaintext {
                values: message.as_ref(),
                embedding: PlaintextEmbedding::Centered,
            },
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    /// Encrypts coefficients already encoded in the native torus.
    pub fn encrypt_encoded_to<T, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_domain(params, fft);
        assert_eq!(encoded.as_ref().len(), self.poly_length());
        assert_eq!(result.as_ref().len(), fft.fourier_length());
        assert_eq!(context.coeff.as_ref().len(), self.poly_length());
        self.encrypt_encoded_to_unchecked(encoded, result, params, fft, rng, context);
    }

    /// Encrypts zero into a freshly allocated Fourier ciphertext.
    pub fn encrypt_zero<T, Table, R>(
        &self,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) -> FourierNtruCiphertext<Vec<Complex64>>
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut result = FourierNtruCiphertext::zero(fft.fourier_length());
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Zero,
            &mut result,
            params,
            fft,
            rng,
            context,
        );
        result
    }

    fn encrypt_to_with_message<T, Table, R, B>(
        &self,
        message: FourierEncryptionMessage<'_, T>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_domain(params, fft);
        assert_eq!(result.as_ref().len(), fft.fourier_length());
        assert_eq!(context.coeff.as_ref().len(), self.poly_length());
        if let Some(values) = message.as_slice() {
            assert_eq!(values.len(), self.poly_length());
        }

        self.encrypt_to_with_message_unchecked(message, result, params, fft, rng, context);
    }

    pub(super) fn encrypt_encoded_to_unchecked<T, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(encoded.as_ref().len(), self.poly_length());
        debug_assert_eq!(result.as_ref().len(), fft.fourier_length());
        self.encrypt_to_with_message_unchecked(
            FourierEncryptionMessage::Encoded(encoded.as_ref()),
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    pub(super) fn encrypt_zero_to_unchecked<T, Table, R, B>(
        &self,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(result.as_ref().len(), fft.fourier_length());
        self.encrypt_to_with_message_unchecked(
            FourierEncryptionMessage::Zero,
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    fn encrypt_to_with_message_unchecked<T, Table, R, B>(
        &self,
        message: FourierEncryptionMessage<'_, T>,
        result: &mut FourierNtruCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        let coefficients = context.coeff.as_mut();
        primus_distr::sample_gaussian_values_to(coefficients, params.noise_distribution(), rng);
        match message {
            FourierEncryptionMessage::Zero => {}
            FourierEncryptionMessage::Plaintext { values, embedding } => params
                .plaintext_codec()
                .add_encode_slice_assign(coefficients, values, embedding),
            FourierEncryptionMessage::Encoded(values) => {
                Polynomial(&mut *coefficients).add_assign(&Polynomial(values), NativeModulus::new())
            }
        }

        fft.forward_as_torus(coefficients, result.as_mut());
        FourierPolynomial(result.as_mut()).mul_assign(&self.inv_key);
    }

    /// Computes `f * c` and writes `e + Delta * m` in native coefficient form.
    pub fn phase_to<T, Table, A, B>(
        &self,
        cipher: &FourierNtruCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruDecryptContext,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
    {
        self.assert_domain(params, fft);
        assert_eq!(cipher.as_ref().len(), fft.fourier_length());
        assert_eq!(result.as_ref().len(), self.poly_length());
        assert_eq!(context.phase.as_ref().len(), fft.fourier_length());

        FourierPolynomial(cipher.as_ref()).mul_to(&self.key, &mut context.phase);
        fft.backward_as_torus(context.phase.as_ref(), result.as_mut());
    }

    /// Decrypts a Fourier ciphertext with unsigned plaintext embedding.
    pub fn decrypt<T, Table, A>(
        &self,
        cipher: &FourierNtruCiphertext<A>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruDecryptContext,
    ) -> PolynomialOwned<T>
    where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
    {
        let mut result = PolynomialOwned::zero(self.poly_length());
        self.decrypt_to(cipher, &mut result, params, fft, context);
        result
    }

    /// Decrypts a Fourier ciphertext into `result`.
    pub fn decrypt_to<T, Table, A, B>(
        &self,
        cipher: &FourierNtruCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruDecryptContext,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
    {
        self.phase_to(cipher, result, params, fft, context);
        params
            .plaintext_codec()
            .decode_slice_assign(result.as_mut());
    }

    /// Decrypts and returns the absolute coefficient-wise native-torus error.
    pub fn decrypt_with_noise<T, Table, A>(
        &self,
        cipher: &FourierNtruCiphertext<A>,
        params: &NtruParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruDecryptContext,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
    {
        let modulus = NativeModulus::new();
        let mut message = PolynomialOwned::zero(self.poly_length());
        self.phase_to(cipher, &mut message, params, fft, context);
        let mut noise = PolynomialOwned::zero(self.poly_length());

        for (phase, noise) in message.iter_mut().zip(noise.iter_mut()) {
            let phase_mod_q = *phase;
            let decoded = params.plaintext_codec().decode_value(phase_mod_q);
            let encoded = params
                .plaintext_codec()
                .encode_value(decoded, PlaintextEmbedding::Unsigned);
            *phase = decoded;
            *noise = modulus
                .reduce_sub(phase_mod_q, encoded)
                .min(modulus.reduce_sub(encoded, phase_mod_q));
        }
        (message, noise)
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

enum FourierEncryptionMessage<'a, T: FheUint> {
    Zero,
    Plaintext {
        values: &'a [T],
        embedding: PlaintextEmbedding,
    },
    Encoded(&'a [T]),
}

impl<'a, T: FheUint> FourierEncryptionMessage<'a, T> {
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext { values, .. } | Self::Encoded(values) => Some(values),
        }
    }
}

/// Reusable coefficient buffer for Fourier NTRU encryption.
/// Sensitive coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruEncryptContext<T: FheUint> {
    coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierNtruEncryptContext<T> {
    /// Creates an encryption workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruEncryptContext<T> {
    fn zeroize(&mut self) {
        self.coeff.as_mut().iter_mut().zeroize();
        self.coeff.0.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruEncryptContext<T> {}

impl<T: FheUint> Drop for FourierNtruEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable Fourier buffer for NTRU phase computation and decryption.
/// Sensitive phase values are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruDecryptContext {
    phase: FourierPolynomialOwned,
}

impl FourierNtruDecryptContext {
    /// Creates a decryption workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        Self {
            phase: FourierPolynomialOwned::zero(poly_length / 2),
        }
    }
}

impl Zeroize for FourierNtruDecryptContext {
    fn zeroize(&mut self) {
        for value in self.phase.as_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.phase.0.spare_capacity_mut().zeroize();
    }
}

impl ZeroizeOnDrop for FourierNtruDecryptContext {}

impl Drop for FourierNtruDecryptContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}
