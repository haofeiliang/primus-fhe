//! Ordinary encryption.

use super::{FourierNtruEncryptContext, FourierNtruSecretKey};
use crate::{FourierNtruCiphertext, NtruParameters};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};

impl FourierNtruSecretKey {
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
