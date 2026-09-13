//! Phase extraction and plaintext decoding.

use super::{FourierNtruDecryptContext, FourierNtruSecretKey};
use crate::{FourierNtruCiphertext, NtruParameters};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::ReduceSub;

impl FourierNtruSecretKey {
    /// Computes `f * c` and writes `e + Delta * m` in native coefficient form.
    /// The result is an undecoded coefficient polynomial; no plaintext codec or
    /// noise distribution is needed. Output is overwritten, including old values.
    ///
    /// # Correctness
    ///
    /// The input and key must use this FFT table instance's Fourier representation.
    ///
    /// # Panics
    ///
    /// Panics before writes if transform, input, output or workspace lengths
    /// do not match the key.
    pub fn phase_to<T, Table, A, B>(
        &self,
        cipher: &FourierNtruCiphertext<A>,
        result: &mut Polynomial<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruDecryptContext,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
        assert_eq!(cipher.as_ref().len(), fft.fourier_length());
        assert_eq!(result.as_ref().len(), self.poly_length());
        assert_eq!(context.phase.as_ref().len(), fft.fourier_length());

        FourierPolynomial(cipher.as_ref()).mul_to(&self.key, &mut context.phase);
        fft.backward_as_torus(context.phase.as_ref(), result.as_mut());
    }

    /// Decrypts to unsigned plaintext values in `[0, t)`.
    /// Both unsigned and centered embeddings use this decoder.
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
        assert_eq!(
            params.poly_length(),
            self.poly_length(),
            "NTRU parameter length mismatch"
        );
        self.phase_to(cipher, result, fft, context);
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
        assert_eq!(
            params.poly_length(),
            self.poly_length(),
            "NTRU parameter length mismatch"
        );
        self.phase_to(cipher, &mut message, fft, context);
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
}
