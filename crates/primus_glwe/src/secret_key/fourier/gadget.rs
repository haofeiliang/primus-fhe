//! Fourier GLev and GGSW generation.

use super::{FourierGadgetEncryptContext, FourierGlweSecretKey};
use crate::{FourierGgswCiphertext, FourierGlevCiphertext, GlevParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};

impl FourierGlweSecretKey {
    /// Generates a Fourier GLev encryption of a coefficient-domain ring polynomial.
    ///
    /// Applies gadget basis scaling without applying the plaintext codec.
    /// GLev uses only polynomial workspace; its cached level count need not match.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    ///
    /// # Panics
    ///
    /// Panics if the key layout, input/output lengths, FFT length or polynomial
    /// workspace do not match `params`. Checks precede all output writes.
    pub fn encrypt_glev_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGlevCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_compatible(params, fft);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.fourier_glev_len(),
            "Fourier GLev output layout mismatch"
        );
        context.assert_glev_compatible(params.size());
        self.encrypt_glev_kernel_to(input, output, params, fft, rng, context);
    }

    /// Encrypts after the caller validates key, input/output, FFT and workspace.
    pub(crate) fn encrypt_glev_kernel_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGlevCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        let modulus = params.cipher_modulus();
        let fourier_glwe_len = params.fourier_glwe_len();

        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_glwe_mut(fourier_glwe_len))
        {
            input.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_kernel_to(
                &context.encoded,
                &mut glwe,
                params.inner(),
                fft,
                rng,
                &mut context.glwe,
            );
        }
    }

    /// Generates a Fourier GGSW encryption of a coefficient-domain ring polynomial.
    ///
    /// Applies gadget basis scaling without applying the plaintext codec.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    ///
    /// # Panics
    ///
    /// Panics if the key, input, transform, output, or workspace lengths do
    /// not match the gadget parameters. Checks precede all output writes.
    pub fn encrypt_ggsw_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_compatible(params, fft);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            params.fourier_ggsw_len(),
            "Fourier GGSW output layout mismatch"
        );
        context.assert_ggsw_compatible(params.size());
        self.encrypt_ggsw_kernel_to(input, output, params, fft, rng, context);
    }

    /// Encrypts after the caller validates key, input/output, FFT and workspace.
    pub(crate) fn encrypt_ggsw_kernel_to<T, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        let fourier_length = fft.fourier_length();
        let modulus = params.cipher_modulus();
        // Torus lifting follows native-ring scaling, so each level needs its
        // own FFT. Cache all transformed levels for reuse across rows.
        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(fourier_length))
        {
            input.mul_scalar_to(scalar, &mut context.encoded, modulus);
            fft.forward_as_torus(context.encoded.as_ref(), transformed);
        }

        self.encrypt_ggsw_from_levels_to(output, params, fft, rng, context);
    }

    /// Encrypts using the complete, prepared level transforms in `context`.
    /// The caller establishes matching key, output, table and workspace layouts.
    pub(super) fn encrypt_ggsw_from_levels_to<T, Table, R, B>(
        &self,
        output: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        let fourier_length = fft.fourier_length();
        let fourier_glwe_len = params.fourier_glwe_len();
        let fourier_glev_len = params.fourier_glev_len();
        // Stream [row][level][component] storage, reusing the cached levels.
        // Add each diagonal only after zero encryption has accumulated the
        // original masks into the body; adding it earlier changes the phase.
        for (row, mut glev) in output.iter_glev_mut(fourier_glev_len).enumerate() {
            let diagonal_start = row * fourier_length;
            for (mut glwe, transformed) in glev
                .iter_glwe_mut(fourier_glwe_len)
                .zip(context.level_transforms.chunks_exact(fourier_length))
            {
                self.encrypt_zeros_kernel_to(
                    &mut glwe,
                    params.inner(),
                    fft,
                    rng,
                    &mut context.glwe,
                );
                FourierPolynomial::new(
                    &mut glwe.as_mut()[diagonal_start..diagonal_start + fourier_length],
                )
                .add_assign(&FourierPolynomial::new(transformed));
            }
        }
    }

    /// Validates the key and FFT before composite gadget generation.
    pub(crate) fn assert_gadget_compatible<T: TorusFftValue, Table: FftTable>(
        &self,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
    ) {
        assert_eq!(
            self.glwe_size(),
            params.glwe_size(),
            "GLWE parameter layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            self.poly_length(),
            "FFT polynomial length mismatch"
        );
    }
}
