//! NLev and NGSW encryption.

use super::{FourierNtruGadgetEncryptContext, FourierNtruSecretKey};
use crate::{FourierNgswCiphertext, FourierNlevCiphertext, NlevParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};

impl FourierNtruSecretKey {
    /// Generates a Fourier NLev encryption of an already encoded native-torus polynomial.
    pub fn encrypt_nlev_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNlevCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, context);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.fourier_nlev_len(),
            "gadget output length mismatch"
        );

        let ntru_params = params.ntru();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_to_unchecked(
                &context.encoded,
                &mut level,
                ntru_params,
                fft,
                rng,
                &mut context.ntru,
            );
        }
    }

    /// Encrypts a constant ring element as NLev without plaintext scaling.
    /// Each level has phase `g_l * input + e_l`; input `1` initializes an
    /// encrypted accumulator through an NLev external product.
    /// Reuses output and scratch, zeroing the coefficient tail once per call.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes for incompatible key/parameter/table,
    /// output or workspace lengths.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied FFT table instance.
    pub fn encrypt_nlev_constant_to<T, Table, R, B>(
        &self,
        input: T,
        output: &mut FourierNlevCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, context);
        assert_eq!(
            output.as_ref().len(),
            params.fourier_nlev_len(),
            "NLev output length mismatch"
        );
        context.encoded.as_mut().fill(T::ZERO);
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntru_mut(fft.fourier_length()))
        {
            context.encoded.as_mut()[0] = input.wrapping_mul(scalar);
            self.encrypt_encoded_to_unchecked(
                &context.encoded,
                &mut level,
                params.ntru(),
                fft,
                rng,
                &mut context.ntru,
            );
        }
    }

    /// Generates a Fourier NGSW encryption of an already encoded native-torus polynomial.
    pub fn encrypt_ngsw_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNgswCiphertext<B>,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = Complex64>,
    {
        self.assert_gadget_domain(params, fft, context);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.fourier_nlev_len(),
            "gadget output length mismatch"
        );

        let ntru_params = params.ntru();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            fft.forward_as_torus(context.encoded.as_ref(), &mut context.transformed);
            self.encrypt_zeros_to_unchecked(&mut level, ntru_params, fft, rng, &mut context.ntru);
            FourierPolynomial(level.as_mut())
                .add_assign(&FourierPolynomial(context.transformed.as_slice()));
        }
    }

    /// Encrypts signed constants into contiguous Fourier NGSWs without plaintext scaling.
    ///
    /// Accepts coefficient-secret slices directly. Output uses
    /// `[input][level][Fourier coefficient]` layout and must contain exactly
    /// `input.len() * params.fourier_nlev_len()` values. Resources are checked
    /// once per batch. Empty input/output consumes no randomness.
    /// Reuses output and the supplied workspace without allocating.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key/parameters/FFT,
    /// output or workspace lengths, or a batch length overflow.
    /// A panicking RNG or FFT can leave partial output and modified scratch.
    ///
    /// # Correctness
    ///
    /// Use the FFT table instance with which this secret key was constructed.
    pub fn encrypt_ngsw_signed_constant_batch_to<T, Table, R>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [Complex64],
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_domain(params, fft, context);
        let nlev_len = params.fourier_nlev_len();
        let expected = input
            .len()
            .checked_mul(nlev_len)
            .expect("Fourier NGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "Fourier NGSW batch output length mismatch"
        );
        context.encoded.as_mut().fill(T::ZERO);
        for (&value, block) in input.iter().zip(output.chunks_exact_mut(nlev_len)) {
            let constant = value.cast_to_unsigned();
            for (scalar, level) in params
                .basis()
                .scalar_iter()
                .zip(block.chunks_exact_mut(fft.fourier_length()))
            {
                context.encoded.as_mut()[0] = constant.wrapping_mul(scalar);
                // Native-ring multiplication precedes torus lifting; preserve
                // the same per-level FFT rounding as polynomial encryption.
                fft.forward_as_torus(context.encoded.as_ref(), &mut context.transformed);
                let mut level = crate::FourierNtruCiphertext::new(level);
                self.encrypt_zeros_to_unchecked(
                    &mut level,
                    params.ntru(),
                    fft,
                    rng,
                    &mut context.ntru,
                );
                FourierPolynomial(level.as_mut())
                    .add_assign(&FourierPolynomial(context.transformed.as_slice()));
            }
        }
    }

    fn assert_gadget_domain<T, Table>(
        &self,
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
    {
        self.assert_domain(params.ntru(), fft);
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());
        assert_eq!(context.transformed.len(), fft.fourier_length());
    }
}
