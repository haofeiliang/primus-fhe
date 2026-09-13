//! NLev and NGSW encryption.

use super::{FourierNtruGadgetEncryptContext, FourierNtruSecretKey};
use crate::{FourierNgswCiphertext, FourierNlevCiphertext, NlevParameters};
use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
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
        self.assert_gadget_domain(message, result.as_ref(), params, fft, context);

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
        self.assert_gadget_domain(message, result.as_ref(), params, fft, context);

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

    fn assert_gadget_domain<T, Table, A>(
        &self,
        message: &Polynomial<A>,
        result: &[Complex64],
        params: &NlevParameters<T, NativeModulus<T>>,
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
    {
        self.assert_domain(params.ntru(), fft);
        assert_eq!(message.as_ref().len(), self.poly_length());
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());
        assert_eq!(context.transformed.len(), fft.fourier_length());
        assert_eq!(result.len(), params.fourier_nlev_len());
    }
}
