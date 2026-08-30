//! NTRU key switching through NLev external products.

use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::nlev::{FourierNlev, NttNlev};
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;

use crate::secret_key::encode_secret_polynomial_to;
use crate::{
    FourierNtruExternalProductContext, FourierNtruGadgetEncryptContext, FourierNtruSecretKey,
    NlevParameters, NtruCiphertext, NtruSecretKey, NttNtruExternalProductContext,
    NttNtruGadgetEncryptContext, NttNtruSecretKey,
};

/// An exact NTT-domain key-switching key from an NTRU secret `f` to `f'`.
///
/// The stored key is `NLEV_{f'}[f]`. Applying its external product to
/// `NTRU_f[mu]` produces `NTRU_{f'}[mu]`.
#[derive(Clone)]
pub struct NttNtruKeySwitchingKey<T: FheUint> {
    data: NttNlev<Vec<T>>,
}

impl<T: FheUint> NttNtruKeySwitchingKey<T> {
    /// Generates `NLEV_{f'}[f]` under `output_secret_key`.
    ///
    /// `parameters` supplies the output encryption domain and the key-switch
    /// decomposition basis `(B_ks, L_ks)`.
    pub fn generate<M, Table, R>(
        input_secret_key: &NtruSecretKey<T>,
        output_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = input_secret_key.poly_length();
        assert_eq!(output_secret_key.poly_length(), poly_length);

        let mut encoded_secret = PolynomialOwned::zero(poly_length);
        encode_secret_polynomial_to(
            input_secret_key.as_slice(),
            encoded_secret.as_mut(),
            parameters.ntru().cipher_modulus(),
        );
        let mut data = NttNlev::zero(parameters.nlev_len());
        output_secret_key.encrypt_nlev_to(
            &encoded_secret,
            &mut data,
            parameters,
            ntt,
            rng,
            context,
        );
        Self { data }
    }

    /// Returns the raw NTT-domain NLev values.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.data.as_ref()
    }

    /// Key-switches a coefficient-domain NTRU ciphertext into `output`.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = input.as_ref().len();
        assert_eq!(output.as_ref().len(), poly_length);
        assert_eq!(poly_length, parameters.poly_length());
        assert_eq!(self.data.as_ref().len(), parameters.nlev_len());
        self.data.external_product_to(
            &Polynomial(input.as_ref()),
            output,
            parameters.basis(),
            parameters.ntru().cipher_modulus(),
            ntt,
            context,
        );
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    pub fn key_switch<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) -> NtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = NtruCiphertext::zero(input.as_ref().len());
        self.key_switch_to(input, &mut output, parameters, ntt, context);
        output
    }
}

/// A native-torus Fourier key-switching key from an NTRU secret `f` to `f'`.
///
/// The stored key is `NLEV_{f'}[f]`. Applying its external product to
/// `NTRU_f[mu]` produces `NTRU_{f'}[mu]`.
#[derive(Clone)]
pub struct FourierNtruKeySwitchingKey {
    data: FourierNlev<Vec<Complex64>>,
}

impl FourierNtruKeySwitchingKey {
    /// Generates `NLEV_{f'}[f]` under `output_secret_key`.
    ///
    /// `parameters` supplies the output encryption domain and the key-switch
    /// decomposition basis `(B_ks, L_ks)`.
    pub fn generate<T, Table, R>(
        input_secret_key: &NtruSecretKey<T>,
        output_secret_key: &FourierNtruSecretKey,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = input_secret_key.poly_length();
        assert_eq!(output_secret_key.poly_length(), poly_length);

        let mut encoded_secret = PolynomialOwned::zero(poly_length);
        encode_secret_polynomial_to(
            input_secret_key.as_slice(),
            encoded_secret.as_mut(),
            NativeModulus::new(),
        );
        let mut data = FourierNlev::zero(parameters.fourier_nlev_len());
        output_secret_key.encrypt_nlev_to(
            &encoded_secret,
            &mut data,
            parameters,
            fft,
            rng,
            context,
        );
        Self { data }
    }

    /// Returns the raw Fourier-domain NLev values.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        self.data.as_ref()
    }

    /// Key-switches a coefficient-domain native-torus NTRU ciphertext into `output`.
    pub fn key_switch_to<T, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = input.as_ref().len();
        assert_eq!(output.as_ref().len(), poly_length);
        assert_eq!(poly_length, parameters.poly_length());
        assert_eq!(self.data.as_ref().len(), parameters.fourier_nlev_len());
        self.data.external_product_to(
            &Polynomial(input.as_ref()),
            output,
            parameters.basis(),
            fft,
            context,
        );
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    pub fn key_switch<T, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) -> NtruCiphertext<Vec<T>>
    where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let mut output = NtruCiphertext::zero(input.as_ref().len());
        self.key_switch_to(input, &mut output, parameters, fft, context);
        output
    }
}
