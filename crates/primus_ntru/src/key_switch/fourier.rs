//! Native-torus Fourier key switching.

use crate::{
    FourierNtruExternalProductContext, FourierNtruGadgetEncryptContext, FourierNtruSecretKey,
    NlevParameters, NtruCiphertext, NtruSecretKey,
};
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::nlev::FourierNlev;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::EncodeSigned;
use zeroize::Zeroizing;

/// A native-torus Fourier key-switching key from an NTRU secret `f` to `f'`.
///
/// The stored key is `NLEV_{f'}[f]`. Applying its external product to
/// `NTRU_f[mu]` produces `NTRU_{f'}[mu]`.
#[derive(Clone)]
pub struct FourierNtruKeySwitchingKey<T: TorusFftValue> {
    data: FourierNlev<Vec<Complex64>>,
    poly_length: usize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierNtruKeySwitchingKey<T> {
    /// Generates `NLEV_{f'}[f]` under `output_secret_key`.
    ///
    /// `parameters` supplies the output encryption domain and the key-switch
    /// decomposition basis `(B_ks, L_ks)`.
    ///
    /// # Panics
    ///
    /// Panics if the secret-key lengths, parameters, FFT length, or gadget
    /// workspace are incompatible. Checks precede sampling.
    ///
    /// # Correctness
    ///
    /// The output secret key must have been constructed with the supplied FFT
    /// table instance. Floating-point errors must fit the precision budget.
    pub fn generate<Table, R>(
        input_secret_key: &NtruSecretKey<T>,
        output_secret_key: &FourierNtruSecretKey,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) -> Self
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = input_secret_key.poly_length();
        assert_eq!(
            output_secret_key.poly_length(),
            poly_length,
            "key-switch secret polynomial length mismatch"
        );

        let mut encoded_secret = Zeroizing::new(vec![T::ZERO; poly_length]);
        NativeModulus::new()
            .encode_signed_slice_to(input_secret_key.as_slice(), encoded_secret.as_mut_slice());
        let mut data = FourierNlev::zero(parameters.fourier_nlev_len());
        output_secret_key.encrypt_nlev_to(
            &Polynomial::new(encoded_secret.as_slice()),
            &mut data,
            parameters,
            fft,
            rng,
            context,
        );
        Self {
            data,
            poly_length,
            basis: parameters.basis().clone(),
        }
    }

    /// Returns the coefficient polynomial length bound to this key.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the native-torus decomposition basis bound to this integer width.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw Fourier-domain NLev values.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        self.data.as_ref()
    }

    /// Key-switches a coefficient-domain native-torus NTRU ciphertext into `output`.
    ///
    /// Uses the polynomial length and decomposition basis stored in this key.
    ///
    /// # Correctness
    ///
    /// The FFT must use the table instance used during key generation.
    /// Floating-point, decomposition and encryption errors must fit the
    /// caller's precision and noise budgets.
    ///
    /// # Panics
    ///
    /// Panics if input/output, FFT, or workspace lengths do not match this key.
    /// Checks precede output writes.
    pub fn key_switch_to<Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.poly_length,
            "key-switch input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.poly_length,
            "key-switch output length mismatch"
        );
        assert_eq!(
            context.poly_length(),
            self.poly_length,
            "key-switch workspace length mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            self.poly_length,
            "key-switch FFT length mismatch"
        );
        self.data.external_product_to(
            &Polynomial(input.as_ref()),
            output,
            &self.basis,
            fft,
            context,
        );
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    ///
    /// Inherits [`Self::key_switch_to`]'s correctness and panic conditions.
    pub fn key_switch<Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) -> NtruCiphertext<Vec<T>>
    where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let mut output = NtruCiphertext::zero(self.poly_length);
        self.key_switch_to(input, &mut output, fft, context);
        output
    }
}
