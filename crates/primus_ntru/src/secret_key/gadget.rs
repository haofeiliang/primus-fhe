//! NLev and NGSW generation with transform-domain NTRU secret keys.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    FourierNgswCiphertext, FourierNlevCiphertext, NtruParameters, NttNgswCiphertext,
    NttNlevCiphertext,
};

use super::{FourierNtruEncryptContext, FourierNtruSecretKey, NttNtruSecretKey};

/// Reusable coefficient buffer for NTT NLev/NGSW generation.
pub struct NttNtruGadgetEncryptContext<T: FheUint> {
    encoded: PolynomialOwned<T>,
}

impl<T: FheUint> NttNtruGadgetEncryptContext<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            encoded: PolynomialOwned::zero(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for NttNtruGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().fill(T::ZERO);
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttNtruGadgetEncryptContext<T> {}

/// Reusable buffers for Fourier NLev/NGSW generation.
pub struct FourierNtruGadgetEncryptContext<T: FheUint> {
    encoded: PolynomialOwned<T>,
    transformed: Vec<Complex64>,
    ntru: FourierNtruEncryptContext<T>,
}

impl<T: FheUint> FourierNtruGadgetEncryptContext<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            transformed: vec![Complex64::default(); poly_length / 2],
            ntru: FourierNtruEncryptContext::new(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().fill(T::ZERO);
        self.transformed.fill(Complex64::default());
        self.ntru.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruGadgetEncryptContext<T> {}

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Generates an NTT NLev encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_nlev_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNlevCiphertext<B>,
        params: &NtruParameters<T, M>,
        basis: &ApproxSignedBasis<T>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.assert_gadget_domain(message, result.as_ref(), params, basis, ntt, context);

        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();
        for (scalar, mut level) in basis
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_to_unchecked(&context.encoded, &mut level, params, ntt, rng);
        }
    }

    /// Generates an NTT NGSW encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_ngsw_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNgswCiphertext<B>,
        params: &NtruParameters<T, M>,
        basis: &ApproxSignedBasis<T>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.assert_gadget_domain(message, result.as_ref(), params, basis, ntt, context);

        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();
        for (scalar, mut level) in basis
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            ntt.transform_slice(context.encoded.as_mut());
            self.encrypt_zero_to_unchecked(&mut level, params, ntt, rng);
            NttPolynomial(level.as_mut())
                .add_assign(&NttPolynomial(context.encoded.as_ref()), modulus);
        }
    }

    fn assert_gadget_domain<M, Table, A>(
        &self,
        message: &Polynomial<A>,
        result: &[T],
        params: &NtruParameters<T, M>,
        basis: &ApproxSignedBasis<T>,
        ntt: &Table,
        context: &NttNtruGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        self.assert_domain(params, ntt);
        assert_eq!(basis.modulus(), Some(params.cipher_modulus().value()));
        assert_eq!(message.as_ref().len(), self.poly_length());
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());
        assert_eq!(result.len(), basis.decompose_length() * self.poly_length());
    }
}

impl FourierNtruSecretKey {
    /// Generates a Fourier NLev encryption of an already encoded native-torus polynomial.
    pub fn encrypt_nlev_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierNlevCiphertext<B>,
        params: &NtruParameters<T, NativeModulus<T>>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        self.assert_gadget_domain(message, result.as_ref(), params, basis, fft, context);

        let modulus = params.cipher_modulus();
        for (scalar, mut level) in basis
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_to_unchecked(
                &context.encoded,
                &mut level,
                params,
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
        params: &NtruParameters<T, NativeModulus<T>>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        self.assert_gadget_domain(message, result.as_ref(), params, basis, fft, context);

        let modulus = params.cipher_modulus();
        for (scalar, mut level) in basis
            .scalar_iter()
            .zip(result.iter_ntru_mut(fft.fourier_length()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            fft.forward_as_torus(context.encoded.as_ref(), &mut context.transformed);
            self.encrypt_zero_to_unchecked(&mut level, params, fft, rng, &mut context.ntru);
            FourierPolynomial(level.as_mut())
                .add_assign(&FourierPolynomial(context.transformed.as_slice()));
        }
    }

    fn assert_gadget_domain<T, Table, A>(
        &self,
        message: &Polynomial<A>,
        result: &[Complex64],
        params: &NtruParameters<T, NativeModulus<T>>,
        basis: &ApproxSignedBasis<T>,
        fft: &FftEngine<'_, Table>,
        context: &FourierNtruGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
    {
        self.assert_domain(params, fft);
        assert_eq!(basis.modulus(), None);
        assert_eq!(message.as_ref().len(), self.poly_length());
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());
        assert_eq!(context.transformed.len(), fft.fourier_length());
        assert_eq!(
            result.len(),
            basis.decompose_length() * fft.fourier_length()
        );
    }
}
