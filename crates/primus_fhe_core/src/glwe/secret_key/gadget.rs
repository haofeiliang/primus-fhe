//! Single-modulus GLev and GGSW generation with GLWE secret keys.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    FourierGgswCiphertext, FourierGlevCiphertext, GlevParameters, NttGgswCiphertext,
    NttGlevCiphertext,
};

use super::{FourierGlweEncryptContext, FourierGlweSecretKey, NttGlweSecretKey};

/// Reusable workspace for Fourier GLev/GGSW generation.
pub struct FourierGadgetEncryptContext<T: FheUint> {
    encoded: PolynomialOwned<T>,
    level_transforms: Vec<Complex64>,
    glwe: FourierGlweEncryptContext<T>,
}

impl<T: FheUint> FourierGadgetEncryptContext<T> {
    /// Creates a workspace for `poly_length` and `decompose_length`.
    pub fn new(poly_length: usize, decompose_length: usize) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        assert!(decompose_length > 0);
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![Complex64::default(); decompose_length * (poly_length / 2)],
            glwe: FourierGlweEncryptContext::new(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().fill(T::ZERO);
        self.level_transforms.fill(Complex64::default());
        self.glwe.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGadgetEncryptContext<T> {}

/// Reusable workspace for NTT GLev/GGSW generation.
pub struct NttGadgetEncryptContext<T: FheUint> {
    encoded: PolynomialOwned<T>,
    level_transforms: Vec<T>,
}

impl<T: FheUint> NttGadgetEncryptContext<T> {
    /// Creates a workspace for `poly_length` and `decompose_length`.
    pub fn new(poly_length: usize, decompose_length: usize) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        assert!(decompose_length > 0);
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![T::ZERO; decompose_length * poly_length],
        }
    }
}

impl<T: FheUint> Zeroize for NttGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().fill(T::ZERO);
        self.level_transforms.fill(T::ZERO);
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGadgetEncryptContext<T> {}

impl<T> FourierGlweSecretKey<T>
where
    T: FheUint + TorusFftValue,
{
    /// Generates a Fourier GLev encryption of an already encoded torus polynomial.
    pub fn encrypt_glev_to<Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierGlevCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &Table,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        self.assert_gadget_shapes(message.as_ref().len(), params, fft);
        assert_eq!(result.as_ref().len(), params.fourier_glev_len());
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());

        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_glwe_mut(params.fourier_glwe_len()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, NativeModulus::new());
            self.encrypt_encoded_to(
                &context.encoded,
                &mut glwe,
                params.glwe_params(),
                fft,
                rng,
                &mut context.glwe,
            );
        }
    }

    /// Generates a Fourier GGSW encryption of an already encoded torus polynomial.
    pub fn encrypt_ggsw_to<Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &Table,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        self.assert_gadget_shapes(message.as_ref().len(), params, fft);
        assert_eq!(result.as_ref().len(), params.fourier_ggsw_len());

        let fourier_length = fft.fourier_length();
        assert_eq!(
            context.level_transforms.len(),
            params.basis().decompose_length() * fourier_length
        );
        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(fourier_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, NativeModulus::new());
            fft.forward_as_torus(context.encoded.as_ref(), transformed);
        }

        for (row, mut glev) in result.iter_glev_mut(params.fourier_glev_len()).enumerate() {
            for (transformed, mut glwe) in context
                .level_transforms
                .chunks_exact(fourier_length)
                .zip(glev.iter_glwe_mut(params.fourier_glwe_len()))
            {
                self.encrypt_zeros_to(&mut glwe, params.glwe_params(), fft, rng, &mut context.glwe);
                let diagonal = glwe
                    .as_mut()
                    .chunks_exact_mut(fourier_length)
                    .nth(row)
                    .expect("GGSW diagonal component is missing");
                FourierPolynomial::new(diagonal).add_assign(&FourierPolynomial::new(transformed));
            }
        }
    }

    fn assert_gadget_shapes<Table: FftTable>(
        &self,
        message_len: usize,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &Table,
    ) {
        assert_eq!(params.dimension(), self.dimension());
        assert_eq!(params.poly_length(), self.poly_length());
        assert_eq!(params.secret_key_type(), self.distr());
        assert_eq!(fft.poly_length(), self.poly_length());
        assert_eq!(message_len, self.poly_length());
    }
}

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Generates an NTT GLev encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_glev_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttGlevCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.assert_gadget_shapes(message.as_ref().len(), params, ntt);
        assert_eq!(result.as_ref().len(), params.glev_len());
        assert_eq!(context.encoded.as_ref().len(), self.poly_length());

        let modulus = params.cipher_modulus();
        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_glwe_mut(params.glwe_len()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_encoded_to(&context.encoded, &mut glwe, params.glwe_params(), ntt, rng);
        }
    }

    /// Generates an NTT GGSW encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_ggsw_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttGgswCiphertext<B>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.assert_gadget_shapes(message.as_ref().len(), params, ntt);
        assert_eq!(result.as_ref().len(), params.ggsw_len());

        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();
        assert_eq!(
            context.level_transforms.len(),
            params.basis().decompose_length() * poly_length
        );
        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            transformed.copy_from_slice(context.encoded.as_ref());
            ntt.transform_slice(transformed);
        }

        for (row, mut glev) in result.iter_ntt_glev_mut(params.glev_len()).enumerate() {
            for (transformed, mut glwe) in context
                .level_transforms
                .chunks_exact(poly_length)
                .zip(glev.iter_ntt_glwe_mut(params.glwe_len()))
            {
                self.encrypt_zeros_to(&mut glwe, params.glwe_params(), ntt, rng);
                let diagonal = glwe
                    .as_mut()
                    .chunks_exact_mut(poly_length)
                    .nth(row)
                    .expect("GGSW diagonal component is missing");
                NttPolynomial::new(diagonal).add_assign(&NttPolynomial::new(transformed), modulus);
            }
        }
    }

    fn assert_gadget_shapes<M, Table>(
        &self,
        message_len: usize,
        params: &GlevParameters<T, M>,
        ntt: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(params.dimension(), self.dimension());
        assert_eq!(params.poly_length(), self.poly_length());
        assert_eq!(params.secret_key_type(), self.distr());
        assert_eq!(ntt.poly_length(), self.poly_length());
        assert_eq!(message_len, self.poly_length());
    }
}
