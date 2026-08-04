//! Single-modulus GLev and GGSW generation with GLWE secret keys.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    FourierGgswCiphertext, FourierGlevCiphertext, GlevParameters, NttGadgetDomain,
    NttGgswCiphertext, NttGlevCiphertext,
};
use primus_lattice::GadgetSize;

use super::{FourierGlweEncryptContext, FourierGlweSecretKey, NttGlweSecretKey};

/// Reusable workspace for Fourier GLev/GGSW generation.
pub struct FourierGadgetEncryptContext<T: FheUint> {
    size: GadgetSize,
    encoded: PolynomialOwned<T>,
    level_transforms: Vec<Complex64>,
    glwe: FourierGlweEncryptContext<T>,
}

impl<T: FheUint> FourierGadgetEncryptContext<T> {
    /// Creates reusable workspace for a checked gadget layout.
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();
        let decompose_length = size.decompose_length();
        Self {
            size,
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![
                Complex64::default();
                decompose_length * glwe_size.fourier_poly_len()
            ],
            glwe: FourierGlweEncryptContext::new(poly_length),
        }
    }

    /// Returns the gadget layout bound to this workspace.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Rebinds this workspace to another checked gadget layout.
    pub fn resize(&mut self, size: GadgetSize) {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();
        self.size = size;
        self.encoded.0.resize(poly_length, T::ZERO);
        self.level_transforms.resize(
            size.decompose_length() * glwe_size.fourier_poly_len(),
            Complex64::default(),
        );
        self.glwe.resize(poly_length);
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
    size: GadgetSize,
    encoded: PolynomialOwned<T>,
    level_transforms: Vec<T>,
}

impl<T: FheUint> NttGadgetEncryptContext<T> {
    /// Creates reusable workspace for a checked gadget layout.
    pub fn new(size: GadgetSize) -> Self {
        let poly_length = size.glwe_size().poly_length();
        let decompose_length = size.decompose_length();
        Self {
            size,
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![T::ZERO; decompose_length * poly_length],
        }
    }

    /// Returns the gadget layout bound to this workspace.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Rebinds this workspace to another checked gadget layout.
    pub fn resize(&mut self, size: GadgetSize) {
        let poly_length = size.glwe_size().poly_length();
        self.size = size;
        self.encoded.0.resize(poly_length, T::ZERO);
        self.level_transforms
            .resize(size.decompose_length() * poly_length, T::ZERO);
    }
}

impl<T: FheUint> Zeroize for NttGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().fill(T::ZERO);
        self.level_transforms.fill(T::ZERO);
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGadgetEncryptContext<T> {}

impl FourierGlweSecretKey {
    /// Generates a Fourier GLev encryption of an already encoded torus polynomial.
    pub fn encrypt_glev_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierGlevCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        assert_eq!(result.as_ref().len(), params.fourier_glev_len());
        assert_eq!(context.size(), params.size());
        let modulus = params.cipher_modulus();
        let fourier_glwe_len = params.fourier_glwe_len();

        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_glwe_mut(fourier_glwe_len))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_gadget_encoded_to(
                &context.encoded,
                &mut glwe,
                params,
                fft,
                rng,
                &mut context.glwe,
            );
        }
    }

    /// Generates a Fourier GGSW encryption of an already encoded torus polynomial.
    pub fn encrypt_ggsw_to<T, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut FourierGgswCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
    {
        assert_eq!(result.as_ref().len(), params.fourier_ggsw_len());
        assert_eq!(context.size(), params.size());

        let fourier_length = fft.fourier_length();
        let fourier_glwe_len = params.fourier_glwe_len();
        let fourier_glev_len = params.fourier_glev_len();
        let modulus = params.cipher_modulus();
        assert_eq!(
            context.size().glwe_size().fourier_poly_len(),
            fourier_length
        );

        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(fourier_length))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            fft.forward_as_torus(context.encoded.as_ref(), transformed);
        }

        for (row, mut glev) in result.iter_glev_mut(fourier_glev_len).enumerate() {
            for (transformed, mut glwe) in context
                .level_transforms
                .chunks_exact(fourier_length)
                .zip(glev.iter_glwe_mut(fourier_glwe_len))
            {
                self.encrypt_gadget_zeros_to(&mut glwe, params, fft, rng, &mut context.glwe);
                let diagonal = glwe
                    .as_mut()
                    .chunks_exact_mut(fourier_length)
                    .nth(row)
                    .expect("GGSW diagonal component is missing");
                FourierPolynomial::new(diagonal).add_assign(&FourierPolynomial::new(transformed));
            }
        }
    }
}

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Generates an NTT GLev encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_glev_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttGlevCiphertext<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let ntt = domain.table();
        assert_eq!(result.as_ref().len(), params.glev_len());
        assert_eq!(context.size(), domain.size());

        let modulus = params.cipher_modulus();
        for (scalar, mut glwe) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_glwe_mut(params.glwe_len()))
        {
            message.mul_scalar_to(scalar, &mut context.encoded, modulus);
            self.encrypt_gadget_encoded_to(&context.encoded, &mut glwe, params, ntt, rng);
        }
    }

    /// Generates an NTT GGSW encryption of a polynomial already encoded in `[0, q)`.
    pub fn encrypt_ggsw_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttGgswCiphertext<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let ntt = domain.table();
        assert_eq!(result.as_ref().len(), params.ggsw_len());
        assert_eq!(context.size(), domain.size());

        let poly_length = self.poly_length();
        let modulus = params.cipher_modulus();
        let glwe_len = params.glwe_len();

        for (scalar, transformed) in params
            .basis()
            .scalar_iter()
            .zip(context.level_transforms.chunks_exact_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut Polynomial(&mut *transformed), modulus);
            ntt.transform_slice(transformed);
        }

        for (row, mut glev) in result.iter_ntt_glev_mut(params.glev_len()).enumerate() {
            for (transformed, mut glwe) in context
                .level_transforms
                .chunks_exact(poly_length)
                .zip(glev.iter_ntt_glwe_mut(glwe_len))
            {
                self.encrypt_gadget_zeros_to(&mut glwe, params, ntt, rng);
                let diagonal = glwe
                    .as_mut()
                    .chunks_exact_mut(poly_length)
                    .nth(row)
                    .expect("GGSW diagonal component is missing");
                NttPolynomial::new(diagonal).add_assign(&NttPolynomial::new(transformed), modulus);
            }
        }
    }
}
