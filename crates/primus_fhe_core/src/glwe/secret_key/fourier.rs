//! Native-torus Fourier-domain GLWE secret key with encryption and decryption.

use core::marker::PhantomData;

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_poly::{
    FourierPolynomial, FourierPolynomialIter, FourierPolynomialOwned, Polynomial, PolynomialOwned,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FourierGlweCiphertext, GlweParameters, PlaintextEmbedding, RingSecretKeyType};

use super::GlweSecretKey;

/// A native-torus GLWE secret key represented in the Fourier domain.
///
/// Each coefficient-domain secret polynomial is transformed with
/// [`FftTable::forward_as_integer`]. Ciphertext polynomials use torus-scaled
/// Fourier values instead, so their pointwise product has the correct torus
/// scale.
#[derive(Clone)]
pub struct FourierGlweSecretKey<T: FheUint> {
    key: Vec<Complex64>,
    poly_length: usize,
    dimension: usize,
    distr: RingSecretKeyType,
    value_type: PhantomData<T>,
}

impl<T: FheUint> Zeroize for FourierGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.fill(Complex64::default());
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweSecretKey<T> {}

impl<T: FheUint> FourierGlweSecretKey<T> {
    /// Creates a Fourier-domain GLWE secret key from its raw Fourier values.
    #[inline]
    pub fn new(
        key: Vec<Complex64>,
        poly_length: usize,
        dimension: usize,
        distr: RingSecretKeyType,
    ) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        assert!(dimension > 0);
        assert_eq!(key.len(), dimension * (poly_length / 2));
        Self {
            key,
            poly_length,
            dimension,
            distr,
            value_type: PhantomData,
        }
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the GLWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the secret-key distribution.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Iterates over the Fourier-domain secret polynomials.
    #[inline]
    pub fn iter(&self) -> FourierPolynomialIter<'_> {
        FourierPolynomialIter::new(&self.key, self.poly_length / 2)
    }

    /// Converts a native coefficient-domain secret key to Fourier form.
    pub fn from_coeff_secret_key<Table>(
        secret_key: &GlweSecretKey<T>,
        fft: &mut FftEngine<'_, Table>,
    ) -> Self
    where
        Table: FftTable,
        T: TorusFftValue,
    {
        assert_eq!(secret_key.poly_length, fft.poly_length());

        let fourier_length = fft.fourier_length();
        let mut key = vec![Complex64::default(); secret_key.dimension * fourier_length];
        for (coeff, fourier) in secret_key
            .key
            .chunks_exact(secret_key.poly_length)
            .zip(key.chunks_exact_mut(fourier_length))
        {
            fft.forward_as_integer(coeff, fourier);
        }

        Self::new(
            key,
            secret_key.poly_length,
            secret_key.dimension,
            secret_key.distr,
        )
    }

    /// Generates a native-torus coefficient key and converts it to Fourier form.
    #[inline]
    pub fn generate<R, Table>(
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        Table: FftTable,
        T: TorusFftValue,
    {
        let coeff_sk = GlweSecretKey::generate(params, rng);
        Self::from_coeff_secret_key(&coeff_sk, fft)
    }

    /// Computes `b - sum(a_i * s_i)` and writes the encoded torus phase in
    /// coefficient form.
    pub fn phase_to<Table, A, B>(
        &self,
        cipher: &FourierGlweCiphertext<A>,
        result: &mut Polynomial<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweDecryptContext,
    ) where
        Table: FftTable,
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        self.assert_fft_and_cipher_shape(cipher.as_ref().len(), fft);
        assert_eq!(result.as_ref().len(), self.poly_length);

        let fourier_length = fft.fourier_length();
        let mid = self.dimension * fourier_length;
        let (a, b) = cipher.a_b_slices(mid);
        assert_eq!(context.phase.fourier_length(), fourier_length);
        let phase = &mut context.phase;
        let mut secret = self.iter();
        let mut mask = a.chunks_exact(fourier_length);
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = mask.next().expect("GLWE ciphertext mask is missing");
        FourierPolynomial::new(ai).mul_to(&si, phase);
        for (si, ai) in secret.zip(mask) {
            phase.add_mul_assign(&FourierPolynomial::new(ai), &si);
        }
        FourierPolynomial::new(b).sub_rev_assign(phase);
        fft.backward_as_torus(phase.as_ref(), result.as_mut());
    }

    /// Encrypts a polynomial into a native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_to<Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Plaintext(msg.as_ref(), PlaintextEmbedding::Unsigned),
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    /// Encrypts a polynomial using centered plaintext embedding.
    pub fn encrypt_centered_to<Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Plaintext(msg.as_ref(), PlaintextEmbedding::Centered),
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    /// Encrypts a polynomial whose coefficients are already encoded in the
    /// native torus ciphertext space.
    pub fn encrypt_encoded_to<Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Encoded(encoded.as_ref()),
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    fn encrypt_to_with_message<Table, R, B>(
        &self,
        message: FourierEncryptionMessage<'_, T>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.assert_parameter_shape(params);
        self.assert_fft_and_cipher_shape(result.as_ref().len(), fft);
        if let Some(message) = message.as_slice() {
            assert_eq!(message.len(), self.poly_length);
        }

        let fourier_length = fft.fourier_length();
        let mid = self.dimension * fourier_length;
        let (a, b) = result.a_b_mut_slices(mid);

        let coeff = context.coeff.as_mut();
        assert_eq!(coeff.len(), self.poly_length);
        primus_distr::sample_gaussian_values_to(coeff, params.noise_distribution(), rng);
        match message {
            FourierEncryptionMessage::Zero => {}
            FourierEncryptionMessage::Plaintext(message, embedding) => {
                params
                    .plaintext_codec()
                    .add_encode_slice_assign_with_delta(coeff, message, embedding);
            }
            FourierEncryptionMessage::Encoded(encoded) => {
                Polynomial::new(&mut *coeff)
                    .add_assign(&Polynomial::new(encoded), NativeModulus::new());
            }
        }
        fft.forward_as_torus(coeff, b);

        let uniform = params.cipher_modulus_uniform_distr();
        let mut b_poly = FourierPolynomial::new(b);
        for (mut ai, si) in a
            .chunks_exact_mut(fourier_length)
            .map(FourierPolynomial::new)
            .zip(self.iter())
        {
            primus_distr::sample_uniform_values_to(coeff, &uniform, rng);
            fft.forward_as_torus(coeff, ai.as_mut_slice());
            b_poly.add_mul_assign(&ai, &si);
        }
    }

    /// Encrypts zero into a native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_zeros<Table, R>(
        &self,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) -> FourierGlweCiphertext<Vec<Complex64>>
    where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        T: TorusFftValue,
    {
        let mut result = FourierGlweCiphertext::zero((self.dimension + 1) * fft.fourier_length());
        self.encrypt_zeros_to(&mut result, params, fft, rng, context);
        result
    }

    /// Encrypts zero into an existing native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_zeros_to<Table, R, B>(
        &self,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_to_with_message(
            FourierEncryptionMessage::Zero,
            result,
            params,
            fft,
            rng,
            context,
        );
    }

    /// Decrypts a native-torus Fourier-domain GLWE ciphertext.
    pub fn decrypt<Table, A>(
        &self,
        cipher: &FourierGlweCiphertext<A>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweDecryptContext,
    ) -> PolynomialOwned<T>
    where
        Table: FftTable,
        A: RawData<Elem = Complex64> + Data,
        T: TorusFftValue,
    {
        let mut result = PolynomialOwned::zero(self.poly_length);
        self.decrypt_to(cipher, &mut result, params, fft, context);
        result
    }

    /// Decrypts into an existing plaintext polynomial.
    pub fn decrypt_to<Table, A, B>(
        &self,
        cipher: &FourierGlweCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &GlweParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweDecryptContext,
    ) where
        Table: FftTable,
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        self.assert_parameter_shape(params);
        self.phase_to(cipher, result, fft, context);
        params
            .plaintext_codec()
            .decode_slice_inplace(result.as_mut());
    }

    #[inline]
    fn assert_parameter_shape(&self, params: &GlweParameters<T, NativeModulus<T>>) {
        assert_eq!(params.poly_length(), self.poly_length);
        assert_eq!(params.dimension(), self.dimension);
        assert_eq!(params.secret_key_type(), self.distr);
    }

    #[inline]
    fn assert_fft_and_cipher_shape<Table: FftTable>(
        &self,
        cipher_len: usize,
        fft: &FftEngine<'_, Table>,
    ) {
        assert_eq!(fft.poly_length(), self.poly_length);
        assert_eq!(cipher_len, (self.dimension + 1) * fft.fourier_length());
    }
}

enum FourierEncryptionMessage<'a, T> {
    Zero,
    Plaintext(&'a [T], PlaintextEmbedding),
    Encoded(&'a [T]),
}

impl<'a, T> FourierEncryptionMessage<'a, T> {
    #[inline]
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext(message, _) | Self::Encoded(message) => Some(message),
        }
    }
}

/// Reusable coefficient-domain workspace for Fourier GLWE encryption.
pub struct FourierGlweEncryptContext<T: FheUint> {
    coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierGlweEncryptContext<T> {
    /// Creates an encryption workspace for coefficient polynomials of length `poly_length`.
    #[inline]
    pub fn new(poly_length: usize) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierGlweEncryptContext<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.coeff.as_mut().fill(T::ZERO);
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweEncryptContext<T> {}

/// Reusable Fourier-domain workspace for Fourier GLWE decryption.
pub struct FourierGlweDecryptContext {
    phase: FourierPolynomialOwned,
}

impl FourierGlweDecryptContext {
    /// Creates a decryption workspace for coefficient polynomials of length `poly_length`.
    #[inline]
    pub fn new(poly_length: usize) -> Self {
        assert!(poly_length.is_power_of_two());
        assert!(poly_length >= 2);
        Self {
            phase: FourierPolynomialOwned::zero(poly_length / 2),
        }
    }
}

impl Zeroize for FourierGlweDecryptContext {
    #[inline]
    fn zeroize(&mut self) {
        self.phase.as_mut().fill(Complex64::default());
    }
}

impl ZeroizeOnDrop for FourierGlweDecryptContext {}
