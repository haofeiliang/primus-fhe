//! Native-torus Fourier-domain GLWE secret key with encryption and decryption.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::{GlweSize, MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomialIter, FourierPolynomialOwned, Polynomial, PolynomialOwned};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    FourierGlweCiphertext, GlevParameters, GlweParameters, GlweParametersInner, PlaintextCodec,
    PlaintextEmbedding, RingSecretKeyType,
};

use super::GlweSecretKey;

/// A native-torus GLWE secret key represented in the Fourier domain.
///
/// Each coefficient-domain secret polynomial is transformed with
/// [`FftTable::forward_as_integer`]. Ciphertext polynomials use torus-scaled
/// Fourier values instead, so their pointwise product has the correct torus
/// scale.
#[derive(Clone)]
pub struct FourierGlweSecretKey {
    key: Vec<Complex64>,
    size: GlweSize,
    distr: RingSecretKeyType,
}

impl Zeroize for FourierGlweSecretKey {
    #[inline]
    fn zeroize(&mut self) {
        self.key.fill(Complex64::default());
    }
}

impl ZeroizeOnDrop for FourierGlweSecretKey {}

impl FourierGlweSecretKey {
    /// Creates a Fourier-domain GLWE secret key from its raw Fourier values.
    #[inline]
    pub fn new(key: Vec<Complex64>, size: GlweSize, distr: RingSecretKeyType) -> Self {
        assert_eq!(key.len(), size.fourier_mask_len());
        Self { key, size, distr }
    }

    /// Returns the coefficient-domain GLWE layout.
    #[inline]
    pub fn glwe_size(&self) -> GlweSize {
        self.size
    }

    /// Returns the coefficient polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.poly_length()
    }

    /// Returns the GLWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.size.dimension()
    }

    /// Returns the secret-key distribution.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Iterates over the Fourier-domain secret polynomials.
    #[inline]
    pub fn iter(&self) -> FourierPolynomialIter<'_> {
        FourierPolynomialIter::new(&self.key, self.size.fourier_poly_len())
    }

    /// Converts a native coefficient-domain secret key to Fourier form.
    pub fn from_coeff_secret_key<T, Table>(
        secret_key: &GlweSecretKey<T>,
        fft: &mut FftEngine<'_, Table>,
    ) -> Self
    where
        T: TorusFftValue,
        Table: FftTable,
    {
        let size = secret_key.glwe_size();
        assert_eq!(size.poly_length(), fft.poly_length());

        let fourier_length = fft.fourier_length();
        let mut key = vec![Complex64::default(); size.fourier_mask_len()];
        let mut native_coefficients = vec![T::ZERO; size.poly_length()];
        for (coefficients, fourier) in secret_key.iter().zip(key.chunks_exact_mut(fourier_length)) {
            native_coefficients
                .iter_mut()
                .zip(coefficients)
                .for_each(|(output, &coefficient)| {
                    *output = T::cast_from_signed(coefficient);
                });
            fft.forward_as_integer(&native_coefficients, fourier);
        }

        Self::new(key, size, secret_key.distr)
    }

    /// Generates a native-torus coefficient key and converts it to Fourier form.
    #[inline]
    pub fn generate<T, R, Table>(
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

    /// Encrypts a polynomial into a native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_to<T, Table, R, A, B>(
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
            FourierEncryptionMessage::Plaintext {
                values: msg.as_ref(),
                embedding: PlaintextEmbedding::Unsigned,
                codec: params.plaintext_codec(),
            },
            result,
            FourierEncryptionParameters::glwe(params),
            fft,
            rng,
            context,
        );
    }

    /// Encrypts a polynomial using centered plaintext embedding.
    pub fn encrypt_centered_to<T, Table, R, A, B>(
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
            FourierEncryptionMessage::Plaintext {
                values: msg.as_ref(),
                embedding: PlaintextEmbedding::Centered,
                codec: params.plaintext_codec(),
            },
            result,
            FourierEncryptionParameters::glwe(params),
            fft,
            rng,
            context,
        );
    }

    /// Encrypts a polynomial whose coefficients are already encoded in the
    /// native torus ciphertext space.
    pub fn encrypt_encoded_to<T, Table, R, A, B>(
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
            FourierEncryptionParameters::glwe(params),
            fft,
            rng,
            context,
        );
    }

    /// Encrypts zero into a native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_zeros<T, Table, R>(
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
        let mut result = FourierGlweCiphertext::zero(self.size.fourier_glwe_len());
        self.encrypt_zeros_to(&mut result, params, fft, rng, context);
        result
    }

    /// Encrypts zero into an existing native-torus Fourier-domain GLWE ciphertext.
    pub fn encrypt_zeros_to<T, Table, R, B>(
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
            FourierEncryptionParameters::glwe(params),
            fft,
            rng,
            context,
        );
    }

    pub(crate) fn encrypt_gadget_encoded_to<T, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
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
            FourierEncryptionParameters::gadget(params),
            fft,
            rng,
            context,
        );
    }

    pub(crate) fn encrypt_gadget_zeros_to<T, Table, R, B>(
        &self,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlevParameters<T, NativeModulus<T>>,
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
            FourierEncryptionParameters::gadget(params),
            fft,
            rng,
            context,
        );
    }

    fn encrypt_to_with_message<T, Table, R, B>(
        &self,
        message: FourierEncryptionMessage<'_, T>,
        result: &mut FourierGlweCiphertext<B>,
        params: FourierEncryptionParameters<'_, T>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGlweEncryptContext<T>,
    ) where
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        let poly_length = self.size.poly_length();
        if let Some(message) = message.as_slice() {
            assert_eq!(message.len(), poly_length);
        }

        let fourier_length = fft.fourier_length();
        let (mask, mut body) = result.a_b_mut(fourier_length);

        let coeff = context.coeff.as_mut();
        assert_eq!(coeff.len(), poly_length);
        primus_distr::sample_gaussian_values_to(coeff, params.inner.noise_distribution(), rng);
        match message {
            FourierEncryptionMessage::Zero => {}
            FourierEncryptionMessage::Plaintext {
                values,
                embedding,
                codec,
            } => {
                codec.add_encode_slice_assign_with_delta(coeff, values, embedding);
            }
            FourierEncryptionMessage::Encoded(encoded) => {
                Polynomial::new(&mut *coeff)
                    .add_assign(&Polynomial::new(encoded), NativeModulus::new());
            }
        }
        fft.forward_as_torus(coeff, body.as_mut());

        let uniform = params.inner.cipher_modulus_uniform_distr();

        for (mut ai, si) in mask.zip(self.iter()) {
            primus_distr::sample_uniform_values_to(coeff, &uniform, rng);
            fft.forward_as_torus(coeff, ai.as_mut_slice());
            body.add_mul_assign(&ai, &si);
        }
    }

    /// Computes `b - sum(a_i * s_i)` and writes the encoded torus phase in
    /// coefficient form.
    pub fn phase_to<T, Table, A, B>(
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
        assert_eq!(result.as_ref().len(), self.size.poly_length());

        let fourier_length = fft.fourier_length();
        let (mut mask, body) = cipher.a_b(fourier_length);

        assert_eq!(context.phase.fourier_length(), fourier_length);
        let phase = &mut context.phase;

        let mut secret = self.iter();
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = mask.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, phase);

        for (si, ai) in secret.zip(mask) {
            phase.add_mul_assign(&ai, &si);
        }

        body.sub_rev_assign(phase);

        fft.backward_as_torus(phase.as_ref(), result.as_mut());
    }

    /// Decrypts a native-torus Fourier-domain GLWE ciphertext.
    pub fn decrypt<T, Table, A>(
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
        let mut result = PolynomialOwned::zero(self.size.poly_length());
        self.decrypt_to(cipher, &mut result, params, fft, context);
        result
    }

    /// Decrypts into an existing plaintext polynomial.
    pub fn decrypt_to<T, Table, A, B>(
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
        self.phase_to(cipher, result, fft, context);
        params
            .plaintext_codec()
            .decode_slice_inplace(result.as_mut());
    }
}

enum FourierEncryptionMessage<'a, T: FheUint> {
    Zero,
    Plaintext {
        values: &'a [T],
        embedding: PlaintextEmbedding,
        codec: &'a PlaintextCodec<T>,
    },
    Encoded(&'a [T]),
}

struct FourierEncryptionParameters<'a, T: FheUint> {
    inner: &'a GlweParametersInner<T, NativeModulus<T>>,
}

impl<'a, T: FheUint> FourierEncryptionParameters<'a, T> {
    fn glwe(params: &'a GlweParameters<T, NativeModulus<T>>) -> Self {
        Self {
            inner: params.inner(),
        }
    }

    fn gadget(params: &'a GlevParameters<T, NativeModulus<T>>) -> Self {
        Self {
            inner: params.inner(),
        }
    }
}

impl<'a, T: FheUint> FourierEncryptionMessage<'a, T> {
    #[inline]
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext { values, .. } | Self::Encoded(values) => Some(values),
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
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }

    pub(crate) fn resize(&mut self, poly_length: usize) {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        self.coeff.0.resize(poly_length, T::ZERO);
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
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
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
