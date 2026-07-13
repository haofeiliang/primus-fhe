//! Fourier-domain GLWE secret key for TFHE-style encryption.
//!
//! Encryption is performed in coefficient domain and then converted to
//! Fourier domain for use in the TFHE external product.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    FourierGlweCiphertext, GlweParameters, NttGlweCiphertext, PlaintextEmbedding, RingSecretKeyType,
};

use super::GlweSecretKey;

/// Fourier-domain GLWE secret key for TFHE operations.
///
/// Wraps a coefficient-domain [`GlweSecretKey`]. Encryption is performed
/// in coefficient form and the result is FFT-converted to Fourier domain.
#[derive(Clone)]
pub struct FourierGlweSecretKey<T: FheUint> {
    inner: GlweSecretKey<T>,
}

impl<T: FheUint> Zeroize for FourierGlweSecretKey<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweSecretKey<T> {}

impl<T: FheUint> FourierGlweSecretKey<T> {
    /// Creates a [`FourierGlweSecretKey`] from a coefficient-domain secret key.
    #[inline]
    pub fn new(inner: GlweSecretKey<T>) -> Self {
        Self { inner }
    }

    /// Returns the inner coefficient-domain secret key.
    #[inline]
    pub fn inner(&self) -> &GlweSecretKey<T> {
        &self.inner
    }

    /// Returns the dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.inner.dimension
    }

    /// Returns the polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.inner.poly_length
    }

    /// Returns the distribution.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.inner.distr
    }

    /// Generates a new [`FourierGlweSecretKey<T>`] from parameters.
    #[inline]
    pub fn generate<R, M>(params: &GlweParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        Self {
            inner: GlweSecretKey::generate(params, rng),
        }
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts a polynomial message into a Fourier-domain GLWE ciphertext.
    ///
    /// Encryption is performed in coefficient domain using NTT arithmetic,
    /// then the result is FFT-converted to Fourier domain.
    pub fn encrypt_inplace<M, NttTableT, FftTableT, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &NttTableT,
        fft_table: &FftTableT,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        NttTableT: NttTable<ValueT = T>,
        FftTableT: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_inplace_with_embedding(
            msg,
            result,
            params,
            ntt_table,
            fft_table,
            rng,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Encrypts using centered plaintext embedding.
    pub fn encrypt_centered_inplace<M, NttTableT, FftTableT, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &NttTableT,
        fft_table: &FftTableT,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        NttTableT: NttTable<ValueT = T>,
        FftTableT: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        self.encrypt_inplace_with_embedding(
            msg,
            result,
            params,
            ntt_table,
            fft_table,
            rng,
            PlaintextEmbedding::Centered,
        )
    }

    /// Encrypts using the selected plaintext embedding, then FFT-converts.
    fn encrypt_inplace_with_embedding<M, NttTableT, FftTableT, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &NttTableT,
        fft_table: &FftTableT,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        M: FieldContext<T>,
        NttTableT: NttTable<ValueT = T>,
        FftTableT: FftTable,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        use primus_lattice::glwe::Glwe;

        let ntt_sk = super::NttGlweSecretKey::from_coeff_secret_key(&self.inner, ntt_table);

        let glwe_len = (self.inner.dimension + 1) * self.inner.poly_length;
        let mut ntt_ct: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(glwe_len);

        ntt_sk.encrypt_inplace_with_embedding(msg, &mut ntt_ct, params, ntt_table, rng, embedding);

        // INTT: NTT domain → coefficient domain
        let mut coeff_ct: Glwe<Vec<T>> = Glwe::zero(glwe_len);
        ntt_ct.write_coeff_form(&mut coeff_ct, ntt_table);

        // FFT: coefficient domain → Fourier domain
        coeff_ct.write_fourier_form(result, fft_table);
    }

    /// Encrypts zeros into a Fourier-domain ciphertext.
    pub fn encrypt_zeros_inplace<M, NttTableT, FftTableT, R, B>(
        &self,
        result: &mut FourierGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &NttTableT,
        fft_table: &FftTableT,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        NttTableT: NttTable<ValueT = T>,
        FftTableT: FftTable,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = Complex64> + DataMut,
        T: TorusFftValue,
    {
        use primus_lattice::glwe::Glwe;

        let ntt_sk = super::NttGlweSecretKey::from_coeff_secret_key(&self.inner, ntt_table);

        let glwe_len = (self.inner.dimension + 1) * self.inner.poly_length;
        let mut ntt_ct: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(glwe_len);

        ntt_sk.encrypt_zeros_inplace(&mut ntt_ct, params, ntt_table, rng);

        let mut coeff_ct: Glwe<Vec<T>> = Glwe::zero(glwe_len);
        ntt_ct.write_coeff_form(&mut coeff_ct, ntt_table);

        coeff_ct.write_fourier_form(result, fft_table);
    }
}
