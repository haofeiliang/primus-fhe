//! Single-modulus NTT-domain GLWE secret key with encryption and decryption.

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{GlweParameters, NttGlweCiphertext, PlaintextEmbedding, RingSecretKeyType};

use super::GlweSecretKey;

/// Represents a secret key for the (NTT) Module Learning with Errors (MLWE)
/// cryptographic scheme.
#[derive(Clone)]
pub struct NttGlweSecretKey<T: FheUint> {
    key: Vec<T>,
    poly_length: usize,
    dimension: usize,
    distr: RingSecretKeyType,
}

impl<T: FheUint> Zeroize for NttGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttGlweSecretKey<T> {}

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Creates a new [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn new(
        key: Vec<T>,
        poly_length: usize,
        dimension: usize,
        distr: RingSecretKeyType,
    ) -> Self {
        debug_assert!(poly_length.is_power_of_two());
        debug_assert_eq!(key.len(), poly_length * dimension);
        Self {
            key,
            poly_length,
            dimension,
            distr,
        }
    }

    /// Returns the poly length of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the dimension of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the distr of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    #[inline]
    pub fn iter(&self) -> NttPolynomialIter<'_, T> {
        NttPolynomialIter::new(self.key.as_ref(), self.poly_length)
    }

    /// Creates a new [`NttGlweSecretKey`] from [`GlweSecretKey`].
    #[inline]
    pub fn from_coeff_secret_key<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let poly_length = secret_key.poly_length;

        let mut key = secret_key.key.clone();
        key.chunks_exact_mut(poly_length)
            .for_each(|poly| ntt_table.transform_slice(poly));

        Self {
            key,
            poly_length,
            dimension: secret_key.dimension,
            distr: secret_key.distr,
        }
    }

    /// Generates a new [`NttGlweSecretKey<T>`] from parameters.
    #[inline]
    pub fn generate<R, M>(
        params: &GlweParameters<T, M>,
        ntt_table: &impl NttTable<ValueT = T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let coeff_sk = GlweSecretKey::generate(params, rng);
        Self::from_coeff_secret_key(&coeff_sk, ntt_table)
    }

    /// Performs `b - ∑ a_i * s_i` (phase), leaving result in coefficient domain.
    pub fn phase_inplace<Table, M, S>(
        &self,
        cipher: &NttGlweCiphertext<S>,
        result: &mut PolynomialOwned<T>,
        ntt_table: &Table,
        modulus: M,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
    {
        let mid = self.poly_length * self.dimension;
        let (a, b) = cipher.a_b(mid);

        result.set_zero();
        let mut result_poly = NttPolynomial(result.as_mut());

        self.iter().zip(a).for_each(|(si, ai)| {
            result_poly.add_mul_assign(&ai, &si, modulus);
        });
        b.sub_rev_assign(&mut result_poly, modulus);

        ntt_table.inverse_transform_slice(result.as_mut())
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts a polynomial message into an NTT-domain GLWE ciphertext.
    pub fn encrypt_inplace<M, Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.encrypt_inplace_with_embedding(
            msg,
            result,
            params,
            ntt_table,
            rng,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Encrypts a polynomial using centered plaintext embedding.
    pub fn encrypt_centered_inplace<M, Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.encrypt_inplace_with_embedding(
            msg,
            result,
            params,
            ntt_table,
            rng,
            PlaintextEmbedding::Centered,
        )
    }

    /// Encrypts a polynomial using the selected plaintext embedding.
    pub fn encrypt_inplace_with_embedding<M, Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let modulus = params.cipher_modulus();
        let mid = self.dimension * poly_length;

        let (a, b) = result.as_mut().split_at_mut(mid);

        // Sample noise into b
        primus_distr::sample_gaussian_values_to(b, params.noise_distribution(), rng);

        // Add message with delta scaling
        match embedding {
            PlaintextEmbedding::Unsigned => {
                Polynomial(&mut *b).add_mul_factor_assign(
                    msg,
                    params.delta_factor(),
                    params.cipher_modulus_value(),
                );
            }
            PlaintextEmbedding::Centered => {
                params.plaintext_codec().add_encode_slice_assign_with_delta(
                    b,
                    msg.as_ref(),
                    embedding,
                );
            }
        }
        ntt_table.transform_slice(b);

        // Sample uniform a_i
        primus_distr::sample_uniform_values_to(a, &params.cipher_modulus_uniform_distr(), rng);

        // b += sum a_i * s_i (pointwise in NTT domain)
        let mut b_ntt = NttPolynomial(b);
        for (si, ai) in self.iter().zip(a.chunks_exact(poly_length)) {
            b_ntt.add_mul_assign(&NttPolynomial(ai), &si, modulus);
        }
    }

    /// Encrypts zeros (randomized encryption of zero).
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let len = (self.dimension + 1) * self.poly_length;
        let mut result: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(len);
        self.encrypt_zeros_inplace(&mut result, params, ntt_table, rng);
        result
    }

    /// Encrypts zeros in-place.
    pub fn encrypt_zeros_inplace<M, Table, R, A>(
        &self,
        result: &mut NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let modulus = params.cipher_modulus();
        let mid = self.dimension * poly_length;

        let (a, b) = result.as_mut().split_at_mut(mid);

        primus_distr::sample_gaussian_values_to(b, params.noise_distribution(), rng);
        ntt_table.transform_slice(b);

        primus_distr::sample_uniform_values_to(a, &params.cipher_modulus_uniform_distr(), rng);

        let mut b_ntt = NttPolynomial(b);
        for (si, ai) in self.iter().zip(a.chunks_exact(poly_length)) {
            b_ntt.add_mul_assign(&NttPolynomial(ai), &si, modulus);
        }
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------

    pub fn decrypt<M, Table, A>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let mut result = PolynomialOwned::zero(self.poly_length);
        self.decrypt_inplace(cipher, &mut result, params, ntt_table);
        result
    }

    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let modulus = params.cipher_modulus();
        let mid = self.dimension * self.poly_length;
        let (a, b) = cipher.a_b_slices(mid);

        let mut temp = NttPolynomial(result.as_mut());

        for (si, ai) in self.iter().zip(a.chunks_exact(self.poly_length)) {
            temp.add_mul_assign(&NttPolynomial(ai), &si, modulus);
        }
        NttPolynomial(b).sub_rev_assign(&mut temp, modulus);

        ntt_table.inverse_transform_slice(result.as_mut());

        params
            .plaintext_codec()
            .decode_slice_inplace(result.as_mut());
    }
}
