//! Single-modulus NTT-domain GLWE public-key encryption.

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{GlweParameters, NttGlweCiphertext, NttGlweSecretKey, PlaintextEmbedding};

/// A GLWE public key represented by one NTT-domain encryption of zero.
#[derive(Clone)]
pub struct NttGlwePublicKey<S>
where
    S: RawData,
    <S as RawData>::Elem: FheUint,
{
    key: NttGlweCiphertext<S>,
}

impl<S, T> AsRef<[T]> for NttGlwePublicKey<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.key.as_ref()
    }
}

impl<S, T> AsMut<[T]> for NttGlwePublicKey<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.key.as_mut()
    }
}

impl<S, T> From<NttGlweCiphertext<S>> for NttGlwePublicKey<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn from(key: NttGlweCiphertext<S>) -> Self {
        Self { key }
    }
}

impl<T: FheUint> NttGlwePublicKey<Vec<T>> {
    /// Generates a public key for `secret_key`.
    pub fn new<M, Table, R>(
        secret_key: &NttGlweSecretKey<T>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            key: secret_key.encrypt_zeros(params, ntt_table, rng),
        }
    }
}

impl<S, T> NttGlwePublicKey<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a public key from its native-endian byte representation.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            key: NttGlweCiphertext::from_bytes(data),
        }
    }
}

impl<S, T> NttGlwePublicKey<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Replaces this public key from its native-endian byte representation.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }
}

impl<S, T> NttGlwePublicKey<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Converts this public key to native-endian bytes.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    /// Writes this public key as native-endian bytes into `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the byte length of this public key.
    #[inline]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
    }

    /// Encrypts a polynomial message into `result`.
    pub fn encrypt_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
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
        self.encrypt_to_with_message(
            Some((message.as_ref(), PlaintextEmbedding::Unsigned)),
            result,
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts a polynomial using centered plaintext embedding into `result`.
    pub fn encrypt_centered_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
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
        self.encrypt_to_with_message(
            Some((message.as_ref(), PlaintextEmbedding::Centered)),
            result,
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts a polynomial into a newly allocated NTT-domain ciphertext.
    pub fn encrypt<M, Table, R, A>(
        &self,
        message: &Polynomial<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
    {
        let mut result = NttGlweCiphertext::zero(params.glwe_len());
        self.encrypt_to(message, &mut result, params, ntt_table, rng);
        result
    }

    /// Encrypts zero into `result`.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = T> + DataMut,
    {
        self.encrypt_to_with_message(None, result, params, ntt_table, rng);
    }

    /// Encrypts zero into a newly allocated NTT-domain ciphertext.
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
        let mut result = NttGlweCiphertext::zero(params.glwe_len());
        self.encrypt_zeros_to(&mut result, params, ntt_table, rng);
        result
    }

    fn encrypt_to_with_message<M, Table, R, B>(
        &self,
        message: Option<(&[T], PlaintextEmbedding)>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: RawData<Elem = T> + DataMut,
    {
        let size = params.size();
        let poly_length = size.poly_length();
        assert_eq!(self.key.as_ref().len(), size.glwe_len());
        assert_eq!(result.as_ref().len(), size.glwe_len());
        assert_eq!(ntt_table.poly_length(), poly_length);
        if let Some((message, _)) = message {
            assert_eq!(message.len(), poly_length);
        }

        let modulus = params.cipher_modulus();
        let mut ephemeral = vec![T::ZERO; poly_length];
        primus_distr::sample_sparse_ternary_values_to(
            &mut ephemeral,
            params.cipher_modulus_minus_one(),
            rng,
        );
        ntt_table.transform_slice(&mut ephemeral);
        let ephemeral = NttPolynomial(ephemeral.as_slice());

        let body_index = size.dimension();
        result
            .iter_ntt_poly_mut(poly_length)
            .zip(self.key.iter_ntt_poly(poly_length))
            .enumerate()
            .for_each(|(index, (mut output, public_key_component))| {
                primus_distr::sample_gaussian_values_to(
                    output.as_mut(),
                    params.noise_distribution(),
                    rng,
                );
                if index == body_index
                    && let Some((message, embedding)) = message
                {
                    params.plaintext_codec().add_encode_slice_assign_with_delta(
                        output.as_mut(),
                        message,
                        embedding,
                    );
                }
                ntt_table.transform_slice(output.as_mut());
                output.add_mul_assign(&public_key_component, &ephemeral, modulus);
            });
    }
}
