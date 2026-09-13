//! Ordinary encryption.

use super::NttNtruSecretKey;
use crate::{NtruParameters, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Allocates a ciphertext and delegates to [`Self::encrypt_to`], with the same
    /// input and transform requirements.
    pub fn encrypt<M, Table, R, A>(
        &self,
        message: &Polynomial<A>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttNtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let mut result = NttNtruCiphertext::zero(self.poly_length());
        self.encrypt_to(message, &mut result, params, ntt_table, rng);
        result
    }

    /// Encrypts a polynomial with unsigned plaintext embedding into `result`.
    ///
    /// `message` and `result` have length `N`, with message values in `[0, t)`.
    ///
    /// # Correctness
    ///
    /// Use the key's construction modulus and NTT representation.
    ///
    /// # Panics
    ///
    /// Panics before sampling on inconsistent key/parameter/table/input/output
    /// lengths, or if the table modulus differs from `params`.
    /// A plaintext-codec panic can leave partial output and consume randomness.
    pub fn encrypt_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Plaintext {
                values: message.as_ref(),
                embedding: PlaintextEmbedding::Unsigned,
            },
            result,
            params,
            ntt_table,
            rng,
        );
    }

    /// Uses centered embedding with the same `[0, t)` input values, storage and
    /// failure conditions as [`Self::encrypt_to`].
    pub fn encrypt_centered_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Plaintext {
                values: message.as_ref(),
                embedding: PlaintextEmbedding::Centered,
            },
            result,
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts coefficients already encoded modulo `q` into `result`.
    /// Layout and transform requirements are the same as [`Self::encrypt_to`].
    ///
    /// # Correctness
    ///
    /// Every input coefficient must be a canonical residue in `[0, q)`;
    /// this entry point does not scale or reduce the encoded message.
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_domain(params, ntt_table);
        assert_eq!(encoded.as_ref().len(), self.poly_length());
        assert_eq!(result.as_ref().len(), self.poly_length());
        self.encrypt_encoded_to_unchecked(encoded, result, params, ntt_table, rng);
    }

    /// Encrypts zero into a freshly allocated NTT ciphertext.
    /// Inherits [`Self::encrypt_zeros_to`]'s transform and layout requirements.
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttNtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut result = NttNtruCiphertext::zero(self.poly_length());
        self.encrypt_zeros_to(&mut result, params, ntt_table, rng);
        result
    }

    fn encrypt_to_with_message<M, Table, R, B>(
        &self,
        message: NttEncryptionMessage<'_, T>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.assert_domain(params, ntt_table);
        assert_eq!(result.as_ref().len(), self.poly_length());
        if let Some(values) = message.as_slice() {
            assert_eq!(values.len(), self.poly_length());
        }

        self.encrypt_to_with_message_unchecked(message, result, params, ntt_table, rng);
    }

    pub(super) fn encrypt_encoded_to_unchecked<M, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(encoded.as_ref().len(), self.poly_length());
        debug_assert_eq!(result.as_ref().len(), self.poly_length());
        self.encrypt_to_with_message_unchecked(
            NttEncryptionMessage::Encoded(encoded.as_ref()),
            result,
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts the zero polynomial into the existing output without allocating.
    ///
    /// # Correctness
    ///
    /// Use the key's construction modulus and NTT representation.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if key/parameter/table/output lengths
    /// disagree, or if the table modulus differs from `params`.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(NttEncryptionMessage::Zero, result, params, ntt_table, rng);
    }

    pub(super) fn encrypt_zeros_to_unchecked<M, Table, R, B>(
        &self,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(result.as_ref().len(), self.poly_length());
        self.encrypt_to_with_message_unchecked(
            NttEncryptionMessage::Zero,
            result,
            params,
            ntt_table,
            rng,
        );
    }

    fn encrypt_to_with_message_unchecked<M, Table, R, B>(
        &self,
        message: NttEncryptionMessage<'_, T>,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let coefficients = result.as_mut();
        primus_distr::sample_gaussian_values_to(coefficients, params.noise_distribution(), rng);
        match message {
            NttEncryptionMessage::Zero => {}
            NttEncryptionMessage::Plaintext { values, embedding } => params
                .plaintext_codec()
                .add_encode_slice_assign(coefficients, values, embedding),
            NttEncryptionMessage::Encoded(values) => Polynomial(&mut *coefficients)
                .add_assign(&Polynomial(values), params.cipher_modulus()),
        }

        ntt_table.transform_slice(coefficients);
        NttPolynomial(coefficients).mul_assign(&self.inv_key, params.cipher_modulus());
    }
}

enum NttEncryptionMessage<'a, T: FheUint> {
    Zero,
    Plaintext {
        values: &'a [T],
        embedding: PlaintextEmbedding,
    },
    Encoded(&'a [T]),
}

impl<'a, T: FheUint> NttEncryptionMessage<'a, T> {
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext { values, .. } | Self::Encoded(values) => Some(values),
        }
    }
}
