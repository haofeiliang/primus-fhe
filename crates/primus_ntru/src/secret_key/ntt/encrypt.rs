//! Ordinary encryption.

use super::NttNtruSecretKey;
use crate::{NtruParameters, NtruParametersInner, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::{FieldContext, RingContext};

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
    /// Use the key's construction-time NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling on inconsistent key/parameter/table/input/output
    /// lengths or moduli.
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
                codec: params.plaintext_codec(),
            },
            result.as_mut_view(),
            params.inner(),
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
                codec: params.plaintext_codec(),
            },
            result.as_mut_view(),
            params.inner(),
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
        params: &NtruParametersInner<T, M>,
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
        self.encrypt_encoded_to_unchecked(
            encoded.as_view(),
            result.as_mut_view(),
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts zero into a freshly allocated NTT ciphertext.
    /// Inherits [`Self::encrypt_zeros_to`]'s transform and layout requirements.
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &NtruParametersInner<T, M>,
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

    /// Validates the complete input/output and backend domain before any sampling.
    /// Message value validation remains in the codec, after coefficient noise sampling.
    fn encrypt_to_with_message<M, Table, R>(
        &self,
        message: NttEncryptionMessage<'_, T, M>,
        result: NttNtruCiphertext<&mut [T]>,
        params: &NtruParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_domain(params, ntt_table);
        assert_eq!(result.as_ref().len(), self.poly_length());
        if let Some(values) = message.as_slice() {
            assert_eq!(values.len(), self.poly_length());
        }

        self.encrypt_to_with_message_unchecked(message, result, params, ntt_table, rng);
    }

    pub(super) fn encrypt_encoded_to_unchecked<M, Table, R>(
        &self,
        encoded: Polynomial<&[T]>,
        result: NttNtruCiphertext<&mut [T]>,
        params: &NtruParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
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
    /// Use the key's construction-time NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if key/parameter/table/output lengths
    /// or moduli disagree.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        result: &mut NttNtruCiphertext<B>,
        params: &NtruParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Zero,
            result.as_mut_view(),
            params,
            ntt_table,
            rng,
        );
    }

    pub(super) fn encrypt_zeros_to_unchecked<M, Table, R>(
        &self,
        result: NttNtruCiphertext<&mut [T]>,
        params: &NtruParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
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

    /// Requires the public or gadget boundary to validate complete operands and resources.
    /// Sample noise, inject the message, then transform and multiply by the inverse secret;
    /// this order preserves codec failures and RNG consumption across all message modes.
    fn encrypt_to_with_message_unchecked<M, Table, R>(
        &self,
        message: NttEncryptionMessage<'_, T, M>,
        mut result: NttNtruCiphertext<&mut [T]>,
        params: &NtruParametersInner<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let coefficients = result.as_mut();
        primus_distr::sample_gaussian_values_to(coefficients, params.noise_distribution(), rng);
        match message {
            NttEncryptionMessage::Zero => {}
            NttEncryptionMessage::Plaintext {
                values,
                embedding,
                codec,
            } => codec.add_encode_slice_assign(coefficients, values, embedding),
            NttEncryptionMessage::Encoded(values) => Polynomial(&mut *coefficients)
                .add_assign(&Polynomial(values), params.cipher_modulus()),
        }

        ntt_table.transform_slice(coefficients);
        NttPolynomial(coefficients).mul_assign(&self.inv_key, params.cipher_modulus());
    }
}

/// Borrowed message injection: plaintext codec, raw encoded coefficients, or zero.
enum NttEncryptionMessage<'a, T: FheUint, M: RingContext<T>> {
    Zero,
    Plaintext {
        values: &'a [T],
        embedding: PlaintextEmbedding,
        codec: &'a ScaledCodec<T, M>,
    },
    Encoded(&'a [T]),
}

impl<'a, T: FheUint, M: RingContext<T>> NttEncryptionMessage<'a, T, M> {
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext { values, .. } | Self::Encoded(values) => Some(values),
        }
    }
}
