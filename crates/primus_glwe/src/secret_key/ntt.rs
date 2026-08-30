//! Single-modulus NTT-domain GLWE secret key with encryption and decryption.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::GlweSize;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    GlevParameters, GlweParameters, GlweParametersInner, NttGlweCiphertext, PlaintextCodec,
    PlaintextEmbedding, SecretKeyDistr, TruncatedGlweCiphertext,
};

use super::{GlweSecretKey, encode_secret_polynomial_to};

/// Represents a secret key for the (NTT) Module Learning with Errors (MLWE)
/// cryptographic scheme.
#[derive(Clone)]
pub struct NttGlweSecretKey<T: FheUint> {
    key: Vec<T>,
    size: GlweSize,
    distr: SecretKeyDistr,
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
    pub fn new(key: Vec<T>, size: GlweSize, distr: SecretKeyDistr) -> Self {
        assert_eq!(key.len(), size.mask_len());
        Self { key, size, distr }
    }

    /// Returns the coefficient-domain GLWE layout.
    #[inline]
    pub fn glwe_size(&self) -> GlweSize {
        self.size
    }

    /// Returns the poly length of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.poly_length()
    }

    /// Returns the dimension of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.size.dimension()
    }

    /// Returns the distr of this [`NttGlweSecretKey<T>`].
    #[inline]
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    #[inline]
    /// Iterates over the NTT-domain secret polynomials in GLWE component order.
    pub fn iter(&self) -> NttPolynomialIter<'_, T> {
        NttPolynomialIter::new(self.key.as_slice(), self.size.poly_length())
    }

    /// Creates a new [`NttGlweSecretKey`] from [`GlweSecretKey`].
    #[inline]
    pub fn from_coeff_secret_key<Table>(secret_key: &GlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let size = secret_key.glwe_size();
        let poly_length = size.poly_length();
        assert_eq!(ntt_table.poly_length(), poly_length);

        let mut key = vec![T::ZERO; size.mask_len()];
        for (coefficients, ntt_secret) in secret_key.iter().zip(key.chunks_exact_mut(poly_length)) {
            encode_secret_polynomial_to(coefficients, ntt_secret, ntt_table.modulus());
            ntt_table.transform_slice(ntt_secret);
        }

        Self::new(key, size, secret_key.distr)
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

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts a polynomial message into an NTT-domain GLWE ciphertext.
    pub fn encrypt_to<M, Table, R, A, B>(
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Plaintext {
                values: msg.as_ref(),
                embedding: PlaintextEmbedding::Unsigned,
                codec: params.plaintext_codec(),
            },
            result,
            NttEncryptionParameters::glwe(params),
            ntt_table,
            rng,
        )
    }

    /// Encrypts a polynomial using centered plaintext embedding.
    pub fn encrypt_centered_to<M, Table, R, A, B>(
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Plaintext {
                values: msg.as_ref(),
                embedding: PlaintextEmbedding::Centered,
                codec: params.plaintext_codec(),
            },
            result,
            NttEncryptionParameters::glwe(params),
            ntt_table,
            rng,
        )
    }

    /// Encrypts a polynomial whose coefficients are already encoded in
    /// `[0, q)`. The plaintext codec and delta scaling are not applied.
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlweParameters<T, M>,
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
            NttEncryptionMessage::Encoded(encoded.as_ref()),
            result,
            NttEncryptionParameters::glwe(params),
            ntt_table,
            rng,
        );
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
        let mut result: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(self.size.glwe_len());
        self.encrypt_zeros_to(&mut result, params, ntt_table, rng);
        result
    }

    /// Encrypts zeros in-place.
    pub fn encrypt_zeros_to<M, Table, R, A>(
        &self,
        result: &mut NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Zero,
            result,
            NttEncryptionParameters::glwe(params),
            ntt_table,
            rng,
        );
    }

    pub(crate) fn encrypt_gadget_encoded_to<M, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        result: &mut NttGlweCiphertext<B>,
        params: &GlevParameters<T, M>,
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
            NttEncryptionMessage::Encoded(encoded.as_ref()),
            result,
            NttEncryptionParameters::gadget(params),
            ntt_table,
            rng,
        );
    }

    pub(crate) fn encrypt_gadget_zeros_to<M, Table, R, A>(
        &self,
        result: &mut NttGlweCiphertext<A>,
        params: &GlevParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.encrypt_to_with_message(
            NttEncryptionMessage::Zero,
            result,
            NttEncryptionParameters::gadget(params),
            ntt_table,
            rng,
        );
    }

    fn encrypt_to_with_message<M, Table, R, B>(
        &self,
        message: NttEncryptionMessage<'_, T>,
        result: &mut NttGlweCiphertext<B>,
        params: NttEncryptionParameters<'_, T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.size.poly_length();
        assert_eq!(ntt_table.poly_length(), poly_length);
        assert_eq!(result.as_ref().len(), self.size.glwe_len());

        if let Some(message) = message.as_slice() {
            assert_eq!(message.len(), poly_length);
        }

        let modulus = params.inner.cipher_modulus();
        let (a, mut b) = result.a_b_mut(poly_length);

        // Sample noise into b
        primus_distr::sample_gaussian_values_to(b.as_mut(), params.inner.noise_distribution(), rng);

        match message {
            NttEncryptionMessage::Zero => {}
            NttEncryptionMessage::Plaintext {
                values,
                embedding,
                codec,
            } => {
                codec.add_encode_slice_assign_with_delta(b.as_mut(), values, embedding);
            }
            NttEncryptionMessage::Encoded(encoded) => {
                Polynomial::new(b.as_mut()).add_assign(&Polynomial::new(encoded), modulus);
            }
        }
        ntt_table.transform_slice(b.as_mut());

        // Sample each a_i, then accumulate a_i * s_i into b pointwise.
        let uniform_distribution = params.inner.cipher_modulus_uniform_distr();
        for (si, mut ai) in self.iter().zip(a) {
            primus_distr::sample_uniform_values_to(ai.as_mut(), &uniform_distribution, rng);
            b.add_mul_assign(&ai, &si, modulus);
        }
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------

    /// Performs `b - ∑ a_i * s_i` (phase), leaving result in coefficient domain.
    pub fn phase_to<Table, M, S, B>(
        &self,
        cipher: &NttGlweCiphertext<S>,
        result: &mut Polynomial<B>,
        ntt_table: &Table,
        modulus: M,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.size.poly_length();
        debug_assert_eq!(ntt_table.poly_length(), poly_length);
        debug_assert_eq!(result.as_ref().len(), poly_length);
        debug_assert_eq!(cipher.as_ref().len(), self.size.glwe_len());

        let (mut a, b) = cipher.a_b(poly_length);
        let mut secret = self.iter();

        let mut result_poly = NttPolynomial(result.as_mut());
        let si = secret.next().expect("GLWE dimension must be non-zero");
        let ai = a.next().expect("GLWE ciphertext mask is missing");

        ai.mul_to(&si, &mut result_poly, modulus);

        secret.zip(a).for_each(|(si, ai)| {
            result_poly.add_mul_assign(&ai, &si, modulus);
        });
        b.sub_rev_assign(&mut result_poly, modulus);

        ntt_table.inverse_transform_slice(result.as_mut())
    }

    /// Decrypts an NTT GLWE ciphertext into a newly allocated plaintext polynomial.
    pub fn decrypt<M, Table, A>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut result = PolynomialOwned::zero(self.size.poly_length());
        self.decrypt_to(cipher, &mut result, params, ntt_table);
        result
    }

    /// Decrypts an NTT GLWE ciphertext into `result`.
    ///
    /// The ciphertext and result must match the polynomial length in `params`.
    pub fn decrypt_to<M, Table, A, B>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.phase_to(cipher, result, ntt_table, params.cipher_modulus());

        params
            .plaintext_codec()
            .decode_slice_inplace(result.as_mut());
    }

    /// Decrypts a ciphertext and returns both its message and the absolute
    /// coefficient-wise noise modulo `q`.
    pub fn decrypt_with_noise<M, Table, A>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.decrypt_with_noise_and_embedding(
            cipher,
            params,
            ntt_table,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Decrypts a centered ciphertext and returns both its message and the
    /// absolute coefficient-wise noise modulo `q`.
    pub fn decrypt_centered_with_noise<M, Table, A>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        self.decrypt_with_noise_and_embedding(
            cipher,
            params,
            ntt_table,
            PlaintextEmbedding::Centered,
        )
    }

    /// Decrypts a ciphertext and measures its coefficient-wise noise using
    /// the selected plaintext embedding.
    pub fn decrypt_with_noise_and_embedding<M, Table, A>(
        &self,
        cipher: &NttGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        embedding: PlaintextEmbedding,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let modulus = params.cipher_modulus();
        let mut message = PolynomialOwned::zero(self.size.poly_length());
        self.phase_to(cipher, &mut message, ntt_table, modulus);

        let mut noise = PolynomialOwned::zero(self.size.poly_length());
        message
            .iter_mut()
            .zip(noise.iter_mut())
            .for_each(|(phase, noise)| {
                let phase_mod_q = *phase;
                let decoded = params.plaintext_codec().decode_value(phase_mod_q);
                let encoded = params
                    .plaintext_codec()
                    .encode_value_with_delta(decoded, embedding);

                *phase = decoded;
                *noise = modulus
                    .reduce_sub(phase_mod_q, encoded)
                    .min(modulus.reduce_sub(encoded, phase_mod_q));
            });

        (message, noise)
    }

    /// Encrypts several zero messages in one coefficient-domain GLWE sample
    /// whose body is truncated to `message_count` coefficients.
    ///
    /// This is useful when only the first few coefficient extractions are
    /// needed. `message_count` must not exceed the polynomial length.
    pub fn encrypt_multi_zeros<R, M, Table>(
        &self,
        message_count: usize,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> TruncatedGlweCiphertext<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let size = params.size();
        let poly_length = size.poly_length();
        assert_eq!(self.size, size);
        assert_eq!(ntt_table.poly_length(), poly_length);
        assert!(message_count <= poly_length);

        let mask_len = size.mask_len();
        let mut data = vec![T::ZERO; mask_len + poly_length];
        let (mask, body) = data.split_at_mut(mask_len);
        primus_distr::sample_uniform_values_to(mask, &params.cipher_modulus_uniform_distr(), rng);

        let modulus = params.cipher_modulus();
        let mut masks = mask.chunks_exact(poly_length);
        let mut secrets = self.iter();
        let first_mask = masks.next().expect("GLWE dimension must be non-zero");
        let first_secret = secrets.next().expect("GLWE dimension must be non-zero");
        body.copy_from_slice(first_mask);
        ntt_table.transform_slice(body);
        NttPolynomial(&mut *body).mul_assign(&first_secret, modulus);

        if masks.len() != 0 {
            let mut transformed_mask = vec![T::ZERO; poly_length];
            for (mask, secret) in masks.zip(secrets) {
                transformed_mask.copy_from_slice(mask);
                ntt_table.transform_slice(&mut transformed_mask);
                NttPolynomial(&mut *body).add_mul_assign(
                    &NttPolynomial(transformed_mask.as_slice()),
                    &secret,
                    modulus,
                );
            }
        }
        ntt_table.inverse_transform_slice(body);
        Polynomial(&mut *body).add_random_gaussian_assign(
            params.noise_distribution(),
            modulus,
            rng,
        );

        data.truncate(mask_len + message_count);
        TruncatedGlweCiphertext::new(data)
    }

    /// Returns the retained coefficient phases of a truncated GLWE
    /// ciphertext.
    pub fn phase_multi_messages<M, Table, A>(
        &self,
        cipher: &TruncatedGlweCiphertext<A>,
        modulus: M,
        ntt_table: &Table,
    ) -> Vec<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let size = self.size;
        let poly_length = size.poly_length();
        assert_eq!(ntt_table.poly_length(), poly_length);
        let (mask, body) = cipher.a_b_slices(size);
        assert!(body.len() <= poly_length);

        let mut masks = mask.chunks_exact(poly_length);
        let mut secrets = self.iter();
        let first_mask = masks.next().expect("GLWE dimension must be non-zero");
        let first_secret = secrets.next().expect("GLWE dimension must be non-zero");
        let mut phase_mask = first_mask.to_vec();
        ntt_table.transform_slice(&mut phase_mask);
        NttPolynomial(phase_mask.as_mut_slice()).mul_assign(&first_secret, modulus);

        if masks.len() != 0 {
            let mut transformed_mask = vec![T::ZERO; poly_length];
            for (mask, secret) in masks.zip(secrets) {
                transformed_mask.copy_from_slice(mask);
                ntt_table.transform_slice(&mut transformed_mask);
                NttPolynomial(phase_mask.as_mut_slice()).add_mul_assign(
                    &NttPolynomial(transformed_mask.as_slice()),
                    &secret,
                    modulus,
                );
            }
        }
        ntt_table.inverse_transform_slice(&mut phase_mask);

        body.iter()
            .zip(phase_mask)
            .map(|(&body, mask)| modulus.reduce_sub(body, mask))
            .collect()
    }

    /// Decrypts all retained messages in a truncated GLWE ciphertext.
    pub fn decrypt_multi_messages<Msg, M, Table, A>(
        &self,
        cipher: &TruncatedGlweCiphertext<A>,
        params: &GlweParameters<T, M>,
        ntt_table: &Table,
    ) -> Vec<Msg>
    where
        Msg: TryFrom<T>,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        assert_eq!(self.size, params.size());
        let mut messages = self.phase_multi_messages(cipher, params.cipher_modulus(), ntt_table);
        params.plaintext_codec().decode_slice_inplace(&mut messages);

        messages
            .into_iter()
            .map(|message| {
                Msg::try_from(message)
                    .map_err(|_| "out of range integral type conversion attempted")
                    .unwrap()
            })
            .collect()
    }
}

enum NttEncryptionMessage<'a, T: FheUint> {
    Zero,
    Plaintext {
        values: &'a [T],
        embedding: PlaintextEmbedding,
        codec: &'a PlaintextCodec<T>,
    },
    Encoded(&'a [T]),
}

struct NttEncryptionParameters<'a, T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    inner: &'a GlweParametersInner<T, M>,
}

impl<'a, T, M> NttEncryptionParameters<'a, T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    fn glwe(params: &'a GlweParameters<T, M>) -> Self {
        Self {
            inner: params.inner(),
        }
    }

    fn gadget(params: &'a GlevParameters<T, M>) -> Self {
        Self {
            inner: params.inner(),
        }
    }
}

impl<'a, T: FheUint> NttEncryptionMessage<'a, T> {
    #[inline]
    fn as_slice(&self) -> Option<&'a [T]> {
        match self {
            Self::Zero => None,
            Self::Plaintext { values, .. } | Self::Encoded(values) => Some(values),
        }
    }
}
