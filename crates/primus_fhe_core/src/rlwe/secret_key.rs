use std::ops::Deref;

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::rlwe::TruncatedRlwe;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialOwned, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{NttRlweCiphertext, PlaintextEmbedding, RingSecretKeyType, RlweParameters};

/// Represents a secret key for the Ring Learning with Errors (RLWE) cryptographic scheme.
#[derive(Clone)]
pub struct RlweSecretKey<T: FheUint> {
    key: PolynomialOwned<T>,
    distr: RingSecretKeyType,
}

impl<T: FheUint> Zeroize for RlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for RlweSecretKey<T> {}

impl<T: FheUint> Deref for RlweSecretKey<T> {
    type Target = PolynomialOwned<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T: FheUint> RlweSecretKey<T> {
    /// Creates a new [`RlweSecretKey<T>`].
    #[inline]
    pub fn new(key: PolynomialOwned<T>, distr: RingSecretKeyType) -> Self {
        debug_assert!(key.poly_length().is_power_of_two());
        Self { key, distr }
    }

    /// Returns the distribution type of the secret key.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    #[inline]
    /// Samples a secret key using the distribution and length in `params`.
    pub fn generate<R, M>(params: &RlweParameters<T, M>, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let distr = params.secret_key_type();
        let poly_length = params.poly_length();
        let modulus_minus_one = params.cipher_modulus_minus_one();

        let key = match distr {
            RingSecretKeyType::Binary => Polynomial::random_binary(poly_length, rng),
            RingSecretKeyType::Ternary => {
                Polynomial::random_ternary(modulus_minus_one, poly_length, rng)
            }
            RingSecretKeyType::Gaussian(_) => Polynomial::random_gaussian(
                poly_length,
                params.secret_key_distribution().unwrap(),
                rng,
            ),
        };

        Self { key, distr }
    }
}

/// Represents a secret key for the (NTT) Ring Learning with Errors (RLWE) cryptographic scheme.
#[derive(Clone)]
pub struct NttRlweSecretKey<T: FheUint> {
    key: NttPolynomialOwned<T>,
    distr: RingSecretKeyType,
}

impl<T: FheUint> Zeroize for NttRlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttRlweSecretKey<T> {}

impl<T: FheUint> Deref for NttRlweSecretKey<T> {
    type Target = NttPolynomialOwned<T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<T: FheUint> NttRlweSecretKey<T> {
    /// Creates a new [`NttRlweSecretKey<T>`].
    #[inline]
    pub fn new(key: NttPolynomialOwned<T>, distr: RingSecretKeyType) -> Self {
        Self { key, distr }
    }

    /// Returns the distribution type of the secret key.
    #[inline]
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    /// Creates a new [`NttRlweSecretKey`] from a coefficient secret key.
    #[inline]
    pub fn from_coeff_secret_key<Table>(secret_key: &RlweSecretKey<T>, ntt_table: &Table) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let key = secret_key.key.clone();
        let key = ntt_table.transform_inplace(key);
        Self {
            key,
            distr: secret_key.distr,
        }
    }

    /// Creates a new [`NttRlweSecretKey`] from a coefficient secret key.
    #[inline]
    pub fn from_coeff_secret_key_owned<Table>(
        secret_key: RlweSecretKey<T>,
        ntt_table: &Table,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        let key = secret_key.key;
        let key = ntt_table.transform_inplace(key);
        Self {
            key,
            distr: secret_key.distr,
        }
    }

    /// Performs `b-as`.
    pub fn phase_inplace<Table, M, A>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        result: &mut PolynomialOwned<T>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let (a, b) = cipher.a_b();
        let mut temp = NttPolynomial(result.as_mut());

        a.mul_to(self, &mut temp, modulus);
        b.sub_rev_assign(&mut temp, modulus);

        ntt_table.inverse_transform_slice(result.as_mut())
    }

    /// Encrypts `msg` into an existing NTT RLWE allocation.
    ///
    /// The message and result must use the polynomial length in `params`.
    pub fn encrypt_inplace<M, Table, R, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut NttRlweCiphertext<B>,
        params: &RlweParameters<T, M>,
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
        result: &mut NttRlweCiphertext<B>,
        params: &RlweParameters<T, M>,
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
        result: &mut NttRlweCiphertext<B>,
        params: &RlweParameters<T, M>,
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
        let (a, b) = result.a_b_mut_slices();
        let modulus = params.cipher_modulus();

        primus_distr::sample_gaussian_values_to(b, params.noise_distribution(), rng);

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

        primus_distr::sample_uniform_values_to(a, &params.cipher_modulus_uniform_distr(), rng);

        NttPolynomial(b).add_mul_assign(&NttPolynomial(a), self, modulus);
    }

    /// Encrypts zero into a newly allocated NTT RLWE ciphertext.
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttRlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut result: NttRlweCiphertext<Vec<T>> =
            NttRlweCiphertext::zero(params.poly_length() * 2);
        self.encrypt_zeros_inplace(&mut result, params, ntt_table, rng);
        result
    }

    /// Encrypts zero into an existing NTT RLWE allocation.
    pub fn encrypt_zeros_inplace<M, Table, R, A>(
        &self,
        result: &mut NttRlweCiphertext<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + DataMut,
    {
        let (a, b) = result.a_b_mut_slices();

        primus_distr::sample_gaussian_values_to(b, params.noise_distribution(), rng);
        ntt_table.transform_slice(b);

        primus_distr::sample_uniform_values_to(a, &params.cipher_modulus_uniform_distr(), rng);

        NttPolynomial(b).add_mul_assign(&NttPolynomial(a), self, params.cipher_modulus());
    }

    /// Encrypts multiple zeros using the secret key.
    pub fn encrypt_multi_zeros<R, M, Table>(
        &self,
        zero_count: usize,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> TruncatedRlwe<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        TruncatedRlwe::generate_random_zero_sample(
            zero_count,
            &self.key,
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            ntt_table,
            params.cipher_modulus(),
            rng,
        )
    }

    /// Decrypts an NTT RLWE ciphertext into `result`.
    ///
    /// The ciphertext and result must use the polynomial length in `params`.
    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        result: &mut Polynomial<B>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let modulus = params.cipher_modulus();
        let (a, b) = cipher.a_b();

        let mut temp = NttPolynomial(result.as_mut());

        a.mul_to(self, &mut temp, modulus);
        b.sub_rev_assign(&mut temp, modulus);
        ntt_table.inverse_transform_slice(result.as_mut());

        params
            .plaintext_codec()
            .decode_slice_inplace(result.as_mut());
    }

    /// Decrypts an NTT RLWE ciphertext into a newly allocated plaintext polynomial.
    pub fn decrypt<M, Table, A>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let mut result = PolynomialOwned::zero(params.poly_length());
        self.decrypt_inplace(cipher, &mut result, params, ntt_table);
        result
    }

    /// Decrypts the [`NttRlweCiphertext`] and returns the decoded message with
    /// the coefficient-wise noise magnitude.
    pub fn decrypt_with_noise<M, Table, A>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        self.decrypt_with_noise_and_embedding(
            cipher,
            params,
            ntt_table,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Decrypts the [`NttRlweCiphertext`] and returns the decoded message with
    /// the coefficient-wise centered noise magnitude.
    pub fn decrypt_centered_with_noise<M, Table, A>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        self.decrypt_with_noise_and_embedding(
            cipher,
            params,
            ntt_table,
            PlaintextEmbedding::Centered,
        )
    }

    /// Decrypts the [`NttRlweCiphertext`] and computes noise under the selected embedding.
    pub fn decrypt_with_noise_and_embedding<M, Table, A>(
        &self,
        cipher: &NttRlweCiphertext<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        embedding: PlaintextEmbedding,
    ) -> (PolynomialOwned<T>, PolynomialOwned<T>)
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let modulus = params.cipher_modulus();

        let mut message = PolynomialOwned::zero(params.poly_length());
        self.phase_inplace(cipher, &mut message, modulus, ntt_table);

        let mut noise = PolynomialOwned::zero(params.poly_length());
        message
            .iter_mut()
            .zip(noise.iter_mut())
            .for_each(|(phase, noise)| {
                let phase_mod_q = *phase;
                let decoded: T = params.plaintext_codec().decode_value(phase_mod_q);
                let fresh: T = params
                    .plaintext_codec()
                    .encode_value_with_delta(decoded, embedding);

                *phase = decoded;
                *noise = modulus
                    .reduce_sub(phase_mod_q, fresh)
                    .min(modulus.reduce_sub(fresh, phase_mod_q));
            });

        (message, noise)
    }

    /// Decrypts the [`TruncatedRlwe`] back to message.
    #[inline]
    pub fn decrypt_multi_messages<Msg, M, Table>(
        &self,
        cipher: &TruncatedRlwe<Vec<T>>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
    ) -> Vec<Msg>
    where
        Msg: TryFrom<T>,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = params.poly_length();
        let modulus = params.cipher_modulus();
        let (a, b) = cipher.a_b_slices(poly_length);

        let mut a = a.to_vec();
        ntt_table.transform_slice(&mut a);
        NttPolynomial(a.as_mut_slice()).mul_assign(&self.key, modulus);
        ntt_table.inverse_transform_slice(&mut a);

        let mut messages: Vec<T> = b
            .iter()
            .zip(a)
            .map(|(x, y)| modulus.reduce_sub(*x, y))
            .collect();
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

    /// Decrypts the [`TruncatedRlwe`] back to message.
    #[inline]
    pub fn phase_multi_messages<M, Table>(
        &self,
        cipher: &TruncatedRlwe<Vec<T>>,
        modulus: M,
        ntt_table: &Table,
    ) -> Vec<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = ntt_table.poly_length();

        let (a, b) = cipher.a_b_slices(poly_length);

        let mut a = a.to_vec();
        ntt_table.transform_slice(&mut a);
        NttPolynomial(a.as_mut_slice()).mul_assign(&self.key, modulus);
        ntt_table.inverse_transform_slice(&mut a);

        b.iter()
            .zip(a)
            .map(|(x, y)| modulus.reduce_sub(*x, y))
            .collect()
    }
}
