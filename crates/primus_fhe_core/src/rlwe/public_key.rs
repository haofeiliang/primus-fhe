use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_lattice::rlwe::NttRlwe;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttRlweCiphertext, NttRlweSecretKey, RlweParameters};

/// An RLWE public key stored as one NTT-domain RLWE encryption of zero.
#[derive(Clone)]
pub struct NttRlwePublicKey<S>
where
    S: RawData,
    <S as RawData>::Elem: FheUint,
{
    key: NttRlwe<S>,
}

impl<S, T> AsRef<[T]> for NttRlwePublicKey<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.key.as_ref()
    }
}

impl<S, T> AsMut<[T]> for NttRlwePublicKey<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.key.as_mut()
    }
}

impl<S, T> From<NttRlwe<S>> for NttRlwePublicKey<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn from(key: NttRlwe<S>) -> Self {
        Self { key }
    }
}

impl<T: FheUint> NttRlwePublicKey<Vec<T>> {
    /// Generates a public key for `secret_key` using the supplied NTT table.
    pub fn new<M, Table, R>(
        secret_key: &NttRlweSecretKey<T>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttRlwePublicKey<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = params.poly_length();

        let mut data = vec![T::ZERO; poly_length * 2];

        let (a, b) = data.split_at_mut(poly_length);

        primus_distr::sample_gaussian_values_to(b, params.noise_distribution(), rng);

        ntt_table.transform_slice(b);

        primus_distr::sample_uniform_values_to(a, &params.cipher_modulus_uniform_distr(), rng);

        NttPolynomial(b).add_mul_assign(&NttPolynomial(a), secret_key, params.cipher_modulus());

        Self {
            key: NttRlwe::new(data),
        }
    }
}

impl<S, T> NttRlwePublicKey<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a new [`NttRlwePublicKey<T>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            key: NttRlwe::from_bytes(data),
        }
    }
}

impl<S, T> NttRlwePublicKey<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Creates a new [`NttRlwePublicKey<T>`] from bytes `data`.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }
}

impl<S, T> NttRlwePublicKey<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Converts [`NttRlwePublicKey<T>`] into bytes.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    /// Converts [`NttRlwePublicKey<T>`] into bytes, stored in `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the bytes count of [`NttRlwePublicKey<T>`].
    #[inline]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
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
        let poly_length = params.poly_length();
        let modulus = params.cipher_modulus();
        let modulus_value = params.cipher_modulus_value();

        let (a_in, b_in) = self.key.a_b_slices();
        let (a_out, b_out) = result.a_b_mut_slices();

        let mut v = vec![T::ZERO; poly_length];
        primus_distr::sample_ternary_values_to(&mut v, params.cipher_modulus_minus_one(), rng);
        ntt_table.transform_slice(&mut v);
        let v_poly = &NttPolynomial(v);

        primus_distr::sample_gaussian_values_to(a_out, params.noise_distribution(), rng);
        ntt_table.transform_slice(a_out);
        NttPolynomial(a_out).add_mul_assign(&NttPolynomial(a_in), v_poly, modulus);

        primus_distr::sample_gaussian_values_to(b_out, params.noise_distribution(), rng);
        Polynomial(&mut *b_out).add_mul_factor_assign(msg, params.delta_factor(), modulus_value);
        ntt_table.transform_slice(b_out);

        NttPolynomial(b_out).add_mul_assign(&NttPolynomial(b_in), v_poly, modulus);
    }

    /// Encrypts `msg` into a newly allocated NTT RLWE ciphertext.
    pub fn encrypt<M, Table, R, A>(
        &self,
        msg: &Polynomial<A>,
        params: &RlweParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttRlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: RawData<Elem = T> + Data,
    {
        let mut result = NttRlweCiphertext::zero(params.poly_length() * 2);
        self.encrypt_inplace(msg, &mut result, params, ntt_table, rng);
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
        let poly_length = params.poly_length();
        let modulus = params.cipher_modulus();

        let (a_in, b_in) = self.key.a_b();
        let (a_out, b_out) = result.a_b_mut_slices();

        let mut v = vec![T::ZERO; poly_length];
        primus_distr::sample_ternary_values_to(&mut v, params.cipher_modulus_minus_one(), rng);
        ntt_table.transform_slice(&mut v);
        let v_poly = &NttPolynomial(v);

        primus_distr::sample_gaussian_values_to(a_out, params.noise_distribution(), rng);
        ntt_table.transform_slice(a_out);
        NttPolynomial(a_out).add_mul_assign(&a_in, v_poly, modulus);

        primus_distr::sample_gaussian_values_to(b_out, params.noise_distribution(), rng);
        ntt_table.transform_slice(b_out);
        NttPolynomial(b_out).add_mul_assign(&b_in, v_poly, modulus);
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
        let mut result = NttRlweCiphertext::zero(params.poly_length() * 2);
        self.encrypt_zeros_inplace(&mut result, params, ntt_table, rng);
        result
    }
}
