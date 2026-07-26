//! DCRT-domain (NTT within CRT, multi-modulus) GLWE secret key with full
//! encryption/decryption and GLev encryption.

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::glev::DcrtGlev;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{
    CrtPolynomial, DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut, Polynomial,
    PolynomialOwned,
};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CrtGlevParameters, CrtGlweParameters, DcrtGlweCiphertext, RingSecretKeyType};

use super::{GlweSecretKey, encode_secret_polynomial_to};

#[derive(Clone)]
pub struct DcrtGlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T>,
    pub(crate) distr: RingSecretKeyType,
    pub(crate) rns_poly_len: usize,
}

impl<T: FheUint> Zeroize for DcrtGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweSecretKey<T> {}

impl<T: FheUint> DcrtGlweSecretKey<T> {
    pub fn zero(dimension: usize, crt_poly_len: usize, distr: RingSecretKeyType) -> Self {
        Self {
            key: vec![T::ZERO; dimension * crt_poly_len],
            distr,
            rns_poly_len: crt_poly_len,
        }
    }

    pub fn key(&self) -> &[T] {
        &self.key
    }

    /// Returns the distr of this [`DcrtGlweSecretKey<T>`].
    pub fn distr(&self) -> RingSecretKeyType {
        self.distr
    }

    pub fn iter_dcrt_poly(&self) -> DcrtPolynomialIter<'_, T> {
        DcrtPolynomialIter::new(self.key.as_slice(), self.rns_poly_len)
    }

    pub fn iter_dcrt_poly_mut(&mut self) -> DcrtPolynomialIterMut<'_, T> {
        DcrtPolynomialIterMut::new(self.key.as_mut_slice(), self.rns_poly_len)
    }

    /// Creates a modulus-specific DCRT representation of a canonical signed
    /// [`GlweSecretKey<T>`].
    #[inline]
    pub fn from_coeff_secret_key<Table>(secret_key: &GlweSecretKey<T>, table: &Table) -> Self
    where
        Table: DcrtTable<ValueT = T>,
    {
        assert_eq!(secret_key.poly_length(), table.poly_length());
        let rns_poly_len = table.moduli_count() * secret_key.poly_length();
        let mut key = vec![T::ZERO; secret_key.dimension() * rns_poly_len];
        for (coefficients, dcrt_secret) in secret_key.iter().zip(key.chunks_exact_mut(rns_poly_len))
        {
            for (ntt_table, modulus_limb) in table
                .ntt_tables()
                .iter()
                .zip(dcrt_secret.chunks_exact_mut(secret_key.poly_length()))
            {
                encode_secret_polynomial_to(coefficients, modulus_limb, ntt_table.modulus());
                ntt_table.transform_slice(modulus_limb);
            }
        }

        Self {
            key,
            distr: secret_key.distr(),
            rns_poly_len,
        }
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /// Encrypts an already-decomposed CRT plaintext polynomial.
    ///
    /// The message should be the result of [`crate::RnsCoeffCodec::unsigned_encode_coeffs`]
    /// or a hand-constructed [`CrtPolynomial`] whose coefficients are in `[0, q_i)`.
    /// Delta scaling is applied using Shoup factors from the codec.
    pub fn encrypt_inplace<R, M, Table, A, B>(
        &self,
        msg: &CrtPolynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            rng,
        );

        let mut b_crt_poly = CrtPolynomial(&mut *b.0);
        b_crt_poly.add_mul_factor_assign(
            msg,
            params.delta_factor_mod_q(),
            poly_length,
            params.cipher_moduli_value(),
        );
        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Encrypts a raw plaintext polynomial using unsigned embedding.
    pub fn encrypt_plaintext_inplace<R, M, Table, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            rng,
        );

        params.codec().add_unsigned_encode_coeffs_assign(
            msg,
            &mut CrtPolynomial(&mut *b.0),
            poly_length,
        );

        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Encrypts a raw plaintext polynomial using centered embedding.
    pub fn encrypt_centered_plaintext_inplace<R, M, Table, A, B>(
        &self,
        msg: &Polynomial<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            rng,
        );

        params.codec().add_centered_encode_coeffs_assign(
            msg,
            &mut CrtPolynomial(&mut *b.0),
            poly_length,
        );

        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    pub fn encrypt_zeros_inplace<R, M, Table, A>(
        &self,
        result: &mut DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(rns_poly_len);

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            rng,
        );

        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    // -------------------------------------------------------------------------
    // GLev encryption helpers (for key-switching key generation)
    // -------------------------------------------------------------------------

    fn encrypt_dcrt_msg_to_dcrt_glwe_inplace_with_custom_delta<R, M, Table, A, B>(
        &self,
        dcrt_msg: &DcrtPolynomial<A>,
        delta_residues: &[T],
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(params.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            &mut *rng,
        );

        table.transform_slice(b.0);
        b.add_mul_scalar_assign(dcrt_msg, delta_residues, poly_length, moduli);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.0,
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    pub fn encrypt_dcrt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        dcrt_msg: &DcrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.basis().iter_scalar_residues())
            .for_each(|(mut dcrt_glwe, scalar_residues)| {
                self.encrypt_dcrt_msg_to_dcrt_glwe_inplace_with_custom_delta(
                    dcrt_msg,
                    scalar_residues,
                    &mut dcrt_glwe,
                    params,
                    table,
                    rng,
                );
            });
    }

    fn encrypt_crt_msg_to_dcrt_glwe_inplace_with_custom_delta<R, M, Table, A, B>(
        &self,
        crt_msg: &CrtPolynomial<A>,
        delta_residues: &[T],
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let moduli = params.cipher_moduli();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let (a, mut b) = result.a_b_mut(params.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            params.cipher_moduli_value(),
            params.noise_distribution(),
            &mut *rng,
        );

        let mut b_crt_poly = CrtPolynomial(&mut *b.0);
        b_crt_poly.add_mul_scalar_assign(crt_msg, delta_residues, poly_length, moduli);
        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(
                ai.0,
                poly_length,
                uniform_distrs,
                &mut *rng,
            );
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    pub fn encrypt_crt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        crt_msg: &CrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.basis().iter_scalar_residues())
            .for_each(|(mut dcrt_glwe, scalar_residues)| {
                self.encrypt_crt_msg_to_dcrt_glwe_inplace_with_custom_delta(
                    crt_msg,
                    scalar_residues,
                    &mut dcrt_glwe,
                    params,
                    table,
                    rng,
                );
            });
    }

    // -------------------------------------------------------------------------
    // Phase / Decryption
    // -------------------------------------------------------------------------

    /// Performs `b - ∑ a*s`.
    pub fn phase_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg_mod_q: &mut DcrtPolynomial<B>,
        params: &CrtGlweParameters<T, M>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let moduli = params.cipher_moduli();

        let (a, b) = ciphertext.a_b(params.rns_poly_len());

        msg_mod_q.set_zero();

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            msg_mod_q.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        b.sub_rev_assign(msg_mod_q, poly_length, moduli);
    }

    /// Performs `- ∑ a*s`.
    pub fn phase_a_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg_mod_q: &mut DcrtPolynomial<B>,
        params: &CrtGlweParameters<T, M>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let moduli = params.cipher_moduli();

        let (a, _b) = ciphertext.a_b(params.rns_poly_len());

        msg_mod_q.set_zero();

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            msg_mod_q.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        msg_mod_q.neg_assign(poly_length, moduli);
    }

    pub fn decrypt<M, Table, A>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        context: &mut DcrtGlweDecryptContext<T>,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let mut msg = PolynomialOwned::zero(params.poly_length());
        self.decrypt_inplace(ciphertext, &mut msg, params, table, context);
        msg
    }

    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg: &mut Polynomial<B>,
        params: &CrtGlweParameters<T, M>,
        table: &Table,
        context: &mut DcrtGlweDecryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();

        let DcrtGlweDecryptContextRefMut {
            msg_mod_q,
            fast_convert_buffer,
        } = context.as_mut();

        self.phase_inplace(ciphertext, msg_mod_q, params);

        table.inverse_transform_slice(msg_mod_q.as_mut());

        params
            .codec()
            .decode_coeffs(msg_mod_q, msg, poly_length, fast_convert_buffer);
    }
}

// ---------------------------------------------------------------------------
// Decryption context
// ---------------------------------------------------------------------------

pub struct DcrtGlweDecryptContext<T: FheUint> {
    msg_mod_q: DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: Vec<T>,
}

pub struct DcrtGlweDecryptContextRefMut<'a, T: FheUint> {
    msg_mod_q: &'a mut DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlweDecryptContext<T> {
    /// Creates a new [`DcrtGlweDecryptContext<T>`].
    #[inline]
    pub fn new(moduli_count: usize, poly_length: usize) -> Self {
        let msg_mod_q: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(moduli_count * poly_length);
        let fast_convert_buffer = vec![T::ZERO; moduli_count * poly_length];

        Self {
            msg_mod_q,
            fast_convert_buffer,
        }
    }

    #[inline]
    pub fn as_mut(&mut self) -> DcrtGlweDecryptContextRefMut<'_, T> {
        DcrtGlweDecryptContextRefMut {
            msg_mod_q: &mut self.msg_mod_q,
            fast_convert_buffer: &mut self.fast_convert_buffer,
        }
    }
}
