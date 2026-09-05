//! DCRT-domain (NTT within CRT, multi-modulus) GLWE secret key with full
//! encryption/decryption and GLev encryption.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{RnsGlweSize, glev::DcrtGlev};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial, DcrtPolynomialIter, Polynomial, PolynomialOwned};
use primus_reduce::FieldContext;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext, SecretKeyDistr,
};

use super::{GlweSecretKey, encode_secret_polynomial_to};

/// A GLWE secret key represented in NTT form for every ordered RNS modulus.
#[derive(Clone)]
pub struct DcrtGlweSecretKey<T: FheUint> {
    pub(crate) key: Vec<T>,
    pub(crate) distr: SecretKeyDistr,
    pub(crate) size: RnsGlweSize,
}

impl<T: FheUint> Zeroize for DcrtGlweSecretKey<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for DcrtGlweSecretKey<T> {}

impl<T: FheUint> DcrtGlweSecretKey<T> {
    pub(crate) fn key(&self) -> &[T] {
        &self.key
    }

    /// Returns the distr of this [`DcrtGlweSecretKey<T>`].
    pub fn distr(&self) -> SecretKeyDistr {
        self.distr
    }

    /// Returns the RNS GLWE layout of this secret key.
    #[inline]
    pub fn rns_glwe_size(&self) -> RnsGlweSize {
        self.size
    }

    /// Iterates over the DCRT secret polynomials in GLWE component order.
    pub fn iter_dcrt_poly(&self) -> DcrtPolynomialIter<'_, T> {
        DcrtPolynomialIter::new(self.key.as_slice(), self.size.rns_poly_len())
    }

    /// Creates a modulus-specific DCRT representation of a canonical signed
    /// [`GlweSecretKey<T>`].
    #[inline]
    pub fn from_coeff_secret_key<Table>(
        secret_key: &GlweSecretKey<T>,
        table: &DcrtTable<Table>,
    ) -> Self
    where
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(secret_key.poly_length(), table.poly_length());

        let size = RnsGlweSize::new(secret_key.glwe_size(), table.moduli_count());
        let poly_length = size.poly_length();
        let rns_poly_len = size.rns_poly_len();
        let mut key = vec![T::ZERO; size.rns_mask_len()];

        for (coefficients, dcrt_secret) in secret_key.iter().zip(key.chunks_exact_mut(rns_poly_len))
        {
            for (ntt_table, modulus_limb) in table
                .ntt_tables()
                .iter()
                .zip(dcrt_secret.chunks_exact_mut(poly_length))
            {
                encode_secret_polynomial_to(coefficients, modulus_limb, ntt_table.modulus());
                ntt_table.transform_slice(modulus_limb);
            }
        }

        Self {
            key,
            distr: secret_key.distr(),
            size,
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
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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

        params
            .codec()
            .add_unsigned_encode_coeffs_assign(msg, &mut CrtPolynomial(&mut *b.0));

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
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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

        params
            .codec()
            .add_centered_encode_coeffs_assign(msg, &mut CrtPolynomial(&mut *b.0));

        table.transform_slice(b.0);

        self.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });
    }

    /// Encrypts zero into an existing DCRT GLWE allocation.
    ///
    /// The result is overwritten and must match `params` and `table`.
    pub fn encrypt_zeros_inplace<R, M, Table, A>(
        &self,
        result: &mut DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: DataMut<Elem = T>,
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
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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

    /// Encrypts a DCRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The plaintext, result, parameters, and table must share the same ordered
    /// RNS basis and polynomial length.
    pub fn encrypt_dcrt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        dcrt_msg: &DcrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        assert_eq!(result.as_ref().len(), params.rns_glev_len());
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.scalar_residue_iter())
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
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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

    /// Encrypts a CRT plaintext polynomial into an existing DCRT GLev allocation.
    ///
    /// The result is overwritten and must match the domain's gadget layout.
    pub fn encrypt_crt_msg_to_dcrt_glev_inplace<R, M, Table, A, B>(
        &self,
        crt_msg: &CrtPolynomial<A>,
        result: &mut DcrtGlev<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let table = domain.table();
        assert_eq!(result.as_ref().len(), params.rns_glev_len());
        result
            .iter_dcrt_glwe_mut(params.rns_glwe_len())
            .zip(params.scalar_residue_iter())
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
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

    /// Decrypts a DCRT GLWE ciphertext into a newly allocated plaintext polynomial.
    pub fn decrypt<M, Table, A>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        context: &mut DcrtGlweDecryptContext<T>,
    ) -> PolynomialOwned<T>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut msg = PolynomialOwned::zero(params.poly_length());
        self.decrypt_inplace(ciphertext, &mut msg, params, table, context);
        msg
    }

    /// Decrypts a DCRT GLWE ciphertext into `msg` using reusable workspace.
    ///
    /// The ciphertext, output, parameters, table, and context must share the
    /// same polynomial length and ordered RNS basis.
    pub fn decrypt_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        msg: &mut Polynomial<B>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        context: &mut DcrtGlweDecryptContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(context.size(), params.size());
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

/// Reusable workspace for DCRT GLWE decryption.
///
/// Decryption overwrites both internal buffers.
pub struct DcrtGlweDecryptContext<T: FheUint> {
    size: RnsGlweSize,
    msg_mod_q: DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: Vec<T>,
}

struct DcrtGlweDecryptContextRefMut<'a, T: FheUint> {
    msg_mod_q: &'a mut DcrtPolynomial<Vec<T>>,
    fast_convert_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlweDecryptContext<T> {
    /// Creates a new [`DcrtGlweDecryptContext<T>`].
    #[inline]
    pub fn new(size: RnsGlweSize) -> Self {
        let msg_mod_q: DcrtPolynomial<Vec<T>> = DcrtPolynomial::zero(size.rns_poly_len());
        let fast_convert_buffer = vec![T::ZERO; size.rns_poly_len()];

        Self {
            size,
            msg_mod_q,
            fast_convert_buffer,
        }
    }

    #[inline]
    fn as_mut(&mut self) -> DcrtGlweDecryptContextRefMut<'_, T> {
        DcrtGlweDecryptContextRefMut {
            msg_mod_q: &mut self.msg_mod_q,
            fast_convert_buffer: &mut self.fast_convert_buffer,
        }
    }

    /// Returns the RNS GLWE layout bound to this workspace.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }
}
