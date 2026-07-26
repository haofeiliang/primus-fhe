//! GLWE key switching with signed digit decomposition over an RNS basis.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    context::DcrtGlevContext,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
};
use primus_ntt::DcrtTable;
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::glwe::secret_key::encode_secret_polynomial_to_rns;
use crate::{
    CrtGlevParameters, CrtGlweCiphertext, CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweSecretKey,
    GlweSecretKey,
};

pub struct DcrtGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    poly_length: usize,
    rns_poly_len: usize,
    rns_glev_len: usize,
}

impl<T: FheUint> DcrtGlweKeySwitchingKey<T> {
    pub fn generate<R, M, Table>(
        input_sk: &GlweSecretKey<T>,
        input_params: &CrtGlweParameters<T, M>,
        output_sk: &DcrtGlweSecretKey<T>,
        ksk_params: &CrtGlevParameters<T, M>,
        table: &Table,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        debug_assert_eq!(input_params.poly_length(), ksk_params.poly_length());
        debug_assert_eq!(input_params.cipher_modulus(), ksk_params.cipher_modulus());
        assert_eq!(input_sk.dimension(), input_params.dimension());
        assert_eq!(input_sk.poly_length(), input_params.poly_length());

        let dcrt_glev_len = ksk_params.rns_glev_len();
        let mut key = vec![T::ZERO; input_params.dimension() * dcrt_glev_len];

        let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);
        let mut secret_mod_q: CrtPolynomial<Vec<T>> =
            CrtPolynomial::zero(input_params.rns_poly_len());

        input_sk
            .iter()
            .zip(key_iter)
            .for_each(|(secret_polynomial, mut dcrt_glev)| {
                encode_secret_polynomial_to_rns(
                    secret_polynomial,
                    secret_mod_q.as_mut(),
                    input_params.cipher_moduli_value(),
                );
                output_sk.encrypt_crt_msg_to_dcrt_glev_inplace(
                    &secret_mod_q,
                    &mut dcrt_glev,
                    ksk_params,
                    table,
                    rng,
                );
            });

        Self {
            key,
            poly_length: input_params.poly_length(),
            rns_poly_len: input_params.rns_poly_len(),
            rns_glev_len: dcrt_glev_len,
        }
    }

    pub fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.rns_glev_len)
    }

    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &CrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let (input_mask, input_body) = input.a_b(self.rns_poly_len);
        let (composed_polynomial, transformed_polynomial, glev_context) = context.as_mut();

        output.set_zero();
        self.iter_dcrt_glev()
            .zip(input_mask)
            .for_each(|(key_entry, mask_polynomial)| {
                rns_base.compose_polynomial_to(
                    &mask_polynomial,
                    composed_polynomial,
                    self.poly_length,
                    glev_context.compose_buffer_mut(),
                );

                output.add_dcrt_glev_mul_big_uint_poly_assign(
                    &key_entry,
                    composed_polynomial,
                    basis,
                    table,
                    rns_base,
                    glev_context,
                );
            });

        transformed_polynomial.copy_from(&input_body);
        table.transform_slice(transformed_polynomial.as_mut());
        output.neg_assign(self.rns_poly_len, self.poly_length, rns_base.moduli());

        let (_, output_body) = output.a_b_mut_slices(self.rns_poly_len);
        DcrtPolynomial(output_body).add_assign(
            &DcrtPolynomial(transformed_polynomial.as_ref()),
            self.poly_length,
            rns_base.moduli(),
        );
    }
}

pub struct DcrtGlweKeySwitchingContext<T: FheUint> {
    composed_polynomial: BigUintPolynomial<Vec<T>>,
    transformed_polynomial: CrtPolynomial<Vec<T>>,
    glev_context: DcrtGlevContext<T>,
}

impl<T: FheUint> DcrtGlweKeySwitchingContext<T> {
    pub fn new(
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        Self {
            composed_polynomial: BigUintPolynomial::zero(big_uint_poly_len),
            transformed_polynomial: CrtPolynomial::zero(crt_poly_len),
            glev_context: DcrtGlevContext::new(
                poly_length,
                crt_poly_len,
                big_uint_poly_len,
                moduli_count,
            ),
        }
    }

    fn as_mut(
        &mut self,
    ) -> (
        &mut BigUintPolynomial<Vec<T>>,
        &mut CrtPolynomial<Vec<T>>,
        &mut DcrtGlevContext<T>,
    ) {
        (
            &mut self.composed_polynomial,
            &mut self.transformed_polynomial,
            &mut self.glev_context,
        )
    }
}
