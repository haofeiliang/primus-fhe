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

use crate::{
    CrtGlevParameters, CrtGlweCiphertext, CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext,
    DcrtGlweSecretKey,
};

pub struct CrtGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    poly_length: usize,
    rns_poly_len: usize,
    rns_glev_len: usize,
    input_rns_glwe_mid: usize,
    output_rns_glwe_mid: usize,
}

impl<T: FheUint> CrtGlweKeySwitchingKey<T> {
    pub fn new<R, M, Table>(
        input_sk: &CrtGlweSecretKey<T>,
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

        let dcrt_glev_len = ksk_params.rns_glev_len();
        let mut key: Vec<T> = vec![T::ZERO; input_params.dimension() * dcrt_glev_len];

        let key_iter = DcrtGlevIterMut::new(key.as_mut_slice(), dcrt_glev_len);

        input_sk
            .iter_crt_poly()
            .zip(key_iter)
            .for_each(|(si, mut dcrt_glev)| {
                output_sk.encrypt_crt_msg_to_dcrt_glev_inplace(
                    &si,
                    &mut dcrt_glev,
                    ksk_params,
                    table,
                    rng,
                );
            });

        let poly_length = input_params.poly_length();
        let rns_poly_len = input_params.rns_poly_len();
        let input_rns_glwe_mid = input_params.rns_glwe_mid();
        let output_rns_glwe_mid = ksk_params.rns_glwe_mid();
        Self {
            key,
            poly_length,
            rns_poly_len,
            rns_glev_len: dcrt_glev_len,
            input_rns_glwe_mid,
            output_rns_glwe_mid,
        }
    }

    pub fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.rns_glev_len)
    }

    pub fn key_swithching_inplace<M, Table, A, B>(
        &self,
        c_in: &CrtGlweCiphertext<A>,
        c_out: &mut DcrtGlweCiphertext<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &Table,
        rns_base: &RNSBase<T, M>,
        context: &mut CrtGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = self.poly_length;

        let (a_in, b_in) = c_in.a_b(self.input_rns_glwe_mid);

        let (big_uint_poly, crt_poly, glev_context) = context.as_mut();

        c_out.set_zero();
        self.iter_dcrt_glev().zip(a_in).for_each(|(ki, ai)| {
            rns_base.compose_polynomial_to(
                &ai,
                big_uint_poly,
                poly_length,
                glev_context.compose_buffer_mut(),
            );

            c_out.add_dcrt_glev_mul_big_uint_poly_assign(
                &ki,
                big_uint_poly,
                basis,
                table,
                rns_base,
                glev_context,
            );
        });

        crt_poly.copy_from(&b_in);
        table.transform_slice(crt_poly.as_mut());
        c_out.neg_assign(self.rns_poly_len, poly_length, rns_base.moduli());

        let (_, b_out) = c_out.a_b_mut_slices(self.output_rns_glwe_mid);
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(crt_poly.as_ref()),
            poly_length,
            rns_base.moduli(),
        );
    }
}

pub struct CrtGlweKeySwitchingContext<T: FheUint> {
    big_uint_poly: BigUintPolynomial<Vec<T>>,
    crt_poly: CrtPolynomial<Vec<T>>,
    glev_context: DcrtGlevContext<T>,
}

impl<T: FheUint> CrtGlweKeySwitchingContext<T> {
    pub fn new(
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let big_uint_poly = BigUintPolynomial::zero(big_uint_poly_len);
        let crt_poly = CrtPolynomial::zero(crt_poly_len);
        let glev_context =
            DcrtGlevContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        Self {
            big_uint_poly,
            crt_poly,
            glev_context,
        }
    }

    pub fn as_mut(
        &mut self,
    ) -> (
        &mut BigUintPolynomial<Vec<T>>,
        &mut CrtPolynomial<Vec<T>>,
        &mut DcrtGlevContext<T>,
    ) {
        (
            &mut self.big_uint_poly,
            &mut self.crt_poly,
            &mut self.glev_context,
        )
    }
}
