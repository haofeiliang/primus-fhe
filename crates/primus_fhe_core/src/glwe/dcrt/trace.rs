use std::sync::Arc;

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey,
};

pub struct DcrtGlweTraceContext<T: FheUint> {
    dcrt_glwe: DcrtGlweCiphertext<Vec<T>>,
    auto_context: CrtGlweAutoContext<T>,
}

impl<T: FheUint> DcrtGlweTraceContext<T> {
    pub fn new(
        dimension: usize,
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let dcrt_glwe = DcrtGlweCiphertext::zero((dimension + 1) * crt_poly_len);
        let auto_context =
            CrtGlweAutoContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        Self {
            dcrt_glwe,
            auto_context,
        }
    }

    pub fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::DcrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        (&mut self.dcrt_glwe, &mut self.auto_context)
    }

    pub fn compose_buffer_mut(&mut self) -> &mut [T] {
        self.auto_context.compose_buffer_mut()
    }
}

#[derive(Clone)]
pub struct DcrtGlweTraceKey<T: FheUint, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    auto_keys: Vec<DcrtGlweAutoKey<T, Table>>,
    table: Arc<Table>,
}

impl<T: FheUint, Table> DcrtGlweTraceKey<T, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    pub fn new<M, R>(
        params: &CrtGlevParameters<T, M>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        table: Arc<Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let log_n = params.poly_length().trailing_zeros();
        let auto_keys: Vec<DcrtGlweAutoKey<T, Table>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKey::new(params, degree, dcrt_sk, Arc::clone(&table), rng))
            .collect();
        Self { auto_keys, table }
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    pub fn trace_inplace<M, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlweTraceContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (dcrt_glwe, auto_context) = context.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_inplace(result, dcrt_glwe, params, rns_base, auto_context);
            result.add_element_wise_assign(dcrt_glwe, poly_length, rns_poly_len, moduli);
        }
    }
}
