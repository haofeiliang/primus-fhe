use std::sync::Arc;

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweCiphertext, DcrtGlweSecretKey,
    GlweSecretKey,
};

pub struct CrtGlweTraceContext<T: FheUint> {
    crt_glwe: CrtGlweCiphertext<Vec<T>>,
    auto_context: CrtGlweAutoContext<T>,
}

impl<T: FheUint> CrtGlweTraceContext<T> {
    pub fn new(
        dimension: usize,
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        let crt_glwe = CrtGlweCiphertext::zero((dimension + 1) * crt_poly_len);
        let auto_context =
            CrtGlweAutoContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        Self {
            crt_glwe,
            auto_context,
        }
    }

    pub fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::CrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        (&mut self.crt_glwe, &mut self.auto_context)
    }
}

#[derive(Clone)]
pub struct CrtGlweTraceKey<T: FheUint, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    auto_keys: Vec<CrtGlweAutoKey<T, Table>>,
    table: Arc<Table>,
}

impl<T: FheUint, Table> CrtGlweTraceKey<T, Table>
where
    Table: DcrtTable<ValueT = T>,
{
    pub fn new<M, R>(
        params: &CrtGlevParameters<T, M>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        table: Arc<Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        let log_n = params.poly_length().trailing_zeros();
        let auto_keys: Vec<CrtGlweAutoKey<T, Table>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| CrtGlweAutoKey::new(params, degree, sk, dcrt_sk, Arc::clone(&table), rng))
            .collect();
        Self { auto_keys, table }
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    pub fn trace_inplace<M, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut CrtGlweCiphertext<B>,
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
        context: &mut CrtGlweTraceContext<T>,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (crt_glwe, auto_context) = context.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_to(result, crt_glwe, params, rns_base, auto_context);
            result.add_element_wise_assign(crt_glwe, poly_length, rns_poly_len, moduli);
        }
    }
}
