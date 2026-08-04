use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::RnsGadgetSize;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, DcrtGadgetDomain, DcrtGlweAutoKey, DcrtGlweCiphertext,
    DcrtGlweSecretKey, GlweKeySwitchingError,
};

/// Reusable workspace for DCRT trace and coefficient-expansion operations.
///
/// Each operation overwrites the internal ciphertext and automorphism buffers.
pub struct DcrtGlweTraceContext<T: FheUint> {
    dcrt_glwe: DcrtGlweCiphertext<Vec<T>>,
    auto_context: CrtGlweAutoContext<T>,
}

impl<T: FheUint> DcrtGlweTraceContext<T> {
    /// Creates reusable workspace from one complete RNS gadget parameter set.
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        Self::from_parameters(domain.parameters())
    }

    pub(crate) fn from_parameters<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let dcrt_glwe = DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let auto_context = CrtGlweAutoContext::from_parameters(parameters);
        Self {
            dcrt_glwe,
            auto_context,
        }
    }

    pub(crate) fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::DcrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        (&mut self.dcrt_glwe, &mut self.auto_context)
    }

    pub fn size(&self) -> RnsGadgetSize {
        self.auto_context.size()
    }
}

#[derive(Clone)]
pub struct DcrtGlweTraceKey<T: FheUint> {
    auto_keys: Vec<DcrtGlweAutoKey<T>>,
}

impl<T: FheUint> DcrtGlweTraceKey<T> {
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
    {
        let log_n = domain.parameters().poly_length().trailing_zeros();
        let auto_keys: Vec<DcrtGlweAutoKey<T>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| DcrtGlweAutoKey::new(domain, degree, dcrt_sk, rng))
            .collect();
        Self { auto_keys }
    }

    pub fn trace_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut DcrtGlweTraceContext<T>,
    ) -> Result<(), GlweKeySwitchingError>
    where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (dcrt_glwe, auto_context) = context.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_kernel(result, dcrt_glwe, domain, auto_context);
            result.add_element_wise_assign(dcrt_glwe, poly_length, rns_poly_len, moduli);
        }
        Ok(())
    }
}
