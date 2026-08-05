use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_reduce::FieldContext;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, DcrtGadgetDomain, DcrtGlweAutoKey, DcrtGlweCiphertext,
    DcrtGlweSecretKey,
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
}

#[derive(Clone)]
/// Automorphism keys for tracing DCRT GLWE ciphertexts to a subring.
pub struct DcrtGlweTraceKey<T: FheUint> {
    auto_keys: Vec<DcrtGlweAutoKey<T>>,
}

impl<T: FheUint> DcrtGlweTraceKey<T> {
    /// Generates the automorphism keys required by the trace.
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

    /// Applies the trace and writes the resulting DCRT ciphertext to `result`.
    ///
    /// The input, output, domain, and context must share the same RNS GLWE
    /// layout. The context is reusable and overwritten by the operation.
    pub fn trace_inplace<M, Table, A, B>(
        &self,
        ciphertext: &DcrtGlweCiphertext<A>,
        result: &mut DcrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut DcrtGlweTraceContext<T>,
    ) where
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
    }
}
