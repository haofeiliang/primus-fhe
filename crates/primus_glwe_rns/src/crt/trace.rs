use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweCiphertext, DcrtGadgetDomain,
    DcrtGlweSecretKey, GlweSecretKey,
};

/// Reusable workspace for CRT trace and coefficient-expansion operations.
///
/// Each operation overwrites the internal ciphertext and automorphism buffers.
pub struct CrtGlweTraceContext<T: FheUint> {
    crt_glwe: CrtGlweCiphertext<Vec<T>>,
    auto_context: CrtGlweAutoContext<T>,
}

impl<T: FheUint> CrtGlweTraceContext<T> {
    /// Creates reusable workspace from one complete RNS gadget parameter set.
    pub fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self::from_parameters(domain.parameters())
    }

    pub(crate) fn from_parameters<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let crt_glwe = CrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let auto_context = CrtGlweAutoContext::from_parameters(parameters);
        Self {
            crt_glwe,
            auto_context,
        }
    }

    pub(crate) fn as_mut(
        &mut self,
    ) -> (
        &mut primus_lattice::glwe::CrtGlwe<Vec<T>>,
        &mut CrtGlweAutoContext<T>,
    ) {
        (&mut self.crt_glwe, &mut self.auto_context)
    }
}

#[derive(Clone)]
/// Automorphism keys for tracing CRT GLWE ciphertexts to a subring.
pub struct CrtGlweTraceKey<T: FheUint> {
    auto_keys: Vec<CrtGlweAutoKey<T>>,
}

impl<T: FheUint> CrtGlweTraceKey<T> {
    /// Generates the automorphism keys required by the trace.
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let log_n = domain.parameters().poly_length().trailing_zeros();
        let auto_keys: Vec<CrtGlweAutoKey<T>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| CrtGlweAutoKey::new(domain, degree, sk, dcrt_sk, rng))
            .collect();
        Self { auto_keys }
    }

    /// Applies the trace and writes the resulting CRT ciphertext to `result`.
    ///
    /// The input, output, domain, and context must share the same RNS GLWE
    /// layout. The context is reusable and overwritten by the operation.
    pub fn trace_inplace<M, Table, A, B>(
        &self,
        ciphertext: &CrtGlweCiphertext<A>,
        result: &mut CrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut CrtGlweTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length();
        let crt_poly_length = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        let (crt_glwe, auto_context) = context.as_mut();

        result.as_mut().copy_from_slice(ciphertext.as_ref());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_kernel(result, crt_glwe, domain, auto_context);
            result.add_element_wise_assign(crt_glwe, poly_length, crt_poly_length, moduli);
        }
    }
}
