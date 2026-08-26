//! Homomorphic trace for single-modulus coefficient-domain GLWE ciphertexts.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{GlweSize, glwe::Glwe};
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext, NttGlweAutomorphismContext,
    NttGlweAutomorphismKey, NttGlweSecretKey,
};

/// Reusable workspace for homomorphic GLWE trace evaluation.
pub struct NttGlweTraceContext<T: FheUint> {
    automorphism_output: Glwe<Vec<T>>,
    automorphism: NttGlweAutomorphismContext<T>,
}

impl<T: FheUint> NttGlweTraceContext<T> {
    /// Creates trace workspace for one GLWE layout.
    pub fn new(size: GlweSize) -> Self {
        Self {
            automorphism_output: Glwe::zero(size.glwe_len()),
            automorphism: NttGlweAutomorphismContext::new(size),
        }
    }
}

/// The `log2(N)` automorphism keys evaluating the full ring trace.
#[derive(Clone)]
pub struct NttGlweTraceKey<T: FheUint> {
    automorphism_keys: Vec<NttGlweAutomorphismKey<T>>,
    glwe_size: GlweSize,
}

impl<T: FheUint> NttGlweTraceKey<T> {
    /// Generates the automorphism keys for degrees `N + 1, N/2 + 1, ...,
    /// 3`.
    pub fn generate<M, Table, R>(
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let glwe_size = secret_key.glwe_size();
        let log_n = glwe_size.poly_length().trailing_zeros();
        let automorphism_keys = (1..=log_n)
            .rev()
            .map(|shift| (1usize << shift) + 1)
            .map(|degree| {
                NttGlweAutomorphismKey::generate(
                    degree,
                    secret_key,
                    ntt_secret_key,
                    domain,
                    rng,
                    context,
                )
            })
            .collect();
        Self {
            automorphism_keys,
            glwe_size,
        }
    }

    /// Returns the number of automorphism evaluations in one trace.
    #[inline]
    pub fn automorphism_count(&self) -> usize {
        self.automorphism_keys.len()
    }

    /// Returns the decomposition basis used by every automorphism key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.first_automorphism_key().basis()
    }

    /// Evaluates the full trace and overwrites `output` with an encryption of
    /// `N` times the constant coefficient of the input phase.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweTraceContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(
            input.as_ref().len(),
            self.glwe_size.glwe_len(),
            "trace input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.glwe_size.glwe_len(),
            "trace output layout mismatch"
        );
        assert_eq!(
            context.automorphism_output.as_ref().len(),
            self.glwe_size.glwe_len(),
            "trace workspace layout mismatch"
        );
        self.first_automorphism_key()
            .assert_compatible(domain, &context.automorphism);

        output.as_mut().copy_from_slice(input.as_ref());
        let modulus = domain.parameters().cipher_modulus();

        for key in &self.automorphism_keys {
            key.apply_kernel_to(
                output,
                &mut context.automorphism_output,
                domain,
                &mut context.automorphism,
            );
            output.add_element_wise_assign(&context.automorphism_output, modulus);
        }
    }

    /// Returns the first key, which exists because supported GLWE polynomial
    /// lengths are at least two.
    fn first_automorphism_key(&self) -> &NttGlweAutomorphismKey<T> {
        self.automorphism_keys
            .first()
            .expect("a trace key must contain at least one automorphism key")
    }
}
