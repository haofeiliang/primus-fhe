//! GLWE key switching with signed digit decomposition over an RNS basis.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    RnsGadgetSize, RnsGlweSize,
    context::DcrtGlevMulContext,
    glev::{DcrtGlevIter, DcrtGlevIterMut},
};
use primus_ntt::NttTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;

use crate::secret_key::encode_secret_polynomial_to_rns;
use crate::{
    CrtGlweCiphertext, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweSecretKey,
    GlweSecretKey,
};

/// A DCRT GLWE key-switching key stored as input-mask-ordered GLev entries.
pub struct DcrtGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    input_size: RnsGlweSize,
    output_size: RnsGadgetSize,
}

impl<T: FheUint> DcrtGlweKeySwitchingKey<T> {
    /// Generates a key from a coefficient-domain input key to a DCRT output key.
    pub fn generate<R, M, Table>(
        input_sk: &GlweSecretKey<T>,
        input_params: &CrtGlweParameters<T, M>,
        output_sk: &DcrtGlweSecretKey<T>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let ksk_params = domain.parameters();
        debug_assert_eq!(input_params.poly_length(), ksk_params.poly_length());
        debug_assert_eq!(input_params.cipher_modulus(), ksk_params.cipher_modulus());
        assert_eq!(input_sk.glwe_size(), input_params.size().glwe_size());
        assert_eq!(output_sk.rns_glwe_size(), ksk_params.size().rns_glwe_size());

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
                    domain,
                    rng,
                );
            });

        Self {
            key,
            input_size: input_params.size(),
            output_size: ksk_params.size(),
        }
    }

    /// Returns the input ciphertext sizes bound to this key.
    #[inline]
    pub fn input_size(&self) -> RnsGlweSize {
        self.input_size
    }

    /// Returns the output gadget sizes bound to this key.
    #[inline]
    pub fn output_size(&self) -> RnsGadgetSize {
        self.output_size
    }

    pub(crate) fn iter_dcrt_glev(&self) -> DcrtGlevIter<'_, T> {
        DcrtGlevIter::new(self.key.as_slice(), self.output_size.rns_glev_len())
    }

    /// Applies DCRT GLWE key switching to `input` and writes `output`.
    ///
    /// # Panics
    ///
    /// Panics if the input, output, or reusable context has a layout that is
    /// incompatible with this key.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &CrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        context: &mut DcrtGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(input.as_ref().len(), self.input_size.rns_glwe_len());
        assert_eq!(
            output.as_ref().len(),
            self.output_size.rns_glwe_size().rns_glwe_len()
        );
        assert!(
            context.input_size == self.input_size && context.output_size == self.output_size,
            "DCRT key-switching key and context use incompatible layouts"
        );

        let parameters = domain.parameters();
        let table = domain.table();
        let rns_base = domain.rns_base();
        let basis = parameters.basis();
        let poly_length = self.input_size.poly_length();
        let rns_poly_len = self.input_size.rns_poly_len();
        let DcrtGlweKeySwitchingContext {
            transformed_polynomial,
            glev_context,
            ..
        } = context;

        let (input_mask, input_body) = input.a_b(rns_poly_len);

        output.set_zero();
        self.iter_dcrt_glev()
            .zip(input_mask)
            .for_each(|(key_entry, mask_polynomial)| {
                // Compose directly into the decomposition workspace; the CRT
                // entry point adjusts it in place and overwrites every buffer.
                output.add_dcrt_glev_mul_crt_polynomial_assign(
                    &key_entry,
                    &mask_polynomial,
                    basis,
                    table,
                    rns_base,
                    glev_context,
                );
            });

        transformed_polynomial.copy_from(&input_body);
        table.transform_slice(transformed_polynomial.as_mut());
        output.neg_assign(poly_length, rns_poly_len, rns_base.moduli());

        let (_, output_body) = output.a_b_mut_slices(rns_poly_len);
        DcrtPolynomial(output_body).add_assign(
            &DcrtPolynomial(transformed_polynomial.as_ref()),
            poly_length,
            rns_base.moduli(),
        );
    }
}

/// Reusable workspace for DCRT GLWE key switching.
///
/// Key switching overwrites every internal polynomial and decomposition buffer.
/// Construct this workspace from the domain used by the operations. Reuse with
/// another domain requires the same gadget layout and RNS big-integer limb
/// width; the caller must maintain this compatibility. No rebinding is performed.
pub struct DcrtGlweKeySwitchingContext<T: FheUint> {
    input_size: RnsGlweSize,
    output_size: RnsGadgetSize,
    transformed_polynomial: CrtPolynomial<Vec<T>>,
    glev_context: DcrtGlevMulContext<T>,
}

impl<T: FheUint> DcrtGlweKeySwitchingContext<T> {
    /// Allocates workspace for a DCRT key-switching Domain.
    pub fn new<M, Table>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        input_size: RnsGlweSize,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let output_size = domain.parameters().size();
        let rns_glwe_size = output_size.rns_glwe_size();
        assert_eq!(input_size.poly_length(), rns_glwe_size.poly_length());
        assert_eq!(input_size.moduli_count(), rns_glwe_size.moduli_count());
        Self {
            input_size,
            output_size,
            transformed_polynomial: CrtPolynomial::zero(input_size.rns_poly_len()),
            glev_context: DcrtGlevMulContext::new(output_size, domain.rns_base()),
        }
    }
}
