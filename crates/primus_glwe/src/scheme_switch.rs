//! Scheme switching from GLev to NTT GGSW ciphertexts.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize,
    context::NttExternalProductContext,
    ggsw::{NttGgsw, NttGgswIter},
    glev::Glev,
};
use primus_ntt::NttTable;
use primus_poly::PolynomialOwned;
use primus_reduce::FieldContext;

use crate::secret_key::encode_secret_polynomial_to;
use crate::{GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext, NttGlweSecretKey};

/// Reusable workspace for GLev-to-GGSW scheme switching.
pub struct NttGlweSchemeSwitchContext<T: FheUint> {
    external_product: NttExternalProductContext<T>,
}

impl<T: FheUint> NttGlweSchemeSwitchContext<T> {
    /// Creates workspace for the scheme-switching key's gadget layout.
    pub fn new(key_size: GadgetSize) -> Self {
        Self {
            external_product: NttExternalProductContext::new(key_size),
        }
    }
}

/// NTT GGSW encryptions of the negated GLWE secret polynomials.
///
/// One key ciphertext is stored for every mask row. The GGSW body row is
/// copied directly from the input GLev during evaluation, avoiding an
/// unnecessary encryption of one and external product.
#[derive(Clone)]
pub struct NttGlweSchemeSwitchKey<T: FheUint> {
    data: Vec<T>,
    key_size: GadgetSize,
    output_size: GadgetSize,
    key_basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttGlweSchemeSwitchKey<T> {
    /// Generates a scheme-switching key for one output GGSW layout.
    pub fn generate<M, Table, R>(
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        key_domain: &NttGadgetDomain<'_, T, M, Table>,
        output_size: GadgetSize,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let key_parameters = key_domain.parameters();
        let key_size = key_parameters.size();
        assert_eq!(secret_key.glwe_size(), key_size.glwe_size());
        assert_eq!(ntt_secret_key.glwe_size(), key_size.glwe_size());
        assert_eq!(output_size.glwe_size(), key_size.glwe_size());

        let dimension = key_size.glwe_size().dimension();
        let mut data = vec![T::ZERO; dimension * key_size.ggsw_len()];
        let mut negated_secret = PolynomialOwned::zero(key_size.glwe_size().poly_length());
        let modulus = key_parameters.cipher_modulus();

        for (secret_polynomial, key_ciphertext) in secret_key
            .iter()
            .zip(data.chunks_exact_mut(key_size.ggsw_len()))
        {
            encode_secret_polynomial_to(
                secret_polynomial,
                negated_secret.as_mut(),
                modulus.value(),
            );
            modulus.reduce_neg_slice_assign(negated_secret.as_mut());
            ntt_secret_key.encrypt_ggsw_to(
                &negated_secret,
                &mut NttGgsw::new(key_ciphertext),
                key_domain,
                rng,
                context,
            );
        }

        Self {
            data,
            key_size,
            output_size,
            key_basis: key_domain.basis().clone(),
        }
    }

    /// Returns the scheme-switching key gadget layout.
    #[inline]
    pub fn key_size(&self) -> GadgetSize {
        self.key_size
    }

    /// Returns the output GGSW layout.
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to the scheme-switching key.
    #[inline]
    pub fn key_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_basis
    }

    /// Converts a coefficient-domain GLev into an NTT-domain GGSW.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &Glev<A>,
        output: &mut NttGgsw<B>,
        key_domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweSchemeSwitchContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(
            input.as_ref().len(),
            self.output_size.glev_len(),
            "scheme-switch input GLev layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.output_size.ggsw_len(),
            "scheme-switch output GGSW layout mismatch"
        );
        assert_eq!(
            key_domain.size(),
            self.key_size,
            "scheme-switch key domain mismatch"
        );
        assert_eq!(
            key_domain.basis(),
            &self.key_basis,
            "scheme-switch decomposition basis mismatch"
        );
        assert_eq!(
            context.external_product.size(),
            self.key_size,
            "scheme-switch workspace layout mismatch"
        );

        let glwe_size = self.output_size.glwe_size();
        let poly_length = glwe_size.poly_length();
        let glwe_len = glwe_size.glwe_len();
        let output_glev_len = self.output_size.glev_len();
        let key_basis = key_domain.basis();
        let modulus = key_domain.parameters().cipher_modulus();
        let ntt = key_domain.table();

        let mut output_rows = output.iter_ntt_glev_mut(output_glev_len);
        for (key, mut output_row) in
            NttGgswIter::new(&self.data, self.key_size.ggsw_len()).zip(&mut output_rows)
        {
            for (input_glwe, mut output_glwe) in input
                .iter_glwe(glwe_len)
                .zip(output_row.iter_ntt_glwe_mut(glwe_len))
            {
                key.external_product_ntt_to(
                    &input_glwe,
                    &mut output_glwe,
                    key_basis,
                    modulus,
                    ntt,
                    &mut context.external_product,
                );
            }
        }

        let mut body_row = output_rows
            .next()
            .expect("scheme-switch output is missing its body row");
        for (input_glwe, mut output_glwe) in input
            .iter_glwe(glwe_len)
            .zip(body_row.iter_ntt_glwe_mut(glwe_len))
        {
            output_glwe.as_mut().copy_from_slice(input_glwe.as_ref());
            for polynomial in output_glwe.as_mut().chunks_exact_mut(poly_length) {
                ntt.transform_slice(polynomial);
            }
        }
        debug_assert!(output_rows.next().is_none());
    }
}
