//! Single-modulus GLWE key switching in the NTT domain.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::{NttGlev, NttGlevIter},
    glwe::{Glwe, NttGlwe},
};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, PolynomialOwned};
use primus_reduce::FieldContext;

use crate::secret_key::encode_secret_polynomial_to;
use crate::{GlweSecretKey, NttGadgetDomain, NttGadgetEncryptContext, NttGlweSecretKey};

/// An NTT-domain GLWE key-switching key.
///
/// Storage is ordered by input secret polynomial. Every entry is a GLev
/// encryption of that polynomial under the output GLWE secret key.
#[derive(Clone)]
pub struct NttGlweKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_size: GlweSize,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttGlweKeySwitchingKey<T> {
    /// Generates an NTT GLWE key-switching key.
    pub fn generate<M, Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let output = domain.parameters();
        assert_eq!(input_secret_key.poly_length(), output.poly_length());
        assert_eq!(output_secret_key.glwe_size(), output.glwe_size());

        let input_size = input_secret_key.glwe_size();
        let output_size = output.size();
        let glev_len = output_size.glev_len();

        let mut data = vec![T::ZERO; input_size.dimension() * glev_len];
        let mut encoded_secret: PolynomialOwned<T> = PolynomialOwned::zero(output.poly_length());

        for (secret_poly, entry) in input_secret_key.iter().zip(data.chunks_exact_mut(glev_len)) {
            encode_secret_polynomial_to(
                secret_poly,
                encoded_secret.as_mut(),
                output.cipher_modulus().value(),
            );
            output_secret_key.encrypt_glev_to(
                &encoded_secret,
                &mut NttGlev::new(entry),
                domain,
                rng,
                context,
            );
        }

        Self {
            data,
            input_size,
            output_size,
            basis: domain.basis().clone(),
        }
    }

    /// Returns the input GLWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_size.dimension()
    }

    /// Returns the output GLWE dimension.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output_size.glwe_size().dimension()
    }

    /// Returns the polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.input_size.poly_length()
    }

    /// Returns the input layout bound to this key.
    #[inline]
    pub fn input_size(&self) -> GlweSize {
        self.input_size
    }

    /// Returns the output gadget layout bound to this key.
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw NTT-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    fn iter(&self) -> NttGlevIter<'_, T> {
        NttGlevIter::new(&self.data, self.output_size.glev_len())
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    pub fn key_switch<M, Table, A>(
        &self,
        input: &Glwe<A>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) -> Glwe<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, domain, context);
        output
    }

    /// Key-switches a coefficient-domain GLWE ciphertext into `output`.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());
        self.assert_compatible(domain, context);

        self.key_switch_kernel_to(input, output, domain, context);
    }

    /// Key-switches a validated coefficient-domain GLWE ciphertext.
    ///
    /// The caller must have validated the ciphertext layouts, domain, and
    /// workspace with [`Self::assert_compatible`].
    pub(crate) fn key_switch_kernel_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        debug_assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let parameters = domain.parameters();
        let ntt = domain.table();
        let modulus = parameters.cipher_modulus();
        let poly_length = self.input_size.poly_length();
        let (input_mask, input_body) = input.a_b_slices(poly_length);

        let mut context = context.as_mut();
        self.mask_product_to_accumulator(input_mask, domain, &mut context);
        context.accumulator.write_coeff_form(output, ntt);
        modulus.reduce_neg_slice_assign(output.as_mut());
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches a validated coefficient-domain mask and NTT-domain body
    /// directly into an NTT GLWE.
    ///
    /// The output is overwritten with `(0, body) - sum_i mask_i * KSK_i`.
    /// The caller must have validated the layouts, domain, and workspace with
    /// [`Self::assert_compatible`].
    pub(crate) fn key_switch_ntt_kernel_to<M, Table, A, B>(
        &self,
        input_mask: &[T],
        input_body: &NttPolynomial<A>,
        output: &mut NttGlwe<B>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(input_mask.len(), self.input_size.mask_len());
        debug_assert_eq!(input_body.as_ref().len(), self.input_size.poly_length());
        debug_assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let modulus = domain.parameters().cipher_modulus();
        let poly_length = self.input_size.poly_length();
        let mut context = context.as_mut_with_accumulator(output);
        self.mask_product_to_accumulator(input_mask, domain, &mut context);
        modulus.reduce_neg_slice_assign(context.accumulator.as_mut());
        let (_, output_body) = context.accumulator.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body.as_ref());
    }

    /// Validates the domain and reusable workspace shared by both output paths.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            domain.size(),
            self.output_size,
            "key-switch domain mismatch"
        );
        assert_eq!(
            domain.basis(),
            &self.basis,
            "key-switch decomposition basis mismatch"
        );
        assert_eq!(
            context.accumulator.as_ref().len(),
            self.output_size.glwe_len(),
            "key-switch workspace layout mismatch"
        );
        assert_eq!(
            context.adjusted_poly.len(),
            self.input_size.poly_length(),
            "key-switch workspace polynomial length mismatch"
        );
    }

    /// Clears the selected NTT accumulator and stores the positive mask
    /// product `sum_i mask_i * KSK_i` in it.
    ///
    /// The caller handles the final negation and body addition.
    fn mask_product_to_accumulator<M, Table>(
        &self,
        input_mask: &[T],
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttGlweKeySwitchingContextRefMut<'_, T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let parameters = domain.parameters();
        let table = domain.table();
        let modulus = parameters.cipher_modulus();
        let basis = domain.basis();
        let poly_length = self.input_size.poly_length();
        let glwe_len = self.output_size.glwe_len();

        context.accumulator.set_zero();
        for (mask_poly, entry) in input_mask.chunks_exact(poly_length).zip(self.iter()) {
            basis.init_value_carry_slice_to(mask_poly, context.adjusted_poly, context.carries);

            for (decomposer, key_glwe) in basis.decomposer_iter().zip(entry.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    context.adjusted_poly,
                    context.decomposed_ntt,
                    context.carries,
                );
                table.transform_slice(context.decomposed_ntt);
                context.accumulator.add_mul_ntt_polynomial_assign(
                    &NttPolynomial::new(&*context.decomposed_ntt),
                    &key_glwe,
                    modulus,
                );
            }
        }
    }
}

/// Reusable NTT GLWE key-switching workspace.
pub struct NttGlweKeySwitchingContext<T: FheUint> {
    adjusted_poly: Vec<T>,
    carries: Vec<bool>,
    decomposed_ntt: Vec<T>,
    accumulator: NttGlwe<Vec<T>>,
}

/// Mutable view of key-switch scratch with a replaceable NTT accumulator.
struct NttGlweKeySwitchingContextRefMut<'a, T: FheUint> {
    adjusted_poly: &'a mut [T],
    carries: &'a mut [bool],
    decomposed_ntt: &'a mut [T],
    accumulator: NttGlwe<&'a mut [T]>,
}

impl<T: FheUint> NttGlweKeySwitchingContext<T> {
    /// Creates a workspace for the output GLWE layout.
    pub fn new(glwe_size: GlweSize) -> Self {
        let poly_length = glwe_size.poly_length();
        Self {
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            accumulator: NttGlwe::zero(glwe_size.glwe_len()),
        }
    }

    #[inline]
    fn as_mut(&mut self) -> NttGlweKeySwitchingContextRefMut<'_, T> {
        NttGlweKeySwitchingContextRefMut {
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            accumulator: NttGlwe(self.accumulator.as_mut()),
        }
    }

    #[inline]
    fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut NttGlwe<S>,
    ) -> NttGlweKeySwitchingContextRefMut<'a, T>
    where
        S: DataMut<Elem = T>,
    {
        NttGlweKeySwitchingContextRefMut {
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            accumulator: NttGlwe(accumulator.as_mut()),
        }
    }
}
