//! Single-modulus GLWE key switching in the NTT domain.

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::{NttGlev, NttGlevIter},
    glwe::{Glwe, NttGlwe},
};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, PolynomialOwned};
use primus_reduce::FieldContext;

use crate::glwe::secret_key::encode_secret_polynomial_to;
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

    /// Returns the raw NTT-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    fn iter(&self) -> NttGlevIter<'_, T> {
        NttGlevIter::new(&self.data, self.output_size.glev_len())
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
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let parameters = domain.parameters();
        let ntt = domain.table();
        let modulus = parameters.cipher_modulus();
        let basis = domain.basis();
        let poly_length = self.input_size.poly_length();
        let glwe_len = self.output_size.glwe_len();
        let (input_mask, input_body) = input.a_b_slices(poly_length);

        context.accumulator.set_zero();
        for (mask_poly, entry) in input_mask.chunks_exact(poly_length).zip(self.iter()) {
            basis.init_value_carry_slice_to(
                mask_poly,
                &mut context.adjusted_poly,
                &mut context.carries,
            );

            for (decomposer, key_glwe) in basis.decompose_iter().zip(entry.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    &context.adjusted_poly,
                    &mut context.decomposed_ntt,
                    &mut context.carries,
                );
                ntt.transform_slice(&mut context.decomposed_ntt);
                context.accumulator.add_mul_ntt_polynomial_assign(
                    &NttPolynomial::new(context.decomposed_ntt.as_slice()),
                    &key_glwe,
                    modulus,
                );
            }
        }

        context.accumulator.write_coeff_form(output, ntt);
        modulus.reduce_neg_slice_assign(output.as_mut());
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
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
        A: RawData<Elem = T> + Data,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, domain, context);
        output
    }
}

/// Reusable NTT GLWE key-switching workspace.
pub struct NttGlweKeySwitchingContext<T: FheUint> {
    adjusted_poly: Vec<T>,
    carries: Vec<bool>,
    decomposed_ntt: Vec<T>,
    accumulator: NttGlwe<Vec<T>>,
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
}
