//! Single-modulus GLWE key switching in the NTT domain.

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_lattice::{
    glev::NttGlev,
    glwe::{Glwe, NttGlwe},
};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, PolynomialOwned};
use primus_reduce::FieldContext;

use crate::glwe::secret_key::encode_secret_polynomial_to;
use crate::{GlweKeySwitchingParameters, GlweSecretKey, NttGadgetEncryptContext, NttGlweSecretKey};

/// An NTT-domain GLWE key-switching key.
///
/// Storage is ordered by input secret polynomial. Every entry is a GLev
/// encryption of that polynomial under the output GLWE secret key.
#[derive(Clone)]
pub struct NttGlweKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: usize,
    output_dimension: usize,
    poly_length: usize,
    glev_len: usize,
}

impl<T: FheUint> NttGlweKeySwitchingKey<T> {
    /// Generates an NTT GLWE key-switching key.
    pub fn generate<M, Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
        parameters: &GlweKeySwitchingParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(input_secret_key.dimension(), parameters.input_dimension());
        assert_eq!(input_secret_key.poly_length(), parameters.poly_length());
        assert_eq!(output_secret_key.dimension(), parameters.output_dimension());
        assert_eq!(output_secret_key.poly_length(), parameters.poly_length());
        assert_eq!(ntt.poly_length(), parameters.poly_length());

        let output = parameters.output();
        let glev_len = output.glev_len();
        let mut data = vec![T::ZERO; parameters.key_len()];
        let mut encoded_secret: PolynomialOwned<T> =
            PolynomialOwned::zero(parameters.poly_length());
        for (secret_poly, entry) in input_secret_key.iter().zip(data.chunks_exact_mut(glev_len)) {
            encode_secret_polynomial_to(
                secret_poly,
                encoded_secret.as_mut(),
                output
                    .cipher_modulus()
                    .value()
                    .expect("NTT key switching requires an explicit modulus"),
            );
            output_secret_key.encrypt_glev_to(
                &encoded_secret,
                &mut NttGlev::new(entry),
                output,
                ntt,
                rng,
                context,
            );
        }

        Self {
            data,
            input_dimension: parameters.input_dimension(),
            output_dimension: parameters.output_dimension(),
            poly_length: parameters.poly_length(),
            glev_len,
        }
    }

    /// Returns the input GLWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the output GLWE dimension.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output_dimension
    }

    /// Returns the polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the raw NTT-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Key-switches a coefficient-domain GLWE ciphertext into `output`.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        parameters: &GlweKeySwitchingParameters<T, M>,
        ntt: &Table,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.assert_shapes(input.as_ref().len(), output.as_ref().len(), parameters, ntt);
        context.assert_shape(self.output_dimension, self.poly_length);

        let modulus = parameters.output().cipher_modulus();
        let basis = parameters.output().basis();
        let (input_mask, input_body) = input.a_b_slices(self.poly_length);

        context.accumulator.set_zero();
        for (mask_poly, entry) in input_mask
            .chunks_exact(self.poly_length)
            .zip(self.data.chunks_exact(self.glev_len))
        {
            basis.init_value_carry_slice_to(
                mask_poly,
                &mut context.adjusted_poly,
                &mut context.carries,
            );
            let entry = NttGlev::new(entry);
            for (decomposer, key_glwe) in basis
                .decompose_iter()
                .zip(entry.iter_ntt_glwe(parameters.output().glwe_len()))
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
        let (_, output_body) = output.a_b_mut_slices(self.poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    pub fn key_switch<M, Table, A>(
        &self,
        input: &Glwe<A>,
        parameters: &GlweKeySwitchingParameters<T, M>,
        ntt: &Table,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) -> Glwe<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
    {
        let mut output = Glwe::zero((self.output_dimension + 1) * self.poly_length);
        self.key_switch_to(input, &mut output, parameters, ntt, context);
        output
    }

    fn assert_shapes<M, Table>(
        &self,
        input_len: usize,
        output_len: usize,
        parameters: &GlweKeySwitchingParameters<T, M>,
        ntt: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(self.input_dimension, parameters.input_dimension());
        assert_eq!(self.output_dimension, parameters.output_dimension());
        assert_eq!(self.poly_length, parameters.poly_length());
        assert_eq!(self.glev_len, parameters.output().glev_len());
        assert_eq!(ntt.poly_length(), self.poly_length);
        assert_eq!(
            parameters.output().basis().modulus(),
            parameters.output().cipher_modulus().value()
        );
        assert_eq!(input_len, (self.input_dimension + 1) * self.poly_length);
        assert_eq!(output_len, (self.output_dimension + 1) * self.poly_length);
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
    pub fn new(output_dimension: usize, poly_length: usize) -> Self {
        assert!(output_dimension > 0);
        assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            accumulator: NttGlwe::zero((output_dimension + 1) * poly_length),
        }
    }

    fn assert_shape(&self, output_dimension: usize, poly_length: usize) {
        assert_eq!(self.adjusted_poly.len(), poly_length);
        assert_eq!(self.carries.len(), poly_length);
        assert_eq!(self.decomposed_ntt.len(), poly_length);
        assert_eq!(
            self.accumulator.as_ref().len(),
            (output_dimension + 1) * poly_length
        );
    }
}
