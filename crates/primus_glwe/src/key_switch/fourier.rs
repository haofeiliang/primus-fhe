//! Single-modulus GLWE key switching in the Fourier domain.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::FourierGlev,
    glwe::{FourierGlwe, Glwe},
};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, PolynomialOwned};
use primus_reduce::{ReduceAddSlice, ReduceNegSlice};

use crate::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters, GlweSecretKey};

/// A Fourier-domain GLWE key-switching key for the native torus modulus.
#[derive(Clone)]
pub struct FourierGlweKeySwitchingKey {
    data: Vec<Complex64>,
    input_size: GlweSize,
    output_size: GadgetSize,
}

impl FourierGlweKeySwitchingKey {
    /// Generates a Fourier GLWE key-switching key.
    pub fn generate<T, Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &FourierGlweSecretKey,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
        T: TorusFftValue,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        let output = parameters;
        assert_eq!(input_secret_key.poly_length(), output.poly_length());
        assert_eq!(output_secret_key.glwe_size(), output.glwe_size());
        assert_eq!(fft.poly_length(), output.poly_length());

        let input_size = input_secret_key.glwe_size();
        let output_size = output.size();
        let fourier_glev_len = output_size.fourier_glev_len();

        let mut data = vec![Complex64::default(); input_size.dimension() * fourier_glev_len];
        let mut encoded_secret: PolynomialOwned<T> = PolynomialOwned::zero(output.poly_length());

        for (secret_poly, entry) in input_secret_key
            .iter()
            .zip(data.chunks_exact_mut(fourier_glev_len))
        {
            encoded_secret
                .as_mut()
                .iter_mut()
                .zip(secret_poly)
                .for_each(|(output, &coefficient)| {
                    *output = coefficient.cast_to_unsigned();
                });
            output_secret_key.encrypt_glev_to(
                &encoded_secret,
                &mut FourierGlev::new(entry),
                output,
                fft,
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

    /// Returns the raw Fourier-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Key-switches a coefficient-domain native-torus GLWE ciphertext.
    pub fn key_switch_to<T, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let basis = parameters.basis();
        let poly_length = self.input_size.poly_length();
        let (input_mask, input_body) = input.a_b_slices(poly_length);
        let fourier_glwe_len = self.output_size.glwe_size().fourier_glwe_len();

        context.accumulator.set_zero();
        for (mask_poly, entry) in input_mask
            .chunks_exact(poly_length)
            .zip(self.data.chunks_exact(self.output_size.fourier_glev_len()))
        {
            basis.init_carry_slice(mask_poly, &mut context.carries);
            let entry = FourierGlev::new(entry);
            for (decomposer, key_glwe) in basis
                .decompose_iter()
                .zip(entry.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    mask_poly,
                    &mut context.decomposed_poly,
                    &mut context.carries,
                );
                fft.forward_as_integer(&context.decomposed_poly, &mut context.decomposed_fourier);
                context.accumulator.add_mul_fourier_poly_assign(
                    &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                    &key_glwe,
                );
            }
        }

        context.accumulator.write_torus_form(output, fft);
        let modulus = NativeModulus::new();
        modulus.reduce_neg_slice_assign(output.as_mut());
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    pub fn key_switch<T, Table, A>(
        &self,
        input: &Glwe<A>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) -> Glwe<Vec<T>>
    where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, parameters, fft, context);
        output
    }
}

/// Reusable Fourier GLWE key-switching workspace.
pub struct FourierGlweKeySwitchingContext<T: TorusFftValue> {
    carries: Vec<bool>,
    decomposed_poly: Vec<T>,
    decomposed_fourier: Vec<Complex64>,
    accumulator: FourierGlwe<Vec<Complex64>>,
}

impl<T: TorusFftValue> FourierGlweKeySwitchingContext<T> {
    /// Creates a workspace for the output GLWE layout.
    pub fn new(glwe_size: GlweSize) -> Self {
        let poly_length = glwe_size.poly_length();
        Self {
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: vec![Complex64::default(); glwe_size.fourier_poly_len()],
            accumulator: FourierGlwe::zero(glwe_size.fourier_glwe_len()),
        }
    }
}
