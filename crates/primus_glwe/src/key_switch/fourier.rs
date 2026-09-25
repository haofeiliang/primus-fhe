//! Single-modulus GLWE key switching in the Fourier domain.

use aligned_vec::{AVec, avec};
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::FourierGlev,
    glwe::{FourierGlwe, Glwe},
};
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, Polynomial};
use primus_reduce::ReduceAddSlice;
use zeroize::Zeroizing;

use crate::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters, GlweSecretKey};

/// A Fourier-domain GLWE key-switching key for the native torus modulus.
#[derive(Clone)]
pub struct FourierGlweKeySwitchingKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    input_size: GlweSize,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierGlweKeySwitchingKey<T> {
    /// Generates a Fourier GLWE key-switching key.
    ///
    /// # Correctness
    ///
    /// `output_secret_key` must have been constructed with the supplied FFT table instance.
    ///
    /// # Panics
    ///
    /// Panics if input/output polynomial lengths, the output key layout, FFT,
    /// or gadget workspace do not match `parameters`.
    pub fn generate<Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &FourierGlweSecretKey,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
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
        let mut encoded_secret = Zeroizing::new(vec![T::ZERO; output.poly_length()]);

        for (secret_poly, entry) in input_secret_key
            .iter()
            .zip(data.chunks_exact_mut(fourier_glev_len))
        {
            encoded_secret
                .as_mut_slice()
                .iter_mut()
                .zip(secret_poly)
                .for_each(|(output, &coefficient)| {
                    *output = coefficient.cast_to_unsigned();
                });
            output_secret_key.encrypt_glev_to(
                &Polynomial::new(encoded_secret.as_slice()),
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
            basis: output.basis().clone(),
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

    /// Returns the output gadget layout bound to this key.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to this key and integer width.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw Fourier-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Key-switches a coefficient-domain native-torus GLWE ciphertext.
    ///
    /// Uses the decomposition basis and layouts stored during key generation.
    ///
    /// # Correctness
    ///
    /// The FFT must use the table instance used during key generation.
    /// Floating-point and decomposition errors must fit the caller's precision budget.
    ///
    /// # Panics
    ///
    /// Panics if the input/output layouts, FFT length,
    /// or workspace layout are incompatible. Checks precede output writes.
    pub fn key_switch_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        self.assert_compatible(fft, context);
        self.key_switch_kernel_to(input, output, fft, context);
    }

    /// Validates the transform and private workspace before composite evaluation.
    pub(crate) fn assert_compatible<Table: FftTable>(
        &self,
        fft: &FftEngine<'_, Table>,
        context: &FourierGlweKeySwitchingContext<T>,
    ) {
        let poly_length = self.input_size.poly_length();
        assert_eq!(
            fft.poly_length(),
            poly_length,
            "FFT polynomial length mismatch"
        );
        assert_eq!(
            context.accumulator.as_ref().len(),
            self.output_size.glwe_size().fourier_glwe_len(),
            "key-switch workspace layout mismatch"
        );
        assert_eq!(
            context.decomposed_poly.len(),
            poly_length,
            "key-switch workspace polynomial length mismatch"
        );
    }

    /// Switches after input/output, transform and workspace have been validated.
    pub(crate) fn key_switch_kernel_to<Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = self.poly_length();
        let (input_mask, input_body) = input.a_b_slices(poly_length);
        self.accumulate_mask_kernel(input_mask, fft, context);

        context.accumulator.write_torus_form(output, fft);
        let modulus = NativeModulus::new();
        output.neg_assign(modulus);
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches validated coefficient masks and a Fourier body into Fourier
    /// output, retaining the accumulator in frequency form. Inputs use this key's
    /// layouts and FFT representation; the owning boundary checks compatibility.
    pub(crate) fn key_switch_fourier_kernel_to<Table, A, B>(
        &self,
        input_mask: &[T],
        input_body: &FourierPolynomial<A>,
        output: &mut FourierGlwe<B>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        self.accumulate_mask_kernel(input_mask, fft, context);
        let (acc_mask, acc_body) = context.accumulator.a_b_slices(fft.fourier_length());
        let (output_mask, output_body) = output.a_b_mut_slices(fft.fourier_length());
        for (output, &acc) in output_mask.iter_mut().zip(acc_mask) {
            *output = -acc;
        }
        for ((output, &body), &acc) in output_body
            .iter_mut()
            .zip(input_body.as_ref())
            .zip(acc_body)
        {
            *output = body - acc;
        }
    }

    /// Computes the positive switching-key product after layout/backend validation.
    fn accumulate_mask_kernel<Table: FftTable>(
        &self,
        input_mask: &[T],
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) {
        let poly_length = self.poly_length();
        let basis = &self.basis;
        let fourier_glwe_len = self.output_size.glwe_size().fourier_glwe_len();
        context.accumulator.set_zero();
        for (mask_poly, entry) in input_mask
            .chunks_exact(poly_length)
            .zip(self.data.chunks_exact(self.output_size.fourier_glev_len()))
        {
            basis.init_carry_slice(mask_poly, &mut context.carries);
            let entry = FourierGlev::new(entry);
            for (decomposer, key_glwe) in basis
                .decomposer_iter()
                .zip(entry.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    mask_poly,
                    &mut context.decomposed_poly,
                    &mut context.carries,
                );
                fft.forward_as_integer(&context.decomposed_poly, &mut context.decomposed_fourier);
                context.accumulator.add_mul_fourier_polynomial_assign(
                    &key_glwe,
                    &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                );
            }
        }
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    /// Inherits [`Self::key_switch_to`]'s representation and precision requirements.
    ///
    /// # Panics
    ///
    /// Panics on the compatibility mismatches described by [`Self::key_switch_to`].
    pub fn key_switch<Table, A>(
        &self,
        input: &Glwe<A>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweKeySwitchingContext<T>,
    ) -> Glwe<Vec<T>>
    where
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, fft, context);
        output
    }
}

/// Reusable Fourier workspace for GLWE key switching and LWE packing key switching.
/// Owned Fourier buffers use cache-line alignment for repeated FFT and product passes.
pub struct FourierGlweKeySwitchingContext<T: TorusFftValue> {
    pub(crate) carries: Vec<bool>,
    pub(crate) decomposed_poly: Vec<T>,
    pub(crate) decomposed_fourier: AVec<Complex64>,
    pub(crate) accumulator: FourierGlwe<AVec<Complex64>>,
}

impl<T: TorusFftValue> FourierGlweKeySwitchingContext<T> {
    /// Creates a workspace for the output GLWE layout.
    pub fn new(glwe_size: GlweSize) -> Self {
        let poly_length = glwe_size.poly_length();
        Self {
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: avec![Complex64::default(); glwe_size.fourier_poly_len()],
            accumulator: FourierGlwe(avec![
                Complex64::default();
                glwe_size.fourier_glwe_len()
            ]),
        }
    }
}
