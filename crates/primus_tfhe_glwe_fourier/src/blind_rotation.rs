//! Fourier blind-rotation APIs, kernels, and workspace.

use primus_data::{Data, DataMut};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    GadgetSize, context::FourierGlweExternalProductContext, glwe::TorusGlwe, lwe::Lwe,
};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::PrepareModulusSwitch;
use primus_tfhe::backend_support::{RotationQuantizer, direct_exponent};

use crate::FourierGlweBootstrappingKey;

impl<T, LM> FourierGlweBootstrappingKey<T, LM>
where
    T: TorusFftValue,
    LM: PrepareModulusSwitch<ValueT = T>,
{
    /// Blind-rotates a native-torus GLWE accumulator using this key.
    ///
    /// Uses this key's stored layout and decomposition basis.
    ///
    /// # Correctness
    ///
    /// Input LWE coefficients must be canonical under this key's input modulus.
    /// Use the FFT table instance with which this key was generated; matching
    /// polynomial lengths do not establish compatible Fourier representations.
    ///
    /// # Panics
    ///
    /// Panics if input, accumulator, output or workspace layouts, or the FFT
    /// polynomial length do not match the key. Checks precede output writes.
    pub fn fourier_blind_rotate_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let quantizer = self.input_quantizer();
        self.blind_rotate_with(input, accumulator, output, fft, context, |x| {
            quantizer.exponent(x)
        });
    }

    /// Blind-rotates an encoded lookup-table polynomial as a trivial GLWE
    /// accumulator.
    ///
    /// Inherits [`Self::fourier_blind_rotate_to`]'s input, transform and
    /// workspace requirements. The lookup polynomial must have N native-torus
    /// coefficients; an incorrect length panics before output writes.
    pub fn fourier_blind_rotate_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len()),
            "blind-rotation input, lookup table or output layout mismatch"
        );
        self.assert_compatible(fft, context);
        self.fourier_blind_rotate_lookup_table_kernel_to(input, lookup_table, output, fft, context);
    }

    /// Requires resources and per-call layouts validated by the public BR/PBS
    /// entry, or fixed by circuit-bootstrap construction. No release rechecks.
    pub(crate) fn fourier_blind_rotate_lookup_table_kernel_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        let two_n = poly_length * 2;
        debug_assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len()),
            "blind-rotation input, lookup table or output layout mismatch"
        );

        let quantizer = self.input_quantizer();
        let exponent_of = |value| quantizer.exponent(value);
        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(
            initial_exponent,
            &mut Polynomial(body),
            NativeModulus::new(),
        );
        self.blind_rotate_initialized(input, output, fft, context, exponent_of);
    }

    /// Blind-rotates an interleaved PBSManyLUT accumulator.
    ///
    /// Each input coefficient is quantized directly to `2N / rotation_step`, then
    /// multiplied by `rotation_step`, preserving the independent output columns.
    /// `rotation_step` is the LUT padded output count: a nonzero power of two
    /// dividing `N`.
    ///
    /// Inherits [`Self::fourier_blind_rotate_lookup_table_to`]'s requirements.
    /// An invalid rotation step panics before output writes.
    pub fn fourier_blind_rotate_interleaved_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        assert!(
            rotation_step.is_power_of_two() && poly_length.is_multiple_of(rotation_step),
            "PBSManyLUT rotation step must be a non-zero power-of-two divisor of N"
        );
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len()),
            "PBSManyLUT input, table, or output layout mismatch"
        );
        self.assert_compatible(fft, context);
        self.fourier_blind_rotate_interleaved_lookup_table_kernel_to(
            input,
            lookup_table,
            rotation_step,
            output,
            fft,
            context,
        );
    }

    /// Requires resources and per-call layouts validated by the public BR/PBS
    /// entry, or fixed by circuit-bootstrap construction.
    pub(crate) fn fourier_blind_rotate_interleaved_lookup_table_kernel_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        let two_n = poly_length * 2;
        debug_assert!(
            rotation_step.is_power_of_two() && poly_length.is_multiple_of(rotation_step),
            "PBSManyLUT rotation step must be a non-zero power-of-two divisor of N"
        );
        debug_assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len()),
            "PBSManyLUT input, table, or output layout mismatch"
        );

        let input_modulus = self.input_modulus();
        let quantizer = if rotation_step == 1 {
            self.input_quantizer()
        } else {
            RotationQuantizer::new(input_modulus, two_n, rotation_step)
        };
        let exponent_of = |value| quantizer.exponent(value);
        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(
            initial_exponent,
            &mut Polynomial(body),
            NativeModulus::new(),
        );
        self.blind_rotate_initialized(input, output, fft, context, exponent_of);
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    ///
    /// Inherits [`Self::fourier_blind_rotate_to`]'s transform and workspace
    /// requirements, using exponent coefficients instead of the input modulus.
    ///
    /// # Correctness
    ///
    /// Every input coefficient must lie in `[0, 2N)`; this range is not checked
    /// in release builds.
    pub fn fourier_blind_rotate_exponents_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let two_n = 2 * self.size().glwe_size().poly_length();
        self.blind_rotate_with(input, accumulator, output, fft, context, |x| {
            direct_exponent(x, two_n)
        });
    }

    /// Validates resources and rotates the initial accumulator before the CMUX loop.
    fn blind_rotate_with<Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
        exponent_of: F,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
        F: Fn(T) -> usize,
    {
        let poly_length = self.size().glwe_size().poly_length();
        let two_n = 2 * poly_length;
        assert_eq!(
            (
                input.dimension(),
                accumulator.as_ref().len(),
                output.as_ref().len(),
            ),
            (
                self.input_dimension(),
                self.size().glwe_len(),
                self.size().glwe_len(),
            ),
            "blind-rotation input, accumulator or output layout mismatch"
        );

        self.assert_compatible(fft, context);
        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        accumulator.mul_monomial_to(initial_exponent, output, poly_length, NativeModulus::new());
        self.blind_rotate_initialized(input, output, fft, context, exponent_of);
    }

    /// Checks evaluation resources before initializing the output accumulator.
    fn assert_compatible<Table: FftTable>(
        &self,
        fft: &FftEngine<'_, Table>,
        context: &FourierGlweBlindRotationContext<T>,
    ) {
        assert_eq!(
            fft.poly_length(),
            self.size().glwe_size().poly_length(),
            "blind-rotation FFT polynomial length mismatch"
        );
        assert_eq!(
            context.external_product.size(),
            self.size(),
            "blind-rotation workspace gadget layout mismatch"
        );
        debug_assert_eq!(
            context.scratch.as_ref().len(),
            self.size().glwe_len(),
            "blind-rotation workspace GLWE layout mismatch"
        );
    }

    /// Rotates an initialized accumulator after layouts and resources have been checked.
    fn blind_rotate_initialized<Table, A, C, F>(
        &self,
        input: &Lwe<A>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
        exponent_of: F,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        F: Fn(T) -> usize,
    {
        let FourierGlweBlindRotationContext {
            scratch,
            external_product,
        } = context;
        let mut output_is_current = true;
        for (&coefficient, control) in input.a().iter().zip(self.iter_fourier_ggsw()) {
            let exponent = exponent_of(coefficient);
            if exponent == 0 {
                continue;
            }
            if output_is_current {
                control.cmux_monomial_to(
                    output,
                    exponent,
                    scratch,
                    self.basis(),
                    fft,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    self.basis(),
                    fft,
                    external_product,
                );
            }
            output_is_current = !output_is_current;
        }
        if !output_is_current {
            output.as_mut().copy_from_slice(scratch.as_ref());
        }
    }
}

/// Reusable workspace for Fourier blind rotation.
pub struct FourierGlweBlindRotationContext<T: TorusFftValue> {
    scratch: TorusGlwe<Vec<T>>,
    external_product: FourierGlweExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierGlweBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        Self {
            scratch: TorusGlwe::zero(size.glwe_len()),
            external_product: FourierGlweExternalProductContext::new(size),
        }
    }

    /// Rebinds the workspace to another decomposition layout without reallocating.
    pub fn rebind(&mut self, size: GadgetSize) {
        self.external_product.rebind(size);
    }

    /// Rebinds the workspace to a new GLWE layout.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.external_product.size().glwe_size() == size.glwe_size() {
            self.rebind(size);
            return;
        }
        self.external_product.resize(size);
        self.scratch.0.resize(size.glwe_len(), T::ZERO);
    }
}
