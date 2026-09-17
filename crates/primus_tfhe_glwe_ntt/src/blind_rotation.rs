//! NTT blind-rotation APIs, kernels, and workspace.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize,
    context::{NttGlweExternalProductContext, NttGlweTernaryCmuxContext},
    glwe::Glwe,
    lwe::Lwe,
};
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::{FieldContext, PrepareModulusSwitch};
use primus_tfhe::rotation::RotationQuantizer;

use crate::NttGlweBootstrappingKey;

impl<T: FheUint, LM: PrepareModulusSwitch<ValueT = T>> NttGlweBootstrappingKey<T, LM> {
    /// Blind-rotates an explicit-modulus GLWE accumulator using this key.
    ///
    /// Uses this key's stored layout and decomposition basis.
    ///
    /// # Correctness
    ///
    /// Input LWE coefficients must be canonical under this key's input modulus.
    /// The accumulator must contain canonical coefficients modulo `modulus`.
    /// The table must use the NTT representation used to generate this key.
    ///
    /// # Panics
    ///
    /// Panics if input/output/accumulator or workspace layouts, the modulus,
    /// or the NTT length/modulus do not match the key. Compatibility checks
    /// precede output writes.
    pub fn ntt_blind_rotate_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let quantizer = self.input_quantizer();
        self.blind_rotate_with(input, accumulator, output, modulus, ntt, context, |x| {
            quantizer.exponent(x)
        });
    }

    /// Blind-rotates an encoded lookup-table polynomial as a trivial GLWE
    /// accumulator.
    ///
    /// Inherits [`Self::ntt_blind_rotate_to`]'s modulus, transform and workspace
    /// requirements. The lookup polynomial must have N canonical coefficients;
    /// an incorrect length panics before output writes.
    pub fn ntt_blind_rotate_lookup_table_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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
        self.assert_compatible(modulus, ntt, context);
        self.ntt_blind_rotate_lookup_table_kernel_to(
            input,
            lookup_table,
            output,
            modulus,
            ntt,
            context,
        );
    }

    /// Requires resources and per-call layouts validated by the public BR/PBS
    /// entry, or fixed by circuit-bootstrap construction. No release rechecks.
    pub(crate) fn ntt_blind_rotate_lookup_table_kernel_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);
        self.blind_rotate_initialized(input, output, modulus, ntt, context, exponent_of);
    }

    /// Blind-rotates an interleaved PBSManyLUT accumulator.
    ///
    /// Each input coefficient is quantized directly to `2N / rotation_step`, then
    /// multiplied by `rotation_step`, preserving the independent output columns.
    /// `rotation_step` is the LUT padded output count: a nonzero power of two
    /// dividing `N`.
    ///
    /// Inherits [`Self::ntt_blind_rotate_lookup_table_to`]'s requirements.
    /// An invalid rotation step panics before output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep modulus, transform and workspace roles explicit"
    )]
    pub fn ntt_blind_rotate_interleaved_lookup_table_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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
        self.assert_compatible(modulus, ntt, context);
        self.ntt_blind_rotate_interleaved_lookup_table_kernel_to(
            input,
            lookup_table,
            rotation_step,
            output,
            modulus,
            ntt,
            context,
        );
    }

    /// Requires resources and per-call layouts validated by the public BR/PBS
    /// entry, or fixed by circuit-bootstrap construction.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep modulus, transform and workspace roles explicit"
    )]
    pub(crate) fn ntt_blind_rotate_interleaved_lookup_table_kernel_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);
        self.blind_rotate_initialized(input, output, modulus, ntt, context, exponent_of);
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    ///
    /// Inherits [`Self::ntt_blind_rotate_to`]'s compatibility requirements.
    ///
    /// # Correctness
    ///
    /// Every input coefficient must lie in `[0, 2N)`; this range is not
    /// checked in release builds.
    pub fn ntt_blind_rotate_exponents_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let two_n = 2 * self.size().glwe_size().poly_length();
        self.blind_rotate_with(input, accumulator, output, modulus, ntt, context, |x| {
            // This entry already receives exponents; do not quantize them again.
            let exponent = x.try_into().unwrap();
            debug_assert!(exponent < two_n);
            exponent
        });
    }

    /// Validates resources and rotates the initial accumulator before the CMUX loop.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep modulus, transform and workspace roles explicit"
    )]
    fn blind_rotate_with<M, Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
        exponent_of: F,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
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

        self.assert_compatible(modulus, ntt, context);
        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        accumulator.mul_monomial_to(initial_exponent, output, poly_length, modulus);
        self.blind_rotate_initialized(input, output, modulus, ntt, context, exponent_of);
    }

    /// Checks evaluation resources before initializing the output accumulator.
    fn assert_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        context: &NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
    {
        assert_eq!(
            ntt.poly_length(),
            self.size().glwe_size().poly_length(),
            "blind-rotation NTT polynomial length mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.cipher_modulus(),
            "blind-rotation ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            context.size(),
            self.size(),
            "blind-rotation workspace gadget layout mismatch"
        );
        assert_eq!(
            matches!(context.cmux, CmuxContext::Binary(_)),
            self.input_distribution().is_binary(),
            "blind-rotation workspace control layout mismatch"
        );
        debug_assert_eq!(
            context.scratch.as_ref().len(),
            self.size().glwe_len(),
            "blind-rotation workspace GLWE layout mismatch"
        );
    }

    /// Rotates an initialized accumulator after layouts and resources have been checked.
    fn blind_rotate_initialized<M, Table, A, C, F>(
        &self,
        input: &Lwe<A>,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
        exponent_of: F,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        F: Fn(T) -> usize,
    {
        let NttGlweBlindRotationContext { scratch, cmux } = context;
        // Dispatch once per blind rotation; the coordinate loop has no secret-
        // distribution branch, and both paths share initialization and swapping.
        match cmux {
            CmuxContext::Binary(product) => {
                let controls = self
                    .iter_binary_controls()
                    .expect("binary workspace requires a binary key");
                rotate_controls(
                    input.a(),
                    controls,
                    output.as_mut(),
                    scratch.as_mut(),
                    exponent_of,
                    |control, exponent, input, output| {
                        control.cmux_monomial_to(
                            &Glwe::new(input),
                            exponent,
                            &mut Glwe::new(output),
                            self.basis(),
                            modulus,
                            ntt,
                            product,
                        );
                    },
                );
            }
            CmuxContext::Ternary(product) => {
                let controls = self
                    .iter_ternary_controls()
                    .expect("ternary workspace requires a ternary key");
                rotate_controls(
                    input.a(),
                    controls,
                    output.as_mut(),
                    scratch.as_mut(),
                    exponent_of,
                    |(positive, negative), exponent, input, output| {
                        positive.cmux_ternary_monomial_to(
                            &negative,
                            &Glwe::new(input),
                            exponent,
                            &mut Glwe::new(output),
                            self.basis(),
                            modulus,
                            ntt,
                            product,
                        );
                    },
                );
            }
        }
    }
}

/// Reusable workspace for Ntt blind rotation.
///
/// Construction selects only the binary or ternary scratch required by the key.
/// Resizing retains that control layout; construct a new workspace to change it.
pub struct NttGlweBlindRotationContext<T: FheUint> {
    scratch: Glwe<Vec<T>>,
    cmux: CmuxContext<T>,
}

enum CmuxContext<T: FheUint> {
    Binary(NttGlweExternalProductContext<T>),
    Ternary(NttGlweTernaryCmuxContext<T>),
}

impl<T: FheUint> NttGlweBlindRotationContext<T> {
    /// Allocates scratch matching the key's gadget and control layouts.
    #[must_use]
    pub fn new<LM: PrepareModulusSwitch<ValueT = T>>(key: &NttGlweBootstrappingKey<T, LM>) -> Self {
        let size = key.size();
        Self {
            scratch: Glwe::zero(size.glwe_len()),
            cmux: if key.input_distribution().is_binary() {
                CmuxContext::Binary(NttGlweExternalProductContext::new(size))
            } else {
                CmuxContext::Ternary(NttGlweTernaryCmuxContext::new(size))
            },
        }
    }

    fn size(&self) -> GadgetSize {
        match &self.cmux {
            CmuxContext::Binary(context) => context.size(),
            CmuxContext::Ternary(context) => context.size(),
        }
    }

    /// Resizes scratch for a new gadget layout, retaining binary/ternary mode.
    /// An unchanged size is allocation-free; a changed size may allocate.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.size() == size {
            return;
        }
        match &mut self.cmux {
            CmuxContext::Binary(context) => context.resize(size),
            CmuxContext::Ternary(context) => *context = NttGlweTernaryCmuxContext::new(size),
        }
        self.scratch.0.resize(size.glwe_len(), T::ZERO);
    }
}

/// Applies one control per input coordinate, skipping public zero exponents.
/// The caller has checked lengths and initialized `output`; `step` overwrites
/// the next accumulator. Alternating buffers avoids a copy at every coordinate.
fn rotate_controls<T: Copy, I: Iterator, E, F>(
    input: &[T],
    controls: I,
    output: &mut [T],
    scratch: &mut [T],
    exponent_of: E,
    mut step: F,
) where
    E: Fn(T) -> usize,
    F: FnMut(I::Item, usize, &[T], &mut [T]),
{
    let mut output_is_current = true;
    for (&coefficient, control) in input.iter().zip(controls) {
        let exponent = exponent_of(coefficient);
        if exponent == 0 {
            continue;
        }
        if output_is_current {
            step(control, exponent, output, scratch);
        } else {
            step(control, exponent, scratch, output);
        }
        output_is_current = !output_is_current;
    }
    if !output_is_current {
        output.copy_from_slice(scratch);
    }
}
