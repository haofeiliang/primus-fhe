//! NTT blind-rotation APIs, kernels, and workspace.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, context::NttGlweExternalProductContext, glwe::Glwe, lwe::Lwe};
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::{FieldContext, PrepareModulusSwitch};
use primus_tfhe::backend_support::{RotationQuantizer, direct_exponent};

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
        Table: NttTable<ValueT = T>,
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
        Table: NttTable<ValueT = T>,
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
        Table: NttTable<ValueT = T>,
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
    /// Each input coefficient is quantized directly to `2N / stride`, then
    /// multiplied by `stride`, preserving the independently programmed residue
    /// classes. `stride` must be a non-zero power of two dividing the
    /// polynomial length `N`.
    ///
    /// Inherits [`Self::ntt_blind_rotate_lookup_table_to`]'s requirements.
    /// An invalid stride panics before output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "keep modulus, transform and workspace roles explicit"
    )]
    pub fn ntt_blind_rotate_interleaved_lookup_table_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        stride: usize,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        assert!(
            stride.is_power_of_two() && poly_length.is_multiple_of(stride),
            "PBSManyLUT stride must be a non-zero power-of-two divisor of N"
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
            stride,
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
        stride: usize,
        output: &mut Glwe<C>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = self.size().glwe_size().poly_length();
        let two_n = poly_length * 2;
        debug_assert!(
            stride.is_power_of_two() && poly_length.is_multiple_of(stride),
            "PBSManyLUT stride must be a non-zero power-of-two divisor of N"
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
        let quantizer = if stride == 1 {
            self.input_quantizer()
        } else {
            RotationQuantizer::new(input_modulus, two_n, stride)
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
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let two_n = 2 * self.size().glwe_size().poly_length();
        self.blind_rotate_with(input, accumulator, output, modulus, ntt, context, |x| {
            direct_exponent(x, two_n)
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
        Table: NttTable<ValueT = T>,
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
        Table: NttTable<ValueT = T>,
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
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        F: Fn(T) -> usize,
    {
        let NttGlweBlindRotationContext {
            scratch,
            external_product,
        } = context;
        let mut output_is_current = true;
        for (&coefficient, control) in input.a().iter().zip(self.iter_ntt_ggsw()) {
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
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    self.basis(),
                    modulus,
                    ntt,
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

/// Reusable workspace for NTT blind rotation.
pub struct NttGlweBlindRotationContext<T: FheUint> {
    // new/resize/rebind keep scratch consistent with external_product.size().
    scratch: Glwe<Vec<T>>,
    external_product: NttGlweExternalProductContext<T>,
}

impl<T: FheUint> NttGlweBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        Self {
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttGlweExternalProductContext::new(size),
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
