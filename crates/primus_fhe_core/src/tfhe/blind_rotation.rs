use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use primus_lattice::{
    GadgetSize,
    context::{FourierExternalProductContext, NttExternalProductContext},
    glwe::{Glwe, TorusGlwe},
    lwe::Lwe,
};

use crate::{FunctionalBootstrappingKey, GlevParameters, NttGadgetDomain};

/// Reusable workspace for Fourier blind rotation.
pub struct FourierBlindRotationContext<T: TorusFftValue> {
    scratch: TorusGlwe<Vec<T>>,
    external_product: FourierExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        let scratch = TorusGlwe::zero(size.glwe_len());
        let external_product = FourierExternalProductContext::new(size);
        Self {
            scratch,
            external_product,
        }
    }

    /// Rebinds the workspace to another decomposition layout without reallocating.
    ///
    /// # Panics
    ///
    /// Panics if `size` has a different GLWE dimension or polynomial length.
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

/// Reusable workspace for NTT blind rotation.
pub struct NttBlindRotationContext<T: FheUint> {
    scratch: Glwe<Vec<T>>,
    external_product: NttExternalProductContext<T>,
}

impl<T: FheUint> NttBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        let scratch = Glwe::zero(size.glwe_len());
        let external_product = NttExternalProductContext::new(size);
        Self {
            scratch,
            external_product,
        }
    }

    /// Rebinds the workspace to another decomposition layout without reallocating.
    ///
    /// # Panics
    ///
    /// Panics if `size` has a different GLWE dimension or polynomial length.
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

impl<T: TorusFftValue> FunctionalBootstrappingKey<T, Vec<Complex64>> {
    /// Blind-rotates a native-torus GLWE accumulator using this Fourier key.
    ///
    /// With LWE input `(a, b)`, the resulting accumulator is rotated by
    /// `X^(-MS(b) + sum_i MS(a_i) s_i)`, where `MS` rounds into `[0, 2N)`.
    pub fn fourier_blind_rotate_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = parameters.poly_length() * 2;
        let modulus = self.input_modulus();
        self.fourier_blind_rotate_with(
            input,
            accumulator,
            output,
            parameters,
            (fft, context),
            |x| modulus_switch(x, modulus, two_n),
        );
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    ///
    /// This entry point performs no modulus switching.
    pub fn fourier_blind_rotate_exponents_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = 2 * parameters.poly_length();
        self.fourier_blind_rotate_with(
            input,
            accumulator,
            output,
            parameters,
            (fft, context),
            |x| direct_exponent(x, two_n),
        );
    }
}

impl<T: FheUint> FunctionalBootstrappingKey<T, Vec<T>> {
    /// Blind-rotates an explicit-modulus GLWE accumulator using this NTT key.
    ///
    /// The input LWE modulus is independent of the NTT GLWE modulus.
    pub fn ntt_blind_rotate_to<GM, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, GM, Table>,
        context: &mut NttBlindRotationContext<T>,
    ) where
        GM: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = domain.parameters().poly_length() * 2;
        let modulus = self.input_modulus();
        self.ntt_blind_rotate_with(input, accumulator, output, domain, context, |x| {
            modulus_switch(x, modulus, two_n)
        });
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    ///
    /// This entry point performs no modulus switching. The LWE modulus may be
    /// `2N`, independently of the NTT GLWE modulus.
    pub fn ntt_blind_rotate_exponents_to<M, Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttBlindRotationContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = 2 * domain.parameters().poly_length();
        self.ntt_blind_rotate_with(input, accumulator, output, domain, context, |x| {
            direct_exponent(x, two_n)
        });
    }
}

impl<T: TorusFftValue> FunctionalBootstrappingKey<T, Vec<Complex64>> {
    fn fourier_blind_rotate_with<Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        ggsw_params: &GlevParameters<T, NativeModulus<T>>,
        workspace: (
            &mut FftEngine<'_, Table>,
            &mut FourierBlindRotationContext<T>,
        ),
        exponent_of: F,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        F: Fn(T) -> usize,
    {
        let (fft, context) = workspace;
        let poly_length = ggsw_params.poly_length();
        let two_n = 2 * poly_length;
        debug_assert_eq!(
            (
                input.dimension(),
                accumulator.as_ref().len(),
                output.as_ref().len(),
            ),
            (
                self.input_dimension(),
                self.size().glwe_len(),
                self.size().glwe_len(),
            )
        );

        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        accumulator.mul_monomial_to(initial_exponent, output, poly_length, NativeModulus::new());

        let FourierBlindRotationContext {
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
                    ggsw_params.basis(),
                    fft,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    ggsw_params.basis(),
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

impl<T: FheUint> FunctionalBootstrappingKey<T, Vec<T>> {
    fn ntt_blind_rotate_with<M, Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &Glwe<B>,
        output: &mut Glwe<C>,
        domain: &NttGadgetDomain<'_, T, M, Table>,
        context: &mut NttBlindRotationContext<T>,
        exponent_of: F,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        F: Fn(T) -> usize,
    {
        let ggsw_params = domain.parameters();
        let ntt = domain.table();
        let modulus = ggsw_params.cipher_modulus();
        let poly_length = ggsw_params.poly_length();
        let two_n = 2 * poly_length;
        debug_assert_eq!(
            (
                input.dimension(),
                accumulator.as_ref().len(),
                output.as_ref().len(),
            ),
            (
                self.input_dimension(),
                self.size().glwe_len(),
                self.size().glwe_len(),
            )
        );

        let initial_exponent = exponent_of(input.b()).wrapping_neg() & (two_n - 1);
        accumulator.mul_monomial_to(initial_exponent, output, poly_length, modulus);

        let NttBlindRotationContext {
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
                    ggsw_params.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    ggsw_params.basis(),
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

#[inline]
fn direct_exponent<T: FheUint>(value: T, two_n: usize) -> usize {
    let exponent = value.try_into().unwrap();
    debug_assert!(exponent < two_n);
    exponent
}

/// Applies the same modulus switch used by blind rotation to one LWE
/// coefficient.
pub(crate) fn modulus_switch<T: FheUint>(value: T, modulus: Option<T>, two_n: usize) -> usize {
    match modulus {
        Some(modulus) if T::try_from(two_n).ok() == Some(modulus) => direct_exponent(value, two_n),
        Some(modulus) => explicit_modulus_switch(value, modulus, two_n),
        None => native_modulus_switch(value, two_n),
    }
}

#[inline]
fn native_modulus_switch<T: FheUint>(value: T, two_n: usize) -> usize {
    debug_assert!(two_n.is_power_of_two());
    let target_log = two_n.trailing_zeros();
    assert!(target_log <= T::BITS);
    let shift = T::BITS - target_log;
    let rounded = if shift == 0 {
        value
    } else {
        value.wrapping_add(T::ONE << (shift - 1)) >> shift
    };
    rounded.try_into().unwrap() & (two_n - 1)
}

#[inline]
fn explicit_modulus_switch<T: FheUint>(value: T, modulus: T, two_n: usize) -> usize {
    debug_assert!(two_n.is_power_of_two());
    let target = T::try_from(two_n).unwrap();
    let (lo, hi) = value.carrying_mul(target, modulus >> 1u32);
    let rounded = T::div_wide(lo, hi, modulus);
    rounded.try_into().unwrap() & (two_n - 1)
}

#[cfg(test)]
mod tests {
    use super::{explicit_modulus_switch, native_modulus_switch};

    #[test]
    fn native_modulus_switch_rounds_half_up_and_wraps() {
        assert_eq!(native_modulus_switch(0u32, 8), 0);
        assert_eq!(native_modulus_switch(1u32 << 28, 8), 1);
        assert_eq!(native_modulus_switch((1u32 << 29) - 1, 8), 1);
        assert_eq!(native_modulus_switch(1u32 << 29, 8), 1);
        assert_eq!(native_modulus_switch(u32::MAX, 8), 0);
    }

    #[test]
    fn explicit_modulus_switch_matches_integer_oracle() {
        const Q: u32 = 132_120_577;
        for value in [0, 1, Q / 8, Q / 2, Q - 1] {
            let oracle = ((value as u64 * 8 + (Q / 2) as u64) / Q as u64) as usize & 7;
            assert_eq!(explicit_modulus_switch(value, Q, 8), oracle);
        }
    }
}
