//! Fourier-domain functional bootstrapping key and blind rotation.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters};
use primus_lattice::{
    GadgetSize, context::FourierGlweExternalProductContext, ggsw::FourierGgswIter, glwe::TorusGlwe,
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_tfhe::backend_support::{direct_exponent, modulus_switch};

/// A Fourier bootstrapping key containing one GGSW encryption per input LWE
/// secret coefficient.
#[derive(Clone)]
pub struct FourierGlweBootstrappingKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    input_dimension: usize,
    input_modulus: Option<T>,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierGlweBootstrappingKey<T> {
    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the explicit input LWE modulus, or `None` for a native torus.
    #[inline]
    pub fn input_modulus(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the GGSW/GLWE layout bound to this key.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns `None` because the Fourier accumulator uses the native torus.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        None
    }

    /// Returns the decomposition basis bound to this key.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the Fourier-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Generates a Fourier bootstrapping key encrypting every binary input
    /// LWE secret coefficient under `output_secret_key`.
    ///
    /// Inherits [`FourierGlweSecretKey::encrypt_ggsw_constant_batch_to`]'s FFT
    /// representation and workspace requirements.
    ///
    /// # Panics
    ///
    /// Panics if input key/parameter distributions are not binary or their
    /// dimensions differ, or if the output key, FFT or workspace layout is
    /// incompatible. A key-length overflow also panics. Checks precede sampling.
    pub fn generate_fourier<LM, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        input_parameters: &LweParameters<T, LM>,
        output_secret_key: &FourierGlweSecretKey,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
        LM: RingContext<T>,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert!(input_secret_key.distr().is_binary());
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert!(input_parameters.secret_key_distr().is_binary());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = parameters.fourier_ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("Fourier bootstrapping-key length overflow");
        let mut data = vec![Complex64::default(); total_len];
        output_secret_key.encrypt_ggsw_constant_batch_to(
            input_secret_key.as_ref(),
            &mut data,
            parameters,
            fft,
            rng,
            context,
        );

        Self {
            data,
            input_dimension,
            input_modulus: input_parameters.cipher_modulus().explicit_value(),
            size: parameters.size(),
            basis: parameters.basis().clone(),
        }
    }

    /// Iterates over the Fourier GGSW encryptions.
    #[inline]
    pub fn iter_fourier_ggsw(&self) -> FourierGgswIter<'_> {
        FourierGgswIter::new(&self.data, self.size.fourier_ggsw_len())
    }

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
        let two_n = self.size.glwe_size().poly_length() * 2;
        let modulus = self.input_modulus();
        self.blind_rotate_with(input, accumulator, output, fft, context, |x| {
            modulus_switch(x, modulus, two_n)
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
        self.assert_compatible(fft, context);
        self.fourier_blind_rotate_lookup_table_kernel_to(input, lookup_table, output, fft, context);
    }

    /// Uses resources bound by evaluator construction or validated by the public
    /// wrapper. Still checks the per-call input, lookup table and output layouts.
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
        let poly_length = self.size.glwe_size().poly_length();
        let two_n = poly_length * 2;
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len()),
            "blind-rotation input, lookup table or output layout mismatch"
        );

        let modulus = self.input_modulus();
        let exponent_of = |value| modulus_switch(value, modulus, two_n);
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
        let two_n = 2 * self.size.glwe_size().poly_length();
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
        let poly_length = self.size.glwe_size().poly_length();
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
            self.size.glwe_size().poly_length(),
            "blind-rotation FFT polynomial length mismatch"
        );
        assert_eq!(
            context.external_product.size(),
            self.size,
            "blind-rotation workspace gadget layout mismatch"
        );
        debug_assert_eq!(
            context.scratch.as_ref().len(),
            self.size.glwe_len(),
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
                    &self.basis,
                    fft,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    &self.basis,
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
