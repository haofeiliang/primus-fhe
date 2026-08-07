//! Fourier-domain functional bootstrapping key and blind rotation.

use primus_data::{Data, DataMut, RawData};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters, SecretKeyDistr,
};
use primus_lattice::{
    GadgetSize,
    context::FourierExternalProductContext,
    ggsw::{FourierGgsw, FourierGgswIter},
    glwe::TorusGlwe,
    lwe::Lwe,
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_poly::{Polynomial, PolynomialOwned};
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

    /// Returns the Fourier-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Generates a Fourier bootstrapping key encrypting every binary input
    /// LWE secret coefficient under `output_secret_key`.
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
        assert_eq!(input_secret_key.distr(), SecretKeyDistr::Binary);
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert_eq!(input_parameters.secret_key_distr(), SecretKeyDistr::Binary);
        assert_eq!(output_secret_key.glwe_size(), parameters.glwe_size());
        assert_eq!(fft.poly_length(), parameters.poly_length());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = parameters.fourier_ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("Fourier bootstrapping-key length overflow");
        let mut data = vec![Complex64::default(); total_len];
        let mut message = PolynomialOwned::zero(parameters.poly_length());

        for (&secret, chunk) in input_secret_key
            .as_ref()
            .iter()
            .zip(data.chunks_exact_mut(ggsw_len))
        {
            message.as_mut()[0] = secret;
            output_secret_key.encrypt_ggsw_to(
                &message,
                &mut FourierGgsw::new(chunk),
                parameters,
                fft,
                rng,
                context,
            );
        }

        Self {
            data,
            input_dimension,
            input_modulus: input_parameters.cipher_modulus().explicit_value(),
            size: parameters.size(),
        }
    }

    /// Iterates over the Fourier GGSW encryptions.
    #[inline]
    pub fn iter_fourier_ggsw(&self) -> FourierGgswIter<'_> {
        FourierGgswIter::new(&self.data, self.size.fourier_ggsw_len())
    }

    /// Blind-rotates a native-torus GLWE accumulator using this key.
    pub fn fourier_blind_rotate_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = parameters.poly_length() * 2;
        let modulus = self.input_modulus();
        self.blind_rotate_with(
            input,
            accumulator,
            output,
            parameters,
            (fft, context),
            |x| modulus_switch(x, modulus, two_n),
        );
    }

    /// Blind-rotates an encoded lookup-table polynomial as a trivial GLWE
    /// accumulator.
    pub fn fourier_blind_rotate_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let poly_length = parameters.poly_length();
        let two_n = poly_length * 2;
        debug_assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, self.size().glwe_len(),)
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
        self.blind_rotate_initialized(input, output, parameters, (fft, context), exponent_of);
    }

    /// Blind-rotates from an LWE whose coefficients are exponents in `[0, 2N)`.
    pub fn fourier_blind_rotate_exponents_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let two_n = 2 * parameters.poly_length();
        self.blind_rotate_with(
            input,
            accumulator,
            output,
            parameters,
            (fft, context),
            |x| direct_exponent(x, two_n),
        );
    }

    fn blind_rotate_with<Table, A, B, C, F>(
        &self,
        input: &Lwe<A>,
        accumulator: &TorusGlwe<B>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        workspace: (
            &mut FftEngine<'_, Table>,
            &mut FourierGlweBlindRotationContext<T>,
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
        let poly_length = parameters.poly_length();
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
        self.blind_rotate_initialized(input, output, parameters, (fft, context), exponent_of);
    }

    fn blind_rotate_initialized<Table, A, C, F>(
        &self,
        input: &Lwe<A>,
        output: &mut TorusGlwe<C>,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        workspace: (
            &mut FftEngine<'_, Table>,
            &mut FourierGlweBlindRotationContext<T>,
        ),
        exponent_of: F,
    ) where
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        F: Fn(T) -> usize,
    {
        let (fft, context) = workspace;

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
                    parameters.basis(),
                    fft,
                    external_product,
                );
            } else {
                control.cmux_monomial_to(
                    scratch,
                    exponent,
                    output,
                    parameters.basis(),
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
    external_product: FourierExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierGlweBlindRotationContext<T> {
    /// Creates a workspace for a checked GLWE size.
    pub fn new(size: GadgetSize) -> Self {
        Self {
            scratch: TorusGlwe::zero(size.glwe_len()),
            external_product: FourierExternalProductContext::new(size),
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
