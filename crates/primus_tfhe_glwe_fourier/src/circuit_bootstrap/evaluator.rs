use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::GlweCiphertext;
use primus_glwe::{FourierGlweTraceContext, GlevCiphertext};
use primus_lattice::context::FourierGlweExternalProductContext;
use primus_lattice::ggsw::FourierGgsw;
use primus_lwe::LweCiphertext;
use primus_reduce::ReduceMul;
use primus_tfhe::{InterleavedLookupTable, LookupTableError};

use crate::{
    BootstrappingKey, CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, ServerKey,
    TfheContext, TfheEvaluationError,
};

/// Classic binary/ternary CBS producing Fourier GGSW under the accumulator secret.
///
/// Both PBS orders share the same BR, reverse-trace projection and scheme-switch
/// stages; KeyswitchBootstrap adds an input key switch. After construction,
/// [`Self::circuit_bootstrap_to`] performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pbs: Evaluator<'a, T, Table>,
    parameters: &'a CircuitBootstrapParameters<T>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    input_dimension: usize,
    lookup_table: InterleavedLookupTable<T>,
    trace: FourierGlweTraceContext<T>,
    external_product: FourierGlweExternalProductContext<T>,
    projected: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds the CBS parameters and material carried by one server key.
    /// Rejects sparse server keys, or keys without CBS material.
    ///
    /// # Correctness
    /// Inherits [`Self::try_from_parts`]'s secret and transform requirements.
    /// Bundled generation pairs secrets; layout checks do not establish identity
    /// for externally assembled material or another transform representation.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if matches!(server_key.bootstrapping_key(), BootstrappingKey::Sparse(_)) {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        let key = server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::try_from_parts(context, server_key, key.parameters(), key)
    }

    /// Checks resource layouts/bases, compiles the gadget-scaled identity LUT
    /// and allocates reusable workspace. Sparse server keys are rejected until
    /// their CBS noise and gadget scales are validated.
    ///
    /// # Correctness
    ///
    /// `server_key` and `circuit_key` must be generated from the same paired
    /// client secrets and this context's FFT table instance. Compatibility
    /// checks cannot verify actual secret or transform identity. See
    /// [`primus_glwe::FourierGlweSchemeSwitchKey::apply_to`] for the underlying
    /// representation and error requirements.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if matches!(server_key.bootstrapping_key(), BootstrappingKey::Sparse(_)) {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping);
        }
        let tfhe = context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !circuit_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        let pbs = Evaluator::try_new(context, server_key)?;
        let glwe = tfhe.accumulator_glwe();
        let modulus = glwe.cipher_modulus();
        let domain_len =
            primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), glwe.poly_length())?;
        let scalars: Vec<T> = parameters.output_basis().scalar_iter().collect();
        let lookup_table = InterleavedLookupTable::try_new(
            domain_len,
            glwe.poly_length(),
            scalars.len(),
            tfhe.plain_modulus_value(),
            tfhe.small_lwe().cipher_modulus(),
            modulus,
            |input, level| {
                let input =
                    T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
                Ok(modulus.reduce_mul(scalars[level], input))
            },
        )?;
        Ok(Self {
            pbs,
            parameters,
            circuit_key,
            input_dimension: tfhe.external_lwe_dimension(),
            lookup_table,
            trace: FourierGlweTraceContext::new(glwe.size()),
            external_product: FourierGlweExternalProductContext::new(
                parameters.scheme_switch().size(),
            ),
            projected: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
    }

    /// Allocates a zeroed Fourier GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> FourierGgsw<Vec<Complex64>> {
        FourierGgsw::zero(self.parameters.output_size().fourier_ggsw_len())
    }

    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// Fourier controls must use the bound FFT table instance.
    /// See [`FourierGgsw::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
        control: &FourierGgsw<A>,
        lhs: &GlweCiphertext<B>,
        rhs: &GlweCiphertext<C>,
        output: &mut GlweCiphertext<D>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let ring_len = self.parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                self.parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        self.external_product.rebind(self.parameters.output_size());
        control.cmux_to(
            lhs,
            rhs,
            output,
            self.parameters.output_basis(),
            self.pbs.fft_mut(),
            &mut self.external_product,
        );
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`FourierGgsw::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes if any ciphertext has the wrong length.
    pub fn external_product_to<A, B, C>(
        &mut self,
        control: &FourierGgsw<A>,
        input: &GlweCiphertext<B>,
        output: &mut GlweCiphertext<C>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let ring_len = self.parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (
                self.parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len
            ),
            "external-product ciphertext layout mismatch"
        );
        self.external_product.rebind(self.parameters.output_size());
        control.external_product_to(
            input,
            output,
            self.parameters.output_basis(),
            self.pbs.fft_mut(),
            &mut self.external_product,
        );
    }

    /// Allocates a Fourier GGSW output. Inherits [`Self::circuit_bootstrap_to`]'s
    /// encoding, secret, FFT representation, noise and input-dimension contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> FourierGgsw<Vec<Complex64>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output);
        output
    }

    /// Writes a Fourier GGSW encrypting the input message under the accumulator
    /// GLWE secret, with the configured output gadget scalars.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::try_new`]'s paired-secret and FFT table requirements.
    /// Input must use the external client secret paired with `server_key` and
    /// unsigned rounded encoding with a plaintext in `0..ceil(t/2)`, where `t`
    /// is the TFHE plaintext modulus. Noise must fit the coarser interleaved-LUT
    /// rotation intervals. Trace and scheme-switch errors, including native
    /// halving and FFT rounding, must fit the independent CBS error budget;
    /// see [`CircuitBootstrapParameters`]. CMUX consumption requires message
    /// 0 or 1. The output uses gadget scales rather than ordinary LWE encoding.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input dimension or output Fourier
    /// GGSW length is wrong. LUT and resource compatibility is fixed at construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = Complex64>>(
        &mut self,
        input: &LweCiphertext<T>,
        output: &mut FourierGgsw<S>,
    ) {
        assert_eq!(
            input.dimension(),
            self.input_dimension,
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.parameters.output_size().fourier_ggsw_len(),
            "circuit-bootstrap output Fourier GGSW layout mismatch"
        );

        let (accumulator, fft) = self.pbs.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );
        // ManyLUT messages can have nonzero tails, so prefix expansion cannot
        // replace full coefficient projection here.
        self.circuit_key.trace_key().project_prefix_coefficients_to(
            accumulator,
            self.parameters.output_basis().decompose_length(),
            self.projected.as_mut(),
            fft,
            &mut self.trace,
        );
        // CMUX can bind the same buffers to a different output decomposition.
        self.external_product
            .rebind(self.parameters.scheme_switch().size());
        self.circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            fft,
            &mut self.external_product,
        );
    }
}
