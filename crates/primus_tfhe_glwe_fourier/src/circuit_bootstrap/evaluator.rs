use primus_data::DataMut;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweSchemeSwitchContext, FourierGlweTraceContext, GlevCiphertext};
use primus_lattice::ggsw::FourierGgsw;
use primus_lwe::LweCiphertext;
use primus_reduce::ReduceMul;
use primus_tfhe::{InterleavedLookupTable, LookupTableError};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, ServerKey, TfheContext,
    TfheEvaluationError,
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
    scheme_switch: FourierGlweSchemeSwitchContext<T>,
    projected: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds the CBS parameters and material carried by one server key.
    /// Returns an error if CBS was not requested during key generation.
    ///
    /// # Correctness
    /// Inherits [`Self::try_from_parts`]'s secret and transform requirements.
    /// Bundled generation pairs secrets; layout checks do not establish identity
    /// for externally assembled material or another transform representation.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let key = server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        Self::try_from_parts(context, server_key, key.parameters(), key)
    }

    /// Checks resource layouts/bases, compiles the gadget-scaled identity LUT
    /// and allocates reusable workspace.
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
            scheme_switch: FourierGlweSchemeSwitchContext::new(parameters.scheme_switch().size()),
            projected: GlevCiphertext::zero(parameters.output_size().glev_len()),
        })
    }

    /// Allocates a Fourier GGSW output. Inherits [`Self::circuit_bootstrap_to`]'s
    /// encoding, secret, FFT representation, noise and input-dimension contracts.
    #[must_use]
    pub fn circuit_bootstrap(&mut self, input: &LweCiphertext<T>) -> FourierGgsw<Vec<Complex64>> {
        let mut output = FourierGgsw::zero(self.parameters.output_size().fourier_ggsw_len());
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
        self.circuit_key.scheme_switch_key().apply_to(
            &self.projected,
            output,
            fft,
            &mut self.scheme_switch,
        );
    }
}
