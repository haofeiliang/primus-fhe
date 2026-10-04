//! Backend-independent parameters for GLWE circuit bootstrapping.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters, GlweEncryptionParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use std::sync::Arc;

use crate::{CircuitBootstrapConfig, CircuitBootstrapParameterError, TfheParameters};

/// Independent parameters for GLWE circuit bootstrapping.
///
/// The output basis controls GGSW gadget scalars; its layout comes from the TFHE
/// accumulator. Input encoding and ManyLUT capacity are bound by the evaluator,
/// allowing these keys to serve more than one message program.
/// Trace and scheme switching retain independent bases and noise distributions.
/// The scheme-switch key binds the output layout, so another
/// output basis with the same level count can reuse it.
///
/// Construction checks modulus, layout and decomposition. Callers must select
/// these parameters using a CBS noise and security analysis. Matching parameters
/// do not establish secret or transform identity; execution backends specify
/// their representation and numerical requirements.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint, M: RingContext<T>> {
    output_basis: ApproxSignedBasis<T>,
    output_size: GadgetSize,
    trace: GlevParameters<T, M>,
    scheme_switch: GgswParameters<T, M>,
}

impl<T: FheUint, M: RingContext<T>> CircuitBootstrapParameters<T, M> {
    /// Derives all CBS ring domains from TFHE, keeping bases and noise independent.
    ///
    /// Returns basis, sampling or layout errors. Program capacity is checked at evaluation binding.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// Invalid key noise/sampler parameters are returned with their key role.
    pub fn try_from_config(
        tfhe: &TfheParameters<T, M>,
        config: CircuitBootstrapConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.blind_rotation_ggsw();
        let output_basis = config
            .output
            .try_build(accumulator.cipher_modulus().explicit_value())?;
        let key_parameters = |role, decomposition: crate::DecompositionConfig, noise| {
            // Trace and scheme-switch rows have independent noise roles. Reuse
            // the accumulator layout, without constructing a message codec.
            let inner = GlweEncryptionParameters::try_new(
                accumulator.cipher_modulus(),
                accumulator.secret_key_distr(),
                noise,
            )
            .map_err(|source| {
                CircuitBootstrapParameterError::EncryptionParameters { role, source }
            })?;
            let basis = decomposition
                .try_build(accumulator.cipher_modulus().explicit_value())
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters {
                    role,
                    source: source.into(),
                })?;
            GlevParameters::try_from_parts(accumulator.glwe_size(), Arc::new(inner), basis)
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters { role, source })
        };
        let trace = key_parameters("trace", config.trace, config.trace_noise_standard_deviation)?;
        let scheme_switch = key_parameters(
            "scheme-switch",
            config.scheme_switch,
            config.scheme_switch_noise_standard_deviation,
        )?;
        Self::try_new(tfhe, output_basis, trace, scheme_switch)
    }

    /// Derives the output layout from the TFHE accumulator and `output_basis`.
    ///
    /// Returns an error if bases or key layouts use another accumulator domain,
    /// or the output layout overflows. No message codec is required.
    pub fn try_new(
        tfhe: &TfheParameters<T, M>,
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, M>,
        scheme_switch: GgswParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.cipher_modulus().explicit_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        let glwe = tfhe.blind_rotation_ggsw();
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.glwe_size() != glwe.glwe_size() {
                return Err(CircuitBootstrapParameterError::GlweLayoutMismatch { role });
            }
            if parameters.cipher_modulus().explicit_value()
                != glwe.cipher_modulus().explicit_value()
            {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }

        let output_size = GadgetSize::try_new(glwe.glwe_size(), output_basis.decompose_length())
            .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        Ok(Self {
            output_basis,
            output_size,
            trace,
            scheme_switch,
        })
    }

    /// Compiles the gadget-scaled identity for a selected Rounded input encoding.
    ///
    /// Checks input q, front-half geometry and interleaved output capacity here,
    /// rather than at key generation. The same CBS material may serve another t
    /// when its program fits. Output values are gadget scalars, not codec-scaled
    /// messages. Callers must budget input, trace and scheme-switch noise.
    pub fn compile_lookup_table(
        &self,
        input_codec: &primus_encoding::RoundedCodec<T, M>,
    ) -> Result<primus_tfhe::InterleavedLookupTable<T>, primus_tfhe::LookupTableError> {
        use primus_tfhe::{InterleavedLookupTable, LookupTableError, front_half_domain_len};
        let modulus = self.trace.cipher_modulus();
        if input_codec.ciphertext_modulus().explicit_value() != modulus.explicit_value() {
            return Err(LookupTableError::InputModulusMismatch);
        }
        let poly_length = self.output_size.glwe_size().poly_length();
        let plaintext_modulus = input_codec.plaintext_modulus();
        let domain_len = front_half_domain_len(plaintext_modulus, poly_length)?;
        let scalars: Vec<T> = self.output_basis.scalar_iter().collect();
        InterleavedLookupTable::try_new(
            domain_len,
            poly_length,
            scalars.len(),
            plaintext_modulus,
            input_codec.ciphertext_modulus(),
            modulus,
            |input, level| {
                let input =
                    T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
                Ok(modulus.reduce_mul(scalars[level], input))
            },
        )
    }

    /// Returns the gadget basis of the output ciphertext.
    #[must_use]
    #[inline]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the output GGSW layout derived from the TFHE accumulator.
    #[must_use]
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the trace key's encryption parameters.
    #[must_use]
    #[inline]
    pub fn trace(&self) -> &GlevParameters<T, M> {
        &self.trace
    }

    /// Returns the gadget parameters of the scheme-switching key.
    #[must_use]
    #[inline]
    pub fn scheme_switch(&self) -> &GgswParameters<T, M> {
        &self.scheme_switch
    }

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    #[inline]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis
            .decompose_length()
            .get()
            .next_power_of_two()
    }

    /// Checks the accumulator layout and ciphertext modulus independently of message encoding.
    /// This does not check noise, secret identity or transform representation.
    #[must_use]
    pub fn is_compatible(&self, tfhe: &TfheParameters<T, M>) -> bool {
        let glwe = tfhe.blind_rotation_ggsw();
        self.output_size.glwe_size() == glwe.glwe_size()
            && self.output_basis.modulus() == glwe.cipher_modulus().explicit_value()
    }
}
