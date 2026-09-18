//! Parameters for the patched NTT circuit-bootstrapping workflow.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;

use crate::{CircuitBootstrapConfig, CircuitBootstrapParameterError, TfheParameters};

/// Independent parameters for patched NTT circuit bootstrapping.
///
/// The output basis controls GGSW gadget scalars; its layout comes from the TFHE
/// accumulator. The input plaintext modulus is bound when checking LUT capacity.
/// Trace and scheme switching retain independent bases and noise distributions.
/// The scheme-switch key binds the output layout, so another
/// output basis with the same level count can reuse it.
///
/// Construction checks representation and ManyLUT capacity. Callers must select
/// these parameters using a CBS noise and security analysis. Matching parameters
/// do not establish secret or NTT representation identity; see
/// [`crate::CircuitBootstrapEvaluator::try_new`].
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint> {
    output_basis: ApproxSignedBasis<T>,
    output_size: GadgetSize,
    trace: GlevParameters<T, BarrettModulus<T>>,
    scheme_switch: GgswParameters<T, BarrettModulus<T>>,
    input_plaintext_modulus: T,
}

impl<T: FheUint> CircuitBootstrapParameters<T> {
    /// Derives all CBS ring domains from TFHE, keeping bases and noise independent.
    ///
    /// Returns basis/layout errors or insufficient interleaved LUT capacity.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// # Panics
    ///
    /// Inherits [`primus_glwe::GlweParameters::new`]'s noise sampler requirements.
    pub fn try_from_config(
        tfhe: &TfheParameters<T>,
        config: CircuitBootstrapConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.accumulator_glwe();
        let output_basis = config.output.try_build(accumulator.cipher_modulus())?;
        let key_parameters = |role, decomposition: crate::DecompositionConfig, noise| {
            let ring = primus_glwe::GlweParameters::new(
                accumulator.dimension(),
                accumulator.poly_length(),
                accumulator.plain_modulus_value(),
                accumulator.cipher_modulus(),
                accumulator.secret_key_distr(),
                noise,
            );
            GlevParameters::try_with_glwe_params(
                &ring,
                decomposition.log_basis,
                decomposition.level_count,
            )
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
    /// the output layout overflows, or the padded output count exceeds LUT capacity.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, BarrettModulus<T>>,
        scheme_switch: GgswParameters<T, BarrettModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.accumulator_glwe().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        let glwe = tfhe.accumulator_glwe();
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.glwe_size() != glwe.size() {
                return Err(CircuitBootstrapParameterError::GlweLayoutMismatch { role });
            }
            if parameters.cipher_modulus().value() != glwe.cipher_modulus().value() {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }

        let lookup_table_padded_output_count = output_basis.decompose_length().next_power_of_two();
        let lookup_domain_len =
            primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), glwe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if lookup_table_padded_output_count > glwe.poly_length() / lookup_domain_len {
            return Err(CircuitBootstrapParameterError::OutputDecompositionTooLarge);
        }

        let output_size = GadgetSize::try_new(glwe.size(), output_basis.decompose_length())
            .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        Ok(Self {
            output_basis,
            output_size,
            trace,
            scheme_switch,
            input_plaintext_modulus: tfhe.plain_modulus_value(),
        })
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
    #[inline]
    pub fn trace(&self) -> &GlevParameters<T, BarrettModulus<T>> {
        &self.trace
    }

    /// Returns the gadget parameters of the scheme-switching key.
    #[inline]
    pub fn scheme_switch(&self) -> &GgswParameters<T, BarrettModulus<T>> {
        &self.scheme_switch
    }

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    #[inline]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis.decompose_length().next_power_of_two()
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        let glwe = tfhe.accumulator_glwe();
        self.output_size.glwe_size() == glwe.size()
            && self.output_basis.modulus() == glwe.cipher_modulus_value()
            && self.input_plaintext_modulus == tfhe.plain_modulus_value()
    }
}
