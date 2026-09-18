use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::TorusFftValue;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_modulus::NativeModulus;

use crate::TfheParameters;

/// An invalid circuit-bootstrapping parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// The output basis belongs to an explicit rather than native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A key's GLWE dimension or polynomial length differs from the accumulator.
    #[error("circuit-bootstrap {role} GLWE layout does not match the TFHE accumulator")]
    GlweLayoutMismatch {
        /// Role of the incompatible key parameter set.
        role: &'static str,
    },
    /// The output layout overflows or its levels exceed interleaved LUT capacity.
    #[error("circuit-bootstrap output decomposition does not fit in the accumulator")]
    OutputDecompositionTooLarge,
}

/// Optional CBS parameters, separate from ordinary PBS server-key parameters.
///
/// The output basis sets the GGSW gadget scalars; the TFHE accumulator supplies
/// its GLWE layout. Trace and scheme switching have independent bases and noise
/// distributions. The scheme-switch key binds only the output layout, so output
/// bases with the same level count can reuse that key.
///
/// Construction checks layouts and interleaved LUT capacity, not noise or
/// security. Native reverse trace uses integer halving at each stage; its
/// rounding, trace key switching, scheme-switch decomposition and FFT precision
/// all contribute to the CBS error budget.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: TorusFftValue> {
    output_basis: ApproxSignedBasis<T>,
    output_size: GadgetSize,
    trace: GlevParameters<T, NativeModulus<T>>,
    scheme_switch: GgswParameters<T, NativeModulus<T>>,
    input_plaintext_modulus: T,
}

impl<T: TorusFftValue> CircuitBootstrapParameters<T> {
    /// Derives the output layout from the TFHE accumulator and `output_basis`.
    ///
    /// Returns an error for a non-native output basis, incompatible key layouts,
    /// output layout overflow, or insufficient interleaved LUT capacity for the
    /// input plaintext domain and padded gadget-level count. The result is bound
    /// to this accumulator layout and input plaintext modulus.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, NativeModulus<T>>,
        scheme_switch: GgswParameters<T, NativeModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus().is_some() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        let glwe = tfhe.accumulator_glwe();
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.glwe_size() != glwe.size() {
                return Err(CircuitBootstrapParameterError::GlweLayoutMismatch { role });
            }
        }

        let padded_output_count = output_basis.decompose_length().next_power_of_two();
        let input_domain_len =
            primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), glwe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if padded_output_count > glwe.poly_length() / input_domain_len {
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

    /// Returns the gadget basis of the output GGSW ciphertext.
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

    /// Returns the reverse-trace key's encryption parameters.
    #[must_use]
    #[inline]
    pub fn trace(&self) -> &GlevParameters<T, NativeModulus<T>> {
        &self.trace
    }

    /// Returns the scheme-switch key's encryption parameters.
    #[must_use]
    #[inline]
    pub fn scheme_switch(&self) -> &GgswParameters<T, NativeModulus<T>> {
        &self.scheme_switch
    }

    /// Returns the padded number of interleaved outputs for the gadget levels.
    #[must_use]
    #[inline]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis.decompose_length().next_power_of_two()
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        self.output_size.glwe_size() == tfhe.accumulator_glwe().size()
            && self.input_plaintext_modulus == tfhe.plain_modulus_value()
    }
}
