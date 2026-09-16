//! Parameters for the patched NTT circuit-bootstrapping workflow.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;

use crate::TfheParameters;

/// An invalid circuit-bootstrapping parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses a different GLWE dimension or polynomial
    /// length from the TFHE accumulator.
    #[error("circuit-bootstrap {role} GLWE layout does not match the TFHE accumulator")]
    GlweLayoutMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// A gadget parameter set uses a different ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus does not match the TFHE accumulator")]
    CipherModulusMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// The output layout overflows or has too many levels for one PBSManyLUT.
    #[error("circuit-bootstrap output decomposition does not fit in the accumulator")]
    OutputDecompositionTooLarge,
}

/// Independent parameters for patched NTT circuit bootstrapping.
///
/// The output basis controls GGSW gadget scalars; its layout comes from the TFHE
/// accumulator. Trace and scheme switching retain independent bases and noise
/// distributions. The scheme-switch key binds the output layout, so another
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
}

impl<T: FheUint> CircuitBootstrapParameters<T> {
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
        if output_basis.modulus() != tfhe.glwe().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        let glwe = tfhe.glwe();
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
        let glwe = tfhe.glwe();
        self.output_size.glwe_size() == glwe.size()
            && self.output_basis.modulus() == glwe.cipher_modulus_value()
    }
}
