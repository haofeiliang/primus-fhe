//! Parameters for the patched NTT circuit-bootstrapping workflow.

use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;

use crate::TfheParameters;

/// An invalid circuit-bootstrapping parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
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
    /// The output decomposition has too many levels for one PBSManyLUT.
    #[error("circuit-bootstrap output decomposition does not fit in the accumulator")]
    OutputDecompositionTooLarge,
}

/// Independent parameters for patched NTT circuit bootstrapping.
///
/// The output basis controls the produced GGSW ciphertext. Trace and scheme
/// switching use separate decomposition bases and noise distributions. Keeping
/// these parameters separate from [`TfheParameters`] prevents ordinary PBS
/// users from paying for circuit-bootstrapping key material.
///
/// Construction validates representation and accumulator-capacity invariants;
/// it does not estimate failure probability or security. Callers must select
/// the three decomposition/noise parameter sets using a CBS noise and security
/// analysis appropriate to their workload.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint> {
    output: GgswParameters<T, BarrettModulus<T>>,
    trace: GlevParameters<T, BarrettModulus<T>>,
    scheme_switch: GgswParameters<T, BarrettModulus<T>>,
    many_lut_output_count: usize,
}

impl<T: FheUint> CircuitBootstrapParameters<T> {
    /// Validates circuit-bootstrapping parameters against a TFHE context.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output: GgswParameters<T, BarrettModulus<T>>,
        trace: GlevParameters<T, BarrettModulus<T>>,
        scheme_switch: GgswParameters<T, BarrettModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let glwe = tfhe.glwe();
        for (role, parameters) in [
            ("output", &output),
            ("trace", &trace),
            ("scheme-switch", &scheme_switch),
        ] {
            if parameters.glwe_size() != glwe.size() {
                return Err(CircuitBootstrapParameterError::GlweLayoutMismatch { role });
            }
            if parameters.cipher_modulus().value() != glwe.cipher_modulus_value() {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }

        let many_lut_output_count = output
            .decompose_length()
            .checked_next_power_of_two()
            .ok_or(CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        let lookup_domain_len =
            primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), glwe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if many_lut_output_count > glwe.poly_length() / lookup_domain_len {
            return Err(CircuitBootstrapParameterError::OutputDecompositionTooLarge);
        }

        Ok(Self {
            output,
            trace,
            scheme_switch,
            many_lut_output_count,
        })
    }

    /// Returns the gadget parameters of the output GGSW ciphertext.
    #[inline]
    pub fn output(&self) -> &GgswParameters<T, BarrettModulus<T>> {
        &self.output
    }

    /// Returns the decomposition parameters used by HomTrace automorphism
    /// keys.
    #[inline]
    pub fn trace(&self) -> &GlevParameters<T, BarrettModulus<T>> {
        &self.trace
    }

    /// Returns the gadget parameters of the scheme-switching key.
    #[inline]
    pub fn scheme_switch(&self) -> &GgswParameters<T, BarrettModulus<T>> {
        &self.scheme_switch
    }

    /// Returns the padded power-of-two output count used by PBSManyLUT.
    #[inline]
    pub fn many_lut_output_count(&self) -> usize {
        self.many_lut_output_count
    }

    pub(crate) fn output_size(&self) -> GadgetSize {
        self.output.size()
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        let glwe = tfhe.glwe();
        [&self.output, &self.trace, &self.scheme_switch]
            .into_iter()
            .all(|parameters| {
                parameters.glwe_size() == glwe.size()
                    && parameters.cipher_modulus().value() == glwe.cipher_modulus_value()
            })
    }
}
