//! Independently selected gadget bases for NTRU circuit bootstrapping.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntru::NlevParameters;

use crate::TfheParameters;

/// An incompatible circuit-bootstrap parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// A gadget parameter set uses another ring length.
    #[error("circuit-bootstrap {role} polynomial length differs from the accumulator")]
    PolynomialLengthMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// A gadget parameter set uses another ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus differs from the accumulator")]
    CipherModulusMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// The padded output levels leave too few programmable input slots.
    #[error("circuit-bootstrap output levels do not fit the ManyLUT accumulator")]
    OutputDecompositionTooLarge,
    /// Trace normalization requires an odd field modulus with Shoup headroom.
    #[error("circuit-bootstrap trace requires odd q below 2^(T::BITS-1)")]
    UnsupportedTraceModulus,
}

/// Optional CBS parameters, separate from ordinary PBS server-key parameters.
///
/// The TFHE context supplies BR parameters. Trace, scheme-switch and output
/// bases are independent. Construction checks layouts and ManyLUT capacity,
/// not noise, failure probability or security. In particular the scheme-switch
/// key encrypts secret-dependent messages and multiplies errors by f and f²;
/// ordinary PBS parameters are not automatically valid CBS parameters.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint> {
    output: NlevParameters<T, BarrettModulus<T>>,
    trace: NlevParameters<T, BarrettModulus<T>>,
    scheme_switch: NlevParameters<T, BarrettModulus<T>>,
    input_plain_modulus: T,
    many_lut_output_count: usize,
}

impl<T: FheUint> CircuitBootstrapParameters<T> {
    /// Checks the accumulator ring, modulus and capacity for the input domain.
    /// Output encryption noise is unused: only its N and basis define output.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output: NlevParameters<T, BarrettModulus<T>>,
        trace: NlevParameters<T, BarrettModulus<T>>,
        scheme_switch: NlevParameters<T, BarrettModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        for (role, parameters) in [
            ("output", &output),
            ("trace", &trace),
            ("scheme-switch", &scheme_switch),
        ] {
            if parameters.poly_length() != tfhe.poly_length() {
                return Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role });
            }
            if parameters.ntru().cipher_modulus_value()
                != tfhe.bootstrapping().ntru().cipher_modulus_value()
            {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }
        let q = trace.ntru().cipher_modulus().value();
        if q & T::ONE != T::ONE || q >= T::ONE << (T::BITS - 1) {
            return Err(CircuitBootstrapParameterError::UnsupportedTraceModulus);
        }
        let many_lut_output_count = output
            .decompose_length()
            .checked_next_power_of_two()
            .ok_or(CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        let domain =
            primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), tfhe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if many_lut_output_count > tfhe.poly_length() / domain {
            return Err(CircuitBootstrapParameterError::OutputDecompositionTooLarge);
        }
        Ok(Self {
            output,
            trace,
            scheme_switch,
            input_plain_modulus: tfhe.plain_modulus_value(),
            many_lut_output_count,
        })
    }

    /// Returns the input NLev/output NGSW basis and layout.
    #[must_use]
    pub fn output(&self) -> &NlevParameters<T, BarrettModulus<T>> {
        &self.output
    }

    /// Returns the reverse-trace key's encryption parameters.
    #[must_use]
    pub fn trace(&self) -> &NlevParameters<T, BarrettModulus<T>> {
        &self.trace
    }

    /// Returns the scheme-switch key's encryption parameters.
    #[must_use]
    pub fn scheme_switch(&self) -> &NlevParameters<T, BarrettModulus<T>> {
        &self.scheme_switch
    }

    /// Returns the padded power-of-two output count for the internal ManyLUT.
    #[must_use]
    pub fn many_lut_output_count(&self) -> usize {
        self.many_lut_output_count
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        self.input_plain_modulus == tfhe.plain_modulus_value()
            && self.output.poly_length() == tfhe.poly_length()
            && self.output.ntru().cipher_modulus_value()
                == tfhe.bootstrapping().ntru().cipher_modulus_value()
    }
}
