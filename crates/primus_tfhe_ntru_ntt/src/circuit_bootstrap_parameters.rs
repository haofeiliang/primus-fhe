//! Independently selected gadget bases for NTRU circuit bootstrapping.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntru::NlevParameters;

use crate::TfheParameters;

/// An incompatible circuit-bootstrap parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
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
/// bases are independent. The scheme-switch key binds the complete output basis.
/// Construction checks layouts and ManyLUT capacity, not noise, failure
/// probability or security. In particular the scheme-switch
/// key encrypts secret-dependent messages and multiplies errors by f and f²;
/// ordinary PBS parameters are not automatically valid CBS parameters.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint> {
    output_basis: ApproxSignedBasis<T>,
    poly_length: usize,
    output_nlev_len: usize,
    trace: NlevParameters<T, BarrettModulus<T>>,
    scheme_switch: NlevParameters<T, BarrettModulus<T>>,
    input_plain_modulus: T,
    many_lut_output_count: usize,
}

impl<T: FheUint> CircuitBootstrapParameters<T> {
    /// Checks the accumulator ring, modulus and capacity for the input domain.
    /// The output layout is derived from the TFHE accumulator and `output_basis`.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, BarrettModulus<T>>,
        scheme_switch: NlevParameters<T, BarrettModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.bootstrapping().ntru().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
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
        let many_lut_output_count = output_basis.decompose_length().next_power_of_two();
        let domain =
            primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), tfhe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if many_lut_output_count > tfhe.poly_length() / domain {
            return Err(CircuitBootstrapParameterError::OutputDecompositionTooLarge);
        }
        let poly_length = tfhe.poly_length();
        // N <= 2^17 and levels <= 32 keep their product within usize.
        let output_nlev_len = poly_length * output_basis.decompose_length();
        Ok(Self {
            output_basis,
            poly_length,
            output_nlev_len,
            trace,
            scheme_switch,
            input_plain_modulus: tfhe.plain_modulus_value(),
            many_lut_output_count,
        })
    }

    /// Returns the gadget basis of the output ciphertext.
    #[must_use]
    #[inline]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the accumulator polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the number of coefficient or NTT values in the output NLev/NGSW.
    #[must_use]
    #[inline]
    pub fn output_nlev_len(&self) -> usize {
        self.output_nlev_len
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
            && self.poly_length == tfhe.poly_length()
            && self.output_basis.modulus() == tfhe.bootstrapping().ntru().cipher_modulus_value()
    }
}
