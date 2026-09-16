//! Independently selected gadget bases for NTRU circuit bootstrapping.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::TorusFftValue;
use primus_modulus::NativeModulus;
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
    /// The interleaving stride leaves too few programmable input slots.
    #[error("circuit-bootstrap output levels do not fit the ManyLUT accumulator")]
    OutputDecompositionTooLarge,
}

/// Optional CBS parameters, separate from ordinary PBS server-key parameters.
///
/// The TFHE context supplies BR parameters. Trace, scheme-switch and output
/// bases are independent. The scheme-switch key binds the complete output basis.
/// Construction checks layouts and ManyLUT capacity, not noise, failure
/// probability or security. In particular the scheme-switch
/// key encrypts secret-dependent messages and multiplies errors by f and f²;
/// ordinary PBS parameters are not automatically valid CBS parameters. Native
/// coefficient halving and FFT precision add errors distinct from the NTT path.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: TorusFftValue> {
    output_basis: ApproxSignedBasis<T>,
    poly_length: usize,
    output_nlev_len: usize,
    trace: NlevParameters<T, NativeModulus<T>>,
    scheme_switch: NlevParameters<T, NativeModulus<T>>,
    input_plain_modulus: T,
}

impl<T: TorusFftValue> CircuitBootstrapParameters<T> {
    /// Checks the accumulator length and capacity in the implicit native ring.
    /// The output layout is derived from the TFHE accumulator and `output_basis`.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, NativeModulus<T>>,
        scheme_switch: NlevParameters<T, NativeModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.bootstrapping().ntru().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.poly_length() != tfhe.poly_length() {
                return Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role });
            }
        }
        let lookup_table_stride = output_basis.decompose_length().next_power_of_two();
        let domain =
            primus_tfhe::lookup_table_domain_len(tfhe.plain_modulus_value(), tfhe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if lookup_table_stride > tfhe.poly_length() / domain {
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

    /// Returns the number of torus coefficients in the projected NLev.
    #[must_use]
    #[inline]
    pub fn output_nlev_len(&self) -> usize {
        self.output_nlev_len
    }

    /// Returns the number of complex values in the output Fourier NLev/NGSW.
    #[must_use]
    #[inline]
    pub fn output_fourier_nlev_len(&self) -> usize {
        self.output_nlev_len / 2
    }

    /// Returns the reverse-trace key's encryption parameters.
    #[must_use]
    pub fn trace(&self) -> &NlevParameters<T, NativeModulus<T>> {
        &self.trace
    }

    /// Returns the scheme-switch key's encryption parameters.
    #[must_use]
    pub fn scheme_switch(&self) -> &NlevParameters<T, NativeModulus<T>> {
        &self.scheme_switch
    }

    /// Returns the interleaving stride for the output gadget levels.
    #[must_use]
    pub fn lookup_table_stride(&self) -> usize {
        self.output_basis.decompose_length().next_power_of_two()
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        self.input_plain_modulus == tfhe.plain_modulus_value()
            && self.poly_length == tfhe.poly_length()
    }
}
