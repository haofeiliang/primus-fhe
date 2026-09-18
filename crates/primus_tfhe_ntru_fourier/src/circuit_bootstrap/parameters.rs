//! Independently selected gadget bases for NTRU circuit bootstrapping.

use primus_decompose::{ApproxSignedBasisError, primitive::ApproxSignedBasis};
use primus_fft::TorusFftValue;
use primus_modulus::NativeModulus;
use primus_ntru::NlevParameters;

use crate::{CircuitBootstrapConfig, TfheParameters};

/// An incompatible circuit-bootstrap parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// The configured output radix or retained-level count is invalid.
    #[error("invalid circuit-bootstrap output basis: {0}")]
    InvalidOutputBasis(#[from] ApproxSignedBasisError),
    /// A configured key decomposition or derived gadget layout is invalid.
    #[error("invalid circuit-bootstrap {role} parameters: {source}")]
    GadgetParameters {
        /// Key role: trace or scheme-switch.
        role: &'static str,
        /// Invalid basis or gadget layout.
        #[source]
        source: primus_ntru::NlevParameterError,
    },
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses another ring length.
    #[error("circuit-bootstrap {role} polynomial length differs from the accumulator")]
    PolynomialLengthMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// The LUT padded output count leaves too few programmable input slots.
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
    /// Derives all CBS ring domains from TFHE, keeping bases and noise independent.
    ///
    /// Returns basis/layout errors or insufficient interleaved LUT capacity.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// # Panics
    ///
    /// Inherits [`primus_ntru::NtruParameters::new`]'s noise sampler requirements.
    pub fn try_from_config(
        tfhe: &TfheParameters<T>,
        config: CircuitBootstrapConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.accumulator_ntru();
        let output_basis = config.output.try_build(accumulator.cipher_modulus())?;
        let key_parameters = |role, decomposition: crate::DecompositionConfig, noise| {
            let ring = primus_ntru::NtruParameters::new(
                accumulator.poly_length(),
                accumulator.plain_modulus(),
                accumulator.cipher_modulus(),
                accumulator.secret_key_distr(),
                noise,
            );
            NlevParameters::try_with_ntru_params(
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

    /// Checks the accumulator length and capacity in the implicit native ring.
    /// The output layout is derived from the TFHE accumulator and `output_basis`.
    pub fn try_new(
        tfhe: &TfheParameters<T>,
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, NativeModulus<T>>,
        scheme_switch: NlevParameters<T, NativeModulus<T>>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.accumulator_ntru().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.poly_length() != tfhe.poly_length() {
                return Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role });
            }
        }
        let lookup_table_padded_output_count = output_basis.decompose_length().next_power_of_two();
        let domain =
            primus_tfhe::front_half_domain_len(tfhe.plain_modulus_value(), tfhe.poly_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        if lookup_table_padded_output_count > tfhe.poly_length() / domain {
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

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis.decompose_length().next_power_of_two()
    }

    pub(crate) fn is_compatible(&self, tfhe: &TfheParameters<T>) -> bool {
        self.input_plain_modulus == tfhe.plain_modulus_value()
            && self.poly_length == tfhe.poly_length()
    }
}
