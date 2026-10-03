//! Shared parameter validation for NTRU circuit bootstrapping.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParametersInner};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use std::sync::Arc;

use crate::{CircuitBootstrapConfig, CircuitBootstrapParameterError, TfheParameters};

/// Optional CBS parameters, separate from ordinary PBS server-key parameters.
///
/// The TFHE context supplies BR parameters. Trace, scheme-switch and output
/// bases are independent. The scheme-switch key binds the complete output basis.
/// The BR basis must resolve the smallest programmed output gadget scale.
/// Construction checks domains and layouts; program binding checks ManyLUT capacity.
/// Neither validates noise, failure probability or security. In particular the scheme-switch
/// key encrypts secret-dependent messages and multiplies errors by f and f²;
/// ordinary PBS parameters are not automatically valid CBS parameters.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint, M: RingContext<T>> {
    output_basis: ApproxSignedBasis<T>,
    poly_length: PolyLength,
    output_nlev_len: usize,
    trace: NlevParameters<T, M>,
    scheme_switch: NlevParameters<T, M>,
}

impl<T: FheUint, M: RingContext<T>> CircuitBootstrapParameters<T, M> {
    /// Derives all CBS ring domains from TFHE, keeping bases and noise independent.
    ///
    /// Returns basis, layout or sampler errors; input encoding and capacity belong to programs.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// Invalid key noise/sampler parameters are returned with their key role.
    pub fn try_from_config<LM: RingContext<T>>(
        tfhe: &TfheParameters<T, M, LM>,
        config: CircuitBootstrapConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.accumulator_ntru();
        let output_basis = config
            .output
            .try_build(accumulator.cipher_modulus_value())?;
        let key_parameters = |role, decomposition: crate::DecompositionConfig, noise| {
            // Each key role has its own encryption noise and needs no codec.
            let inner = NtruParametersInner::try_new(
                accumulator.poly_length(),
                accumulator.cipher_modulus(),
                accumulator.secret_key_distr(),
                noise,
            )
            .map_err(|source| {
                CircuitBootstrapParameterError::EncryptionParameters { role, source }
            })?;
            let basis = decomposition
                .try_build(accumulator.cipher_modulus_value())
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters {
                    role,
                    source: source.into(),
                })?;
            NlevParameters::try_from_parts(Arc::new(inner), basis)
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

    /// Checks the accumulator ring, modulus and output layout independently of input encoding.
    /// The output layout is derived from the TFHE accumulator and `output_basis`.
    pub fn try_new<LM: RingContext<T>>(
        tfhe: &TfheParameters<T, M, LM>,
        output_basis: ApproxSignedBasis<T>,
        trace: NlevParameters<T, M>,
        scheme_switch: NlevParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        if output_basis.modulus() != tfhe.accumulator_ntru().cipher_modulus_value() {
            return Err(CircuitBootstrapParameterError::OutputBasisModulusMismatch);
        }
        for (role, parameters) in [("trace", &trace), ("scheme-switch", &scheme_switch)] {
            if parameters.poly_length() != tfhe.poly_length() {
                return Err(CircuitBootstrapParameterError::PolynomialLengthMismatch { role });
            }
            if parameters.inner().cipher_modulus_value()
                != tfhe.accumulator_ntru().cipher_modulus_value()
            {
                return Err(CircuitBootstrapParameterError::CipherModulusMismatch { role });
            }
        }
        // Explicit-modulus trace uses modular halving. Native trace instead
        // uses coefficient halving with a distinct rounding-error contract.
        if let Some(q) = trace.inner().cipher_modulus_value()
            && (q & T::ONE != T::ONE || q >= T::ONE << (T::BITS - 1))
        {
            return Err(CircuitBootstrapParameterError::UnsupportedTraceModulus);
        }
        let poly_length = tfhe.poly_length();
        // N <= 2^17 and levels <= 32 keep their product within usize.
        let output_nlev_len = poly_length.get() * output_basis.decompose_length().get();
        Ok(Self {
            output_basis,
            poly_length,
            output_nlev_len,
            trace,
            scheme_switch,
        })
    }

    /// Compiles the gadget-scaled identity for a selected Rounded input encoding.
    ///
    /// Checks front-half geometry and interleaved output capacity here,
    /// rather than at key generation. The same CBS material may serve another t
    /// when its program fits. Output values are gadget scalars, not codec-scaled
    /// messages. These parameters own Q only; backend binding checks the input
    /// codec against external q. Callers must budget input, trace and scheme-switch noise.
    pub fn compile_lookup_table<LM: RingContext<T>>(
        &self,
        input_codec: &primus_encoding::RoundedCodec<T, LM>,
    ) -> Result<primus_tfhe::InterleavedLookupTable<T>, primus_tfhe::LookupTableError> {
        use primus_tfhe::{InterleavedLookupTable, LookupTableError, front_half_domain_len};
        let modulus = self.trace.inner().cipher_modulus();
        let poly_length = self.poly_length;
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

    /// Returns the accumulator polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
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
    pub fn trace(&self) -> &NlevParameters<T, M> {
        &self.trace
    }

    /// Returns the scheme-switch key's encryption parameters.
    #[must_use]
    pub fn scheme_switch(&self) -> &NlevParameters<T, M> {
        &self.scheme_switch
    }

    /// Returns the LUT padded output count for the output gadget levels.
    #[must_use]
    pub fn lookup_table_padded_output_count(&self) -> usize {
        self.output_basis
            .decompose_length()
            .get()
            .next_power_of_two()
    }

    /// Checks the accumulator ring and modulus independently of message encoding.
    /// This does not establish noise margins or secret/transform identity.
    #[must_use]
    pub fn is_compatible<LM: RingContext<T>>(&self, tfhe: &TfheParameters<T, M, LM>) -> bool {
        self.poly_length == tfhe.poly_length()
            && self.output_basis.modulus() == tfhe.accumulator_ntru().cipher_modulus_value()
    }
}

impl<T: FheUint> CircuitBootstrapParameters<T, NativeModulus<T>> {
    /// Returns the number of complex values in the output Fourier NLev/NGSW.
    #[must_use]
    #[inline]
    pub fn output_fourier_nlev_len(&self) -> usize {
        self.output_nlev_len / 2
    }
}
