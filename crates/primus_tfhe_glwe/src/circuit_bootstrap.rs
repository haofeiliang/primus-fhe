//! Backend-independent parameters for GLWE circuit bootstrapping.

use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_encoding::RoundedCodec;
use primus_glwe::{GadgetSize, GgswParameters, GlevParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{CircuitBootstrapLookupTable, LookupTableError};

use crate::{CircuitBootstrapConfig, CircuitBootstrapParameterError, TfheParameters};

/// Independent parameters for GLWE circuit bootstrapping.
///
/// The output basis controls GGSW gadget scalars; its layout comes from the TFHE
/// accumulator. Input encoding and ManyLUT capacity belong to program compilation,
/// allowing these keys to serve more than one message program.
/// Trace and scheme switching retain independent bases. The config constructor
/// shares their immutable encryption state with the TFHE accumulator.
/// The scheme-switch key binds the output layout, so another
/// output basis with the same level count can reuse it.
///
/// Construction checks modulus, layout and decomposition. Callers must select
/// these parameters using a CBS noise and security analysis. Matching parameters
/// do not establish secret or transform identity; execution backends specify
/// their representation and numerical requirements.
#[derive(Clone)]
pub struct CircuitBootstrapParameters<T: FheUint, M: RingContext<T>> {
    trace: GlevParameters<T, M>,
    scheme_switch: GgswParameters<T, M>,
    output_basis: ApproxSignedBasis<T>,
    output_size: GadgetSize,
}

impl<T: FheUint, M: RingContext<T>> CircuitBootstrapParameters<T, M> {
    /// Derives CBS parameters from TFHE with independent gadget bases.
    ///
    /// Reuses the accumulator's validated layout and sampler state without preparing
    /// new samplers. All key rows use its fresh encryption noise and independent RNG draws.
    /// The derived components already share one domain; only new gadget layouts are checked.
    /// Returns basis or layout errors. Program capacity is checked at evaluation binding.
    /// The direct [`Self::try_new`] constructor also accepts prepared bases and
    /// independently constructed key parameters.
    ///
    /// Invalid trace and scheme-switch bases/layouts are returned with their key role.
    pub fn try_from_config(
        tfhe: &TfheParameters<T, M>,
        config: CircuitBootstrapConfig,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let accumulator = tfhe.blind_rotation_ggsw();
        let output_basis = config
            .output
            .try_build(accumulator.cipher_modulus().explicit_value())?;
        let key_parameters = |role, decomposition: DecompositionConfig| {
            let basis = decomposition
                .try_build(accumulator.cipher_modulus().explicit_value())
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters {
                    role,
                    source: source.into(),
                })?;
            accumulator
                .try_with_new_basis(basis)
                .map_err(|source| CircuitBootstrapParameterError::GadgetParameters { role, source })
        };
        let trace = key_parameters("trace", config.trace)?;
        let scheme_switch = key_parameters("scheme-switch", config.scheme_switch)?;
        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
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

        Self::try_from_matching_parts(output_basis, trace, scheme_switch)
    }

    /// Derives the output layout after the entry point has established a common
    /// accumulator domain, either by construction or by checking supplied components.
    fn try_from_matching_parts(
        output_basis: ApproxSignedBasis<T>,
        trace: GlevParameters<T, M>,
        scheme_switch: GgswParameters<T, M>,
    ) -> Result<Self, CircuitBootstrapParameterError> {
        let output_size =
            GadgetSize::try_new(trace.glwe_size(), output_basis.decompose_length())
                .map_err(|_| CircuitBootstrapParameterError::OutputDecompositionTooLarge)?;
        Ok(Self {
            output_basis,
            output_size,
            trace,
            scheme_switch,
        })
    }

    /// Compiles the gadget-scaled identity for a selected Rounded input encoding.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, capacity and noise contracts.
    pub fn compile_lookup_table(
        &self,
        input_codec: &RoundedCodec<T, M>,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.compile_lookup_table_fn(input_codec, T::as_from)
    }

    /// Compiles `g_j * F(m) mod Q` for every output gadget level j.
    ///
    /// Checks input q against the accumulator Q. Uses the complete
    /// unsigned front-half domain `0..ceil(t_in/2)`. Results must be canonical
    /// ring integers (less than explicit Q), rather than codec-scaled messages.
    /// The callback runs once per input during compilation; execution never calls it.
    /// Input geometry, capacity and results follow
    /// [`CircuitBootstrapLookupTable::try_from_fn`]. CMux requires every result
    /// in `{0, 1}`; other integers can be consumed by external products.
    /// Callers must budget BR, trace, scheme-switch and consumption noise.
    pub fn compile_lookup_table_fn<F>(
        &self,
        input_codec: &RoundedCodec<T, M>,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        if input_codec.ciphertext_modulus().explicit_value()
            != self.trace.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        CircuitBootstrapLookupTable::try_from_fn(
            self.output_size.glwe_size().poly_length(),
            input_codec,
            &self.output_basis,
            self.trace.cipher_modulus(),
            function,
        )
    }

    /// Compiles the complete slice of integer results indexed by input message.
    /// Inherits [`Self::compile_lookup_table_fn`]'s gadget, domain and noise contracts.
    /// Missing or extra entries return [`LookupTableError::DomainLengthMismatch`].
    pub fn compile_lookup_table_slice(
        &self,
        input_codec: &RoundedCodec<T, M>,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        if input_codec.ciphertext_modulus().explicit_value()
            != self.trace.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        CircuitBootstrapLookupTable::try_from_slice(
            self.output_size.glwe_size().poly_length(),
            input_codec,
            &self.output_basis,
            self.trace.cipher_modulus(),
            values,
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
