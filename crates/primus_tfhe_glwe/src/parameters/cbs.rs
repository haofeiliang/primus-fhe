//! Complete ring-output CBS preparation, independent of transform representation.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    CircuitBootstrapLookupTable, LookupTableError, ModulusConfig, ModulusConfigError,
};

use crate::{
    CbsGadgetConfig, CbsGadgetParameters, PbsConfig, PbsOrder, PbsParameters, TfheParameterError,
};

/// Complete CBS parameters: shared BR, prepared gadgets and selector encoding.
/// The PBS domain supplies KS for downstream LWE returns; CBS adds no
/// candidate-ring message codec. Both operations share the same PBS state.
/// Program capacity and the noise budget are checked separately.
#[derive(Clone)]
pub struct CbsParameters<T: FheUint, M: RingContext<T>> {
    pbs: PbsParameters<T, M>,
    gadget: CbsGadgetParameters<T, M>,
    input_codec: RoundedCodec<T, M>,
}

impl<T: FheUint, M: RingContext<T>> CbsParameters<T, M> {
    /// Prepares one common domain, then adds CBS-specific gadgets and input encoding.
    pub fn try_from_config(
        pbs: PbsConfig<T, M>,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
    {
        Self::try_with_config(PbsParameters::try_from_config(pbs)?, gadget)
    }

    /// Adds CBS to an already prepared PBS domain without rebuilding its samplers.
    /// Selector encoding uses the domain's input message modulus. Existing KS state
    /// is shared with input preparation and downstream LWE returns.
    pub fn try_with_config(
        pbs: PbsParameters<T, M>,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheParameterError> {
        let input_modulus = pbs.messages().input_modulus;
        let gadget = CbsGadgetParameters::try_from_config(&pbs, gadget)
            .map_err(TfheParameterError::CircuitBootstrap)?;
        let input_codec = RoundedCodec::try_new(input_modulus, pbs.cipher_modulus())
            .map_err(TfheParameterError::InputEncoding)?;
        Ok(Self {
            pbs,
            gadget,
            input_codec,
        })
    }

    /// Borrows the shared BR domain and selected algorithm.
    #[must_use]
    pub fn pbs_parameters(&self) -> &PbsParameters<T, M> {
        &self.pbs
    }

    /// Borrows trace/scheme-switch parameters and the complete output basis.
    #[must_use]
    pub fn gadget(&self) -> &CbsGadgetParameters<T, M> {
        &self.gadget
    }

    /// Borrows the prepared Rounded selector-input encoding.
    #[must_use]
    pub fn input_codec(&self) -> &RoundedCodec<T, M> {
        &self.input_codec
    }

    /// Compiles the gadget identity F(m)=m using the retained input encoding.
    /// The output is a gadget control, independently of ordinary PBS's output codec.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain and noise contracts.
    pub fn compile_lookup_table(&self) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.gadget.compile_lookup_table(&self.input_codec)
    }

    /// Compiles F on the complete unsigned Rounded domain `0..ceil(t_in/2)`.
    /// Each result is a canonical ring integer; CMux requires every result to be
    /// a bit. Encoding validity and capacity do not establish a CBS noise margin.
    /// Inherits [`CbsGadgetParameters::compile_lookup_table_fn`]'s contracts.
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        self.gadget
            .compile_lookup_table_fn(&self.input_codec, function)
    }

    /// Compiles the complete F(0), ..., F(ceil(t_in/2)-1) slice.
    /// Inherits [`Self::compile_lookup_table_fn`]'s domain, result and noise contracts;
    /// rejects both missing and extra entries before compilation.
    pub fn compile_lookup_table_slice(
        &self,
        values: &[T],
    ) -> Result<CircuitBootstrapLookupTable<T>, LookupTableError> {
        self.gadget
            .compile_lookup_table_slice(&self.input_codec, values)
    }

    /// Checks an independently prepared common domain before Context composition.
    /// Metadata compatibility does not establish actual secret identity.
    fn check_pbs_pairing(
        &self,
        parameters: &PbsParameters<T, M>,
    ) -> Result<(), TfheParameterError> {
        if !self.pbs.has_same_domain(parameters)
            || self.pbs.blind_rotation_method() != parameters.blind_rotation_method()
            || self.input_codec.plaintext_modulus() != parameters.messages().input_modulus
        {
            return Err(TfheParameterError::IncompatibleComponents);
        }
        // Only KS→BR changes CBS's input phase. Return KS is not consumed here.
        if self.pbs.pbs_order() == PbsOrder::KeyswitchBootstrap {
            let lhs = self.pbs.glwe_key_switching().output();
            let rhs = parameters.glwe_key_switching().output();
            if lhs.basis() != rhs.basis()
                || lhs.noise_standard_deviation() != rhs.noise_standard_deviation()
            {
                return Err(TfheParameterError::IncompatibleComponents);
            }
        }
        Ok(())
    }

    /// Replaces the common owner after checking independent component pairing.
    /// The input message modulus must retain the prepared CBS encoding;
    /// ordinary PBS may independently choose another output message modulus.
    /// Does not rebuild its samplers or the CBS gadgets.
    pub fn try_with_pbs_parameters(
        mut self,
        parameters: PbsParameters<T, M>,
    ) -> Result<Self, TfheParameterError> {
        self.check_pbs_pairing(&parameters)?;
        self.pbs = parameters;
        Ok(self)
    }

    /// Moves out the common domain and CBS-only state without cloning samplers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PbsParameters<T, M>,
        CbsGadgetParameters<T, M>,
        RoundedCodec<T, M>,
    ) {
        (self.pbs, self.gadget, self.input_codec)
    }
}

impl<T: FheUint, M: RingContext<T>> AsRef<PbsParameters<T, M>> for CbsParameters<T, M> {
    fn as_ref(&self) -> &PbsParameters<T, M> {
        &self.pbs
    }
}
