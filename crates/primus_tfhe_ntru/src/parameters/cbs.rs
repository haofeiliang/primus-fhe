//! Complete ring-output CBS preparation, independent of transform representation.

use crate::{CbsGadgetConfig, CbsGadgetParameters, PbsParameters, TfheParameterError};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Complete CBS/one-hot parameters: shared BR, prepared gadgets and selector encoding.
/// The PBS domain supplies KS for downstream LWE returns; CBS adds no
/// candidate-ring message codec. Both operations share the same PBS state.
/// Program capacity, one-hot geometry and the noise budget are checked separately.
#[derive(Clone)]
pub struct CbsParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    pbs: PbsParameters<T, M, LM>,
    gadget: CbsGadgetParameters<T, M>,
    input_codec: RoundedCodec<T, LM>,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> CbsParameters<T, M, LM> {
    /// Prepares one common domain, then adds CBS-specific gadgets and input encoding.
    pub fn try_from_config(
        pbs: crate::PbsConfig<T, M, LM>,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        Self::try_with_config(PbsParameters::try_from_config(pbs)?, gadget)
    }

    /// Adds CBS to an already prepared PBS domain without rebuilding its samplers.
    /// Selector encoding uses the domain's input message modulus. KS state is
    /// shared with downstream LWE returns.
    pub fn try_with_config(
        pbs: PbsParameters<T, M, LM>,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheParameterError> {
        let input_modulus = pbs.messages().input_modulus;
        let gadget = CbsGadgetParameters::try_from_config(&pbs, gadget)
            .map_err(TfheParameterError::CircuitBootstrap)?;
        let input_codec = RoundedCodec::try_new(input_modulus, pbs.external_lwe().cipher_modulus())
            .map_err(TfheParameterError::InputEncoding)?;
        Ok(Self {
            pbs,
            gadget,
            input_codec,
        })
    }

    /// Borrows the shared BR domain and selected algorithm.
    #[must_use]
    pub fn pbs_parameters(&self) -> &PbsParameters<T, M, LM> {
        &self.pbs
    }

    /// Borrows trace/scheme-switch parameters and the complete output basis.
    #[must_use]
    pub fn gadget(&self) -> &CbsGadgetParameters<T, M> {
        &self.gadget
    }

    /// Borrows the prepared Rounded selector-input encoding.
    #[must_use]
    pub fn input_codec(&self) -> &RoundedCodec<T, LM> {
        &self.input_codec
    }

    /// Checks an independently prepared common domain before Context composition.
    /// Metadata compatibility does not establish actual secret identity.
    fn check_pbs_pairing(
        &self,
        parameters: &PbsParameters<T, M, LM>,
    ) -> Result<(), TfheParameterError> {
        if !self.pbs.has_same_domain(parameters) || self.pbs.algorithm() != parameters.algorithm() {
            return Err(TfheParameterError::IncompatibleComponents);
        }
        Ok(())
    }

    /// Replaces the common owner after checking independent component pairing.
    /// Does not rebuild its samplers or the CBS gadgets.
    pub fn try_with_pbs_parameters(
        mut self,
        parameters: PbsParameters<T, M, LM>,
    ) -> Result<Self, TfheParameterError> {
        self.check_pbs_pairing(&parameters)?;
        self.pbs = parameters;
        Ok(self)
    }

    /// Moves out the common domain and CBS-only state without cloning samplers.
    #[must_use]
    #[allow(clippy::type_complexity)] // The three independently reusable owners.
    pub fn into_parts(
        self,
    ) -> (
        PbsParameters<T, M, LM>,
        CbsGadgetParameters<T, M>,
        RoundedCodec<T, LM>,
    ) {
        (self.pbs, self.gadget, self.input_codec)
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<PbsParameters<T, M, LM>>
    for CbsParameters<T, M, LM>
{
    fn as_ref(&self) -> &PbsParameters<T, M, LM> {
        &self.pbs
    }
}
