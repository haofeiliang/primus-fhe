//! Complete numerical operation configs, before preparing samplers and bases.

use primus_integer::FheUint;
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::{BlindRotationAlgorithm, LweConfig, ModulusConfig, ModulusConfigError};

use crate::{
    CbsGadgetConfig, CbsParameters, CircuitBootstrapParameterError, GadgetEncryptionConfig,
    PbsMessageConfig, PbsParameters, TfheParameterError,
};

/// Shared NTRU blind-rotation choices with independent external q and ring Q.
///
/// Only numerical data is retained. Return KS is an operation choice: ordinary
/// PBS and high-precision lookup need it; ring-output CBS/one-hot do not.
#[derive(Debug, Clone, Copy)]
pub struct BlindRotationConfig<M: Modulus, LM: Modulus = M> {
    /// External LWE secret, q and fresh-encryption noise.
    pub external_lwe: LweConfig<LM>,
    /// Ring Q and reduction representation shared by the accumulator and BSK ciphertexts.
    pub acc_modulus: ModulusConfig<M>,
    /// Ring polynomial length N shared by the accumulator and BSK ciphertexts.
    pub acc_poly_length: PolyLength,
    /// Distribution for sampling the NTRU secret that encrypts BSK ciphertexts.
    ///
    /// BR output uses this same secret. The input LWE secret encoded by the
    /// BSK is configured separately in `external_lwe.secret_key_distr`.
    pub bsk_secret_distr: SecretKeyDistr,
    /// BSK NLev/NGSW decomposition and coefficient-unit encryption noise at Q.
    ///
    /// Ring encryption clients reuse this noise setting. Preparing the public LUT
    /// samples no encryption noise; BR lifting and controls propagate key-row noise.
    pub bsk_gadget: GadgetEncryptionConfig,
    /// Algorithm selected during material generation, not during evaluation.
    pub algorithm: BlindRotationAlgorithm,
}

/// Complete ordinary PBS/ManyLUT/MVB numerical choices and default message domains.
#[derive(Debug, Clone, Copy)]
pub struct PbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// Shared blind-rotation domains and algorithm.
    pub blind_rotation: BlindRotationConfig<M, LM>,
    /// Independent return-q decomposition and coefficient-unit row noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Default input/output message moduli; output choices can be changed independently.
    pub messages: PbsMessageConfig<T>,
}

/// Complete ring-output CBS/one-hot numerical choices, without an unused return KS.
///
/// Candidate ring messages are chosen by the consumer. One-hot geometry is
/// derived from the input modulus, ring length and output decomposition.
#[derive(Debug, Clone, Copy)]
pub struct CbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// Shared blind-rotation domains and algorithm.
    pub blind_rotation: BlindRotationConfig<M, LM>,
    /// Trace, scheme-switch and output gadget decompositions.
    pub gadget: CbsGadgetConfig,
    /// Rounded selector-input plaintext modulus, including padding.
    pub input_modulus: T,
}

impl<M: Modulus, LM: Modulus> BlindRotationConfig<M, LM> {
    /// Prepares BR domains and samplers with no LWE return basis or sampler.
    ///
    /// Checks layouts, secret support and numerical representations; does not
    /// establish NTRU invertibility, security or a complete-operation noise budget.
    pub fn try_prepare<T: FheUint>(self) -> Result<PbsParameters<T, M, LM>, TfheParameterError>
    where
        M: RingContext<T> + TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: RingContext<T> + TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        let external_lwe = self
            .external_lwe
            .try_prepare()
            .map_err(TfheParameterError::InputParameters)?;
        let modulus = self
            .acc_modulus
            .try_build()
            .map_err(TfheParameterError::AccumulatorModulus)?;
        let blind_rotation = crate::parameters::prepare_blind_rotation(
            self.acc_poly_length,
            modulus,
            self.bsk_secret_distr,
            self.bsk_gadget,
        )?;
        PbsParameters::try_without_key_switching(external_lwe, blind_rotation)
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsConfig<T, M, LM> {
    /// Prepares BR and independent return-KS state; codecs remain operation-bound.
    pub fn try_prepare(self) -> Result<PbsParameters<T, M, LM>, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        self.blind_rotation
            .try_prepare()?
            .try_with_key_switching(self.key_switching)
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> CbsConfig<T, M, LM> {
    /// Prepares BR domains without any unused LWE return state.
    /// Trace/scheme-switch state is prepared separately by key generation or
    /// [`Self::try_cbs_parameters`], inheriting the checked accumulator samplers.
    pub fn try_prepare(self) -> Result<PbsParameters<T, M, LM>, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        self.blind_rotation.try_prepare()
    }

    /// Derives trace/scheme-switch state and the output gadget in this prepared ring.
    pub fn try_cbs_parameters(
        self,
        parameters: &PbsParameters<T, M, LM>,
    ) -> Result<CbsParameters<T, M>, CircuitBootstrapParameterError> {
        CbsParameters::try_from_config(parameters, self.gadget)
    }
}
