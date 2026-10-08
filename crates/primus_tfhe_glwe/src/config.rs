//! Complete numerical operation configs, separate from prepared sampling state.

use primus_glwe::GlweDimension;
use primus_integer::FheUint;
use primus_poly::PolyLength;
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::{BlindRotationAlgorithm, LweConfig, ModulusConfig, ModulusConfigError};

use crate::{
    CbsGadgetConfig, CbsParameters, CircuitBootstrapParameterError, GadgetEncryptionConfig,
    PbsMessageConfig, PbsOrder, PbsParameters, SecretKeyDistr, TfheParameterError,
};

/// Shared small-LWE and accumulator choices for GLWE blind rotation.
///
/// Contains only numerical data; modulus reducers, bases and samplers are
/// prepared at setup. The LWE and ring share one ciphertext modulus.
#[derive(Debug, Clone, Copy)]
pub struct BlindRotationConfig<M: Modulus> {
    /// Small BR-control LWE domain; external for BR→KS.
    pub small_lwe: LweConfig<M>,
    /// GLWE mask-polynomial count shared by the accumulator and BSK ciphertexts.
    pub acc_dimension: GlweDimension,
    /// Ring polynomial length N shared by the accumulator and BSK ciphertexts.
    pub acc_poly_length: PolyLength,
    /// Distribution for sampling the GLWE secret that encrypts BSK ciphertexts.
    ///
    /// BR output uses this same secret; the public `(0, LUT * X^(-b))`
    /// accumulator initialization needs no secret. The input LWE secret encoded
    /// by the BSK is configured separately in `small_lwe.secret_key_distr`.
    pub bsk_secret_distr: SecretKeyDistr,
    /// BSK GGSW decomposition and coefficient-unit encryption noise.
    ///
    /// Ring encryption clients reuse this noise setting. Public GLWE accumulator
    /// initialization samples no encryption noise.
    pub bsk_gadget: GadgetEncryptionConfig,
    /// Algorithm selected when generating material; never chosen during evaluation.
    pub algorithm: BlindRotationAlgorithm,
}

/// Complete ordinary PBS/ManyLUT/MVB numerical choices and default message domains.
///
/// Choose Rounded or factorized Scaled outputs through the prepared parameters'
/// codec factory. Modifying `messages.output_modulus` does not change the keys;
/// the caller must establish the new operation's noise budget.
#[derive(Debug, Clone, Copy)]
pub struct PbsConfig<T: FheUint, M: RingContext<T>> {
    /// Default input/output message moduli; programs can choose other compatible codecs.
    pub messages: PbsMessageConfig<T>,
    /// Shared blind-rotation domain and algorithm.
    pub blind_rotation: BlindRotationConfig<M>,
    /// Independent ring-KS decomposition and coefficient-unit row noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Determines the external LWE secret and placement of ring KS.
    pub order: PbsOrder,
}

/// Input preparation required by ring-output GLWE circuit bootstrapping.
#[derive(Debug, Clone, Copy)]
pub enum CbsInput {
    /// External ciphertexts already use the small LWE secret; no KS is prepared.
    Direct,
    /// External ciphertexts use the accumulator secret; ring KS precedes BR.
    Keyswitch {
        /// Input ring-KS decomposition and coefficient-unit row noise.
        key_switching: GadgetEncryptionConfig,
    },
}

/// Complete CBS numerical choices; candidate ring messages belong to the consumer.
///
/// One input message domain produces gadget controls, not ordinarily encoded LWE
/// outputs. BR→KS therefore needs no return-KS configuration or output codec.
#[derive(Debug, Clone, Copy)]
pub struct CbsConfig<T: FheUint, M: RingContext<T>> {
    /// Shared blind-rotation domain and algorithm.
    pub blind_rotation: BlindRotationConfig<M>,
    /// Trace, scheme-switch and output gadget decompositions.
    pub gadget: CbsGadgetConfig,
    /// Rounded selector-input plaintext modulus, including padding.
    pub input_modulus: T,
    /// Direct small-LWE input or the required KS→BR input preparation.
    pub input: CbsInput,
}

impl<M: Modulus> BlindRotationConfig<M> {
    /// Prepares a BR→KS ring-output prefix without any unused output KS.
    pub fn try_prepare<T: FheUint>(self) -> Result<PbsParameters<T, M>, TfheParameterError>
    where
        M: RingContext<T> + TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
    {
        let small_lwe = self
            .small_lwe
            .try_prepare()
            .map_err(TfheParameterError::InputParameters)?;
        let blind_rotation = crate::parameters::prepare_blind_rotation(
            small_lwe.cipher_modulus(),
            self.acc_dimension,
            self.acc_poly_length,
            self.bsk_secret_distr,
            self.bsk_gadget,
        )?;
        PbsParameters::try_without_key_switching(small_lwe, blind_rotation)
    }
}

impl<T: FheUint, M: RingContext<T>> PbsConfig<T, M> {
    /// Prepares shared BR and independent KS sampling state, without choosing a codec.
    ///
    /// This checks numerical/layout contracts, not security or a joint noise budget.
    pub fn try_prepare(self) -> Result<PbsParameters<T, M>, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
    {
        self.blind_rotation
            .try_prepare()?
            .try_with_key_switching(self.key_switching, self.order)
    }
}

impl<T: FheUint, M: RingContext<T>> CbsConfig<T, M> {
    /// Prepares BR and only the input KS required by this CBS order.
    ///
    /// Trace/scheme-switch state is prepared by [`Self::try_cbs_parameters`] or
    /// by backend key generation using `gadget`. No output-return sampler is built.
    pub fn try_prepare(self) -> Result<PbsParameters<T, M>, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
    {
        let parameters = self.blind_rotation.try_prepare()?;
        match self.input {
            CbsInput::Direct => Ok(parameters),
            CbsInput::Keyswitch { key_switching } => {
                parameters.try_with_key_switching(key_switching, PbsOrder::KeyswitchBootstrap)
            }
        }
    }

    /// Derives trace/scheme-switch state and the output gadget in this prepared ring.
    pub fn try_cbs_parameters(
        self,
        parameters: &PbsParameters<T, M>,
    ) -> Result<CbsParameters<T, M>, CircuitBootstrapParameterError> {
        CbsParameters::try_from_config(parameters, self.gadget)
    }
}
