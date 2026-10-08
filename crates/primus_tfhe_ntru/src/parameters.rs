use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_ntru::{NlevParameters, NtruEncryptionParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe::rotation::RotationModulusSwitch;

use std::sync::Arc;

use crate::{GadgetEncryptionConfig, TfheParameterError};
/// Checked programmable-bootstrapping domains and sampling state for NTRU-based TFHE.
///
/// Blind rotation operates under ring secret f at Q; the return key encrypts
/// its coefficients under independent LWE secret s at q. Key parameters contain no
/// message encoding; clients and programs choose their codecs at binding.
/// CBS/one-hot reuse these PBS-stage domains and add [`crate::CbsParameters`].
/// Ring-output CBS/one-hot omit return-KS state; ordinary PBS and lookup add it
/// before return material generation or binding.
#[derive(Clone)]
pub struct PbsParameters<T, M, LM = M>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    external_lwe: LweEncryptionParameters<T, LM>,
    blind_rotation: NlevParameters<T, M>,
    key_switching: Option<ReturnParameters<T, LM>>,
    rotation_modulus_switch: RotationModulusSwitch<T>,
}

/// Return-only sampling state and decomposition, always present or absent together.
#[derive(Clone)]
struct ReturnParameters<T: FheUint, LM: RingContext<T>> {
    lwe: LweEncryptionParameters<T, LM>,
    basis: ApproxSignedBasis<T>,
}

impl<T, M, LM> PbsParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    /// Binds independent external LWE and accumulator domains with a return decomposition at q.
    /// External secrets must be binary or ternary; their dimension need not fit in N.
    /// The rotation domain 2N must fit in T; message codecs are bound separately.
    ///
    /// The BR gadget owns the accumulator ring/sampling state without a codec.
    /// The return key uses its own decomposition and coefficient-unit noise at
    /// external q, independently of fresh LWE noise and accumulator noise at Q.
    /// Returns domain, decomposition or return-key noise-sampler errors.
    pub fn try_new(
        external_lwe: LweEncryptionParameters<T, LM>,
        blind_rotation: NlevParameters<T, M>,
        key_switching: GadgetEncryptionConfig,
    ) -> Result<Self, TfheParameterError> {
        Self::try_without_key_switching(external_lwe, blind_rotation)?
            .try_with_key_switching(key_switching)
    }

    /// Prepares the shared BR domains without any LWE return basis or sampler.
    ///
    /// Ring-output CBS/one-hot use this path. Inherits [`Self::try_new`]'s
    /// input-secret and rotation-domain checks, without its return-key requirements.
    pub fn try_without_key_switching(
        external_lwe: LweEncryptionParameters<T, LM>,
        blind_rotation: NlevParameters<T, M>,
    ) -> Result<Self, TfheParameterError> {
        let distr = external_lwe.secret_key_distr();
        if !(distr.is_binary() || distr.is_ternary()) {
            return Err(TfheParameterError::UnsupportedClientSecretKeyDistribution);
        }
        let two_n = 2 * blind_rotation.poly_length().get();
        T::try_from(two_n).map_err(|_| TfheParameterError::RotationDomainTooLarge)?;
        let rotation_modulus_switch =
            RotationModulusSwitch::new(external_lwe.cipher_modulus(), two_n, 1);
        Ok(Self {
            external_lwe,
            blind_rotation,
            key_switching: None,
            rotation_modulus_switch,
        })
    }

    /// Adds or replaces the return-q decomposition and sampler in a checked BR setup.
    ///
    /// Consumes existing parameters without repeating BR/secret validation.
    /// Returns only new return-basis or noise-sampler errors.
    pub fn try_with_key_switching(
        mut self,
        key_switching: GadgetEncryptionConfig,
    ) -> Result<Self, TfheParameterError> {
        let basis = key_switching
            .decomposition
            .try_build(self.external_lwe.cipher_modulus_value())
            .map_err(TfheParameterError::KeySwitchingParameters)?;
        let lwe = LweEncryptionParameters::try_new(
            self.external_lwe.dimension(),
            self.external_lwe.cipher_modulus(),
            self.external_lwe.secret_key_distr(),
            key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        self.key_switching = Some(ReturnParameters { lwe, basis });
        Ok(self)
    }

    /// Returns the rotation modulus switch prepared for ordinary PBS.
    #[doc(hidden)]
    #[must_use]
    pub fn rotation_modulus_switch(&self) -> RotationModulusSwitch<T> {
        self.rotation_modulus_switch
    }

    /// Returns the externally visible LWE parameters.
    #[must_use]
    #[inline]
    pub fn external_lwe(&self) -> &LweEncryptionParameters<T, LM> {
        &self.external_lwe
    }

    /// Returns the shared parameters of the NLev initializer and NGSW controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation(&self) -> &NlevParameters<T, M> {
        &self.blind_rotation
    }

    /// Borrows the accumulator ring and samplers owned by the BR gadget, without a codec.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru(&self) -> &NtruEncryptionParameters<T, M> {
        self.blind_rotation.encryption_parameters()
    }

    /// Returns the dimension of externally visible LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        self.external_lwe.dimension()
    }

    /// Borrows the return-q sampler, absent in ring-output CBS/one-hot setups.
    #[must_use]
    pub fn key_switching_lwe(&self) -> Option<&LweEncryptionParameters<T, LM>> {
        self.key_switching
            .as_ref()
            .map(|parameters| &parameters.lwe)
    }

    /// Borrows the return-q basis, absent in ring-output CBS/one-hot setups.
    #[must_use]
    pub fn key_switching_basis(&self) -> Option<&ApproxSignedBasis<T>> {
        self.key_switching
            .as_ref()
            .map(|parameters| &parameters.basis)
    }

    /// Returns the common NTRU polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.blind_rotation.poly_length()
    }
}

/// Prepares shared NLev/NGSW state for numerical blind-rotation configs.
pub(crate) fn prepare_blind_rotation<T: FheUint, M: RingContext<T>>(
    poly_length: PolyLength,
    modulus: M,
    secret: SecretKeyDistr,
    gadget: GadgetEncryptionConfig,
) -> Result<NlevParameters<T, M>, TfheParameterError> {
    let accumulator = NtruEncryptionParameters::try_new(
        poly_length,
        modulus,
        secret,
        gadget.noise_standard_deviation,
    )
    .map_err(TfheParameterError::AccumulatorParameters)?;
    let basis = gadget
        .decomposition
        .try_build(accumulator.cipher_modulus_value())
        .map_err(|source| TfheParameterError::BootstrappingParameters(source.into()))?;
    NlevParameters::try_from_parts(Arc::new(accumulator), basis)
        .map_err(TfheParameterError::BootstrappingParameters)
}
