use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_ntru::{NlevParameters, NtruEncryptionParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe::rotation::RotationModulusSwitch;

use std::sync::Arc;

use crate::{GadgetEncryptionConfig, TfheParameterError};
/// NTRU-TFHE choices with independent accumulator Q and external LWE q domains.
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// External LWE dimension, ciphertext modulus q, secret distribution and fresh encryption noise.
    pub external_lwe: LweEncryptionParameters<T, LM>,
    /// Accumulator ciphertext modulus Q, independent of external q.
    pub accumulator_modulus: M,
    /// Common NTRU polynomial length `N`.
    pub poly_length: PolyLength,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Coefficient-unit standard deviation at Q for accumulator and BR-key encryption.
    pub accumulator_noise_standard_deviation: f64,
    /// NLev initializer and NGSW control decomposition.
    pub blind_rotation: DecompositionConfig,
    /// Post-bootstrap LWE key-switch decomposition and row noise at external q.
    pub key_switching: GadgetEncryptionConfig,
}

/// Mathematical parameters for NTRU-based TFHE.
///
/// Blind rotation operates under ring secret f at Q; the return key encrypts
/// its coefficients under independent LWE secret s at q. Key parameters contain no
/// message encoding; clients and programs choose their codecs at binding.
#[derive(Clone)]
pub struct TfheParameters<T, M, LM = M>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    external_lwe: LweEncryptionParameters<T, LM>,
    blind_rotation: NlevParameters<T, M>,
    key_switching_lwe: LweEncryptionParameters<T, LM>,
    key_switching_basis: ApproxSignedBasis<T>,
    rotation_modulus_switch: RotationModulusSwitch<T>,
}

impl<T, M, LM> TfheParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    /// Derives the accumulator and external LWE return domains from named choices.
    ///
    /// Returns accumulator/return-key construction and compatibility errors.
    /// This does not validate a noise/security budget or NTRU invertibility.
    pub fn try_from_config(config: TfheConfig<T, M, LM>) -> Result<Self, TfheParameterError> {
        let accumulator = NtruEncryptionParameters::try_new(
            config.poly_length,
            config.accumulator_modulus,
            config.accumulator_secret_key_distr,
            config.accumulator_noise_standard_deviation,
        )
        .map_err(TfheParameterError::AccumulatorParameters)?;
        let basis = config
            .blind_rotation
            .try_build(accumulator.cipher_modulus_value())
            .map_err(|source| TfheParameterError::BootstrappingParameters(source.into()))?;
        let blind_rotation = NlevParameters::try_from_parts(Arc::new(accumulator), basis)
            .map_err(TfheParameterError::BootstrappingParameters)?;
        Self::try_new(config.external_lwe, blind_rotation, config.key_switching)
    }

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
        let distr = external_lwe.secret_key_distr();
        if !(distr.is_binary() || distr.is_ternary()) {
            return Err(TfheParameterError::UnsupportedClientSecretKeyDistribution);
        }
        let two_n = 2 * blind_rotation.poly_length().get();
        T::try_from(two_n).map_err(|_| TfheParameterError::RotationDomainTooLarge)?;
        let key_switching_basis = key_switching
            .decomposition
            .try_build(external_lwe.cipher_modulus_value())
            .map_err(TfheParameterError::KeySwitchingParameters)?;
        let key_switching_lwe = LweEncryptionParameters::try_new(
            external_lwe.dimension(),
            external_lwe.cipher_modulus(),
            distr,
            key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        let rotation_modulus_switch =
            RotationModulusSwitch::new(external_lwe.cipher_modulus(), two_n, 1);
        Ok(Self {
            external_lwe,
            blind_rotation,
            key_switching_lwe,
            key_switching_basis,
            rotation_modulus_switch,
        })
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

    /// Returns the target-q LWE encryption parameters used for return key rows.
    #[must_use]
    pub fn key_switching_lwe(&self) -> &LweEncryptionParameters<T, LM> {
        &self.key_switching_lwe
    }

    /// Returns the return-key decomposition at external modulus q.
    #[must_use]
    pub fn key_switching_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_switching_basis
    }

    /// Returns the common NTRU polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.blind_rotation.poly_length()
    }
}
