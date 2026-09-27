use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_tfhe::rotation::RotationQuantizer;

use crate::TfheParameterError;
/// NTRU-TFHE choices with independent accumulator Q and external LWE q domains.
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// External LWE dimension, moduli, secret distribution and fresh encryption noise.
    pub external_lwe: LweParameters<T, LM>,
    /// Accumulator ciphertext modulus Q, independent of external q.
    pub accumulator_modulus: M,
    /// Common NTRU polynomial length `N`.
    pub poly_length: usize,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Standard deviation for accumulator and blind-rotation-key encryption.
    pub accumulator_noise_standard_deviation: f64,
    /// NLev initializer and NGSW control decomposition.
    pub blind_rotation: DecompositionConfig,
    /// Decomposition at q for the post-bootstrap LWE key switch.
    pub key_switching: DecompositionConfig,
    /// Standard deviation for return-key LWE encryption under the external secret.
    pub key_switching_noise_standard_deviation: f64,
}

/// Mathematical parameters for NTRU-based TFHE.
///
/// Blind rotation operates under ring secret f at Q; the return key encrypts
/// its coefficients under independent LWE secret s at q.
#[derive(Clone)]
pub struct TfheParameters<T, M, LM = M>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    external_lwe: LweParameters<T, LM>,
    blind_rotation: NlevParameters<T, M>,
    key_switching_lwe: LweParameters<T, LM>,
    key_switching_basis: ApproxSignedBasis<T>,
    rotation_quantizer: RotationQuantizer<LM::Prepared>,
}

impl<T, M, LM> TfheParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    /// Derives the accumulator and external LWE return domains from named choices.
    ///
    /// # Panics
    /// Inherits [`NtruParameters::new`] and [`LweParameters::new`]'s sampler and codec requirements.
    pub fn try_from_config(config: TfheConfig<T, M, LM>) -> Result<Self, TfheParameterError> {
        let accumulator = NtruParameters::new(
            config.poly_length,
            config.external_lwe.plain_modulus_value(),
            config.accumulator_modulus,
            config.accumulator_secret_key_distr,
            config.accumulator_noise_standard_deviation,
        );
        let blind_rotation = NlevParameters::try_with_ntru_params(
            &accumulator,
            config.blind_rotation.log_basis,
            config.blind_rotation.level_count,
        )
        .map_err(TfheParameterError::BootstrappingParameters)?;
        Self::try_new(
            config.external_lwe,
            blind_rotation,
            config.key_switching,
            config.key_switching_noise_standard_deviation,
        )
    }

    /// Binds independent external LWE and accumulator domains with a return decomposition at q.
    /// External secrets must be binary or ternary; their dimension need not fit in N.
    /// Both domains must share plaintext modulus t, and 2N must fit in T.
    ///
    /// # Panics
    /// Inherits [`LweParameters::new`]'s noise-sampler requirements.
    pub fn try_new(
        external_lwe: LweParameters<T, LM>,
        blind_rotation: NlevParameters<T, M>,
        key_switching: DecompositionConfig,
        key_switching_noise_standard_deviation: f64,
    ) -> Result<Self, TfheParameterError> {
        let distr = external_lwe.secret_key_distr();
        if !(distr.is_binary() || distr.is_ternary()) {
            return Err(TfheParameterError::UnsupportedClientSecretKeyDistribution);
        }
        if external_lwe.plain_modulus_value() != blind_rotation.ntru().plain_modulus() {
            return Err(TfheParameterError::PlainModulusMismatch);
        }
        let two_n = blind_rotation
            .poly_length()
            .checked_mul(2)
            .filter(|&n| T::try_from(n).is_ok())
            .ok_or(TfheParameterError::RotationDomainTooLarge)?;
        let key_switching_basis = ApproxSignedBasis::try_new(
            external_lwe.cipher_modulus_value(),
            key_switching.log_basis,
            key_switching.level_count,
        )
        .map_err(TfheParameterError::KeySwitchingParameters)?;
        let key_switching_lwe = LweParameters::new(
            external_lwe.dimension(),
            external_lwe.plain_modulus_value(),
            external_lwe.cipher_modulus(),
            distr,
            key_switching_noise_standard_deviation,
        );
        let rotation_quantizer = RotationQuantizer::new(external_lwe.cipher_modulus(), two_n, 1);
        Ok(Self {
            external_lwe,
            blind_rotation,
            key_switching_lwe,
            key_switching_basis,
            rotation_quantizer,
        })
    }

    /// Returns the ordinary-PBS quantizer prepared with these parameters.
    #[doc(hidden)]
    #[must_use]
    pub fn rotation_quantizer(&self) -> RotationQuantizer<LM::Prepared> {
        self.rotation_quantizer
    }

    /// Returns the externally visible LWE parameters.
    #[must_use]
    #[inline]
    pub fn external_lwe(&self) -> &LweParameters<T, LM> {
        &self.external_lwe
    }

    /// Returns the shared parameters of the NLev initializer and NGSW controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation(&self) -> &NlevParameters<T, M> {
        &self.blind_rotation
    }

    /// Returns the accumulator's NTRU encryption parameters.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru(&self) -> &NtruParameters<T, M> {
        self.blind_rotation.ntru()
    }

    /// Returns the dimension of externally visible LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe.dimension()
    }

    /// Returns the input LWE codec used by client encryption and LUT compilation.
    #[must_use]
    #[inline]
    pub fn input_plaintext_codec(&self) -> &RoundedCodec<T, LM> {
        self.external_lwe.plaintext_codec()
    }

    /// Returns the target-q LWE encryption parameters used for return key rows.
    #[must_use]
    pub fn key_switching_lwe(&self) -> &LweParameters<T, LM> {
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
    pub fn poly_length(&self) -> usize {
        self.blind_rotation.poly_length()
    }

    /// Returns the common plaintext modulus.
    #[must_use]
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.external_lwe.plain_modulus_value()
    }
}
