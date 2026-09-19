use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_tfhe::DecompositionConfig;
use primus_tfhe::rotation::RotationQuantizer;

use crate::TfheParameterError;
use crate::TfheParameterError::{
    CipherModulusMismatch, ClientSecretKeyDistributionMismatch, InvalidLweDimension,
    PlainModulusMismatch, PolynomialLengthMismatch, UnsupportedClientSecretKeyDistribution,
};

/// NTRU-TFHE choices with one shared ring length and modulus domain.
///
/// The accumulator and padded client NTRU parameters inherit `t` and `q` from
/// `external_lwe`; the client NTRU secret inherits its distribution as well.
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>> {
    /// External secret prefix, dimension, moduli and fresh LWE encryption noise.
    pub external_lwe: LweParameters<T, M>,
    /// Common NTRU polynomial length `N`.
    pub poly_length: usize,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Standard deviation for accumulator and blind-rotation-key encryption.
    pub accumulator_noise_standard_deviation: f64,
    /// NLev initializer and NGSW control decomposition.
    pub blind_rotation: DecompositionConfig,
    /// Decomposition for the post-bootstrap NTRU key switch.
    pub key_switching: DecompositionConfig,
    /// Standard deviation for encryption under the padded client NTRU secret.
    pub key_switching_noise_standard_deviation: f64,
}

/// Mathematical parameters for NTRU-based TFHE.
///
/// The blind-rotation parameters describe ciphertexts under the accumulator
/// key. The key-switching parameters describe NLev ciphertexts under the
/// client key and therefore the target of the post-bootstrap NTRU key switch.
#[derive(Clone)]
pub struct TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    external_lwe: LweParameters<T, M>,
    blind_rotation: NlevParameters<T, M>,
    ntru_key_switching: NlevParameters<T, M>,
    rotation_quantizer: RotationQuantizer<M::Prepared>,
}

impl<T, M> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Derives both NTRU domains and their gadget parameters from named choices.
    ///
    /// Returns the compatibility errors of [`Self::try_new`] or an invalid
    /// gadget decomposition error, with its blind-rotation/key-switch role.
    ///
    /// # Panics
    ///
    /// Inherits [`NtruParameters::new`]'s layout, sampler and codec requirements.
    pub fn try_from_config(config: TfheConfig<T, M>) -> Result<Self, TfheParameterError> {
        let modulus = config.external_lwe.cipher_modulus();
        let accumulator = NtruParameters::new(
            config.poly_length,
            config.external_lwe.plain_modulus_value(),
            modulus,
            config.accumulator_secret_key_distr,
            config.accumulator_noise_standard_deviation,
        );
        let client = NtruParameters::new(
            config.poly_length,
            config.external_lwe.plain_modulus_value(),
            modulus,
            config.external_lwe.secret_key_distr(),
            config.key_switching_noise_standard_deviation,
        );
        let blind_rotation = NlevParameters::try_with_ntru_params(
            &accumulator,
            config.blind_rotation.log_basis,
            config.blind_rotation.level_count,
        )
        .map_err(TfheParameterError::BootstrappingParameters)?;
        let key_switching = NlevParameters::try_with_ntru_params(
            &client,
            config.key_switching.log_basis,
            config.key_switching.level_count,
        )
        .map_err(TfheParameterError::KeySwitchingParameters)?;
        Self::try_new(config.external_lwe, blind_rotation, key_switching)
    }

    /// Creates one NTRU TFHE parameter set.
    ///
    /// # Errors
    ///
    /// Returns an error unless the external LWE key is the binary or ternary coefficient
    /// prefix of an NTRU key, fits in `N`, and all three parameter domains
    /// agree on `N`, `t`, and `q` where applicable. The rotation domain `2N`
    /// must be representable by `T`.
    pub fn try_new(
        external_lwe: LweParameters<T, M>,
        blind_rotation: NlevParameters<T, M>,
        ntru_key_switching: NlevParameters<T, M>,
    ) -> Result<Self, TfheParameterError> {
        let external_distr = external_lwe.secret_key_distr();
        let client_ntru_distr = ntru_key_switching.ntru().secret_key_distr();
        if !(external_distr.is_binary() || external_distr.is_ternary())
            || !(client_ntru_distr.is_binary() || client_ntru_distr.is_ternary())
        {
            return Err(UnsupportedClientSecretKeyDistribution);
        }
        if external_distr != client_ntru_distr {
            return Err(ClientSecretKeyDistributionMismatch);
        }

        let accumulator_ntru = blind_rotation.ntru();
        let client_ntru = ntru_key_switching.ntru();
        let poly_length = accumulator_ntru.poly_length();
        if !(1..=poly_length).contains(&external_lwe.dimension()) {
            return Err(InvalidLweDimension {
                lwe_dimension: external_lwe.dimension(),
                poly_length,
            });
        }
        if client_ntru.poly_length() != poly_length {
            return Err(PolynomialLengthMismatch);
        }
        if external_lwe.plain_modulus_value() != accumulator_ntru.plain_modulus()
            || client_ntru.plain_modulus() != accumulator_ntru.plain_modulus()
        {
            return Err(PlainModulusMismatch);
        }
        if external_lwe.cipher_modulus_value() != accumulator_ntru.cipher_modulus_value()
            || client_ntru.cipher_modulus_value() != accumulator_ntru.cipher_modulus_value()
        {
            return Err(CipherModulusMismatch);
        }

        if T::try_from(poly_length * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }
        let rotation_quantizer =
            RotationQuantizer::new(external_lwe.cipher_modulus(), poly_length * 2, 1);
        Ok(Self {
            rotation_quantizer,
            external_lwe,
            blind_rotation,
            ntru_key_switching,
        })
    }

    /// Returns the ordinary-PBS quantizer prepared with these parameters.
    #[doc(hidden)]
    #[must_use]
    pub fn rotation_quantizer(&self) -> RotationQuantizer<M::Prepared> {
        self.rotation_quantizer
    }

    /// Returns the externally visible LWE parameters.
    #[must_use]
    #[inline]
    pub fn external_lwe(&self) -> &LweParameters<T, M> {
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
    pub fn input_plaintext_codec(&self) -> &RoundedCodec<T, M> {
        self.external_lwe.plaintext_codec()
    }

    /// Returns the post-bootstrap NTRU key-switching parameters.
    #[must_use]
    #[inline]
    pub fn ntru_key_switching(&self) -> &NlevParameters<T, M> {
        &self.ntru_key_switching
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
