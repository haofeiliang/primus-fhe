//! Parameters for GLWE-based TFHE.

use crate::{GadgetEncryptionConfig, TfheParameterError};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweEncryptionParameters, GlweSize};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use std::sync::Arc;

use crate::{GgswParameters, GlevParameters, GlweKeySwitchingParameters, SecretKeyDistr};

/// Execution order of programmable bootstrapping and key switching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbsOrder {
    /// Blind rotation is followed by a GLWE key switch and compact sample
    /// extraction back to the small LWE key.
    BootstrapKeyswitch,
    /// A GLWE key switch and compact sample extraction first produce a small
    /// LWE ciphertext, which is then bootstrapped.
    KeyswitchBootstrap,
}

/// GLWE-TFHE key-generation choices with one ciphertext modulus domain.
///
/// The accumulator inherits `q` from `small_lwe`. Message codecs are selected
/// when constructing clients or compiling programs. BR and ring-KS noise are
/// selected independently, as in [`TfheParameters::try_new`].
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>> {
    /// Small BR-control secret, dimension, ciphertext modulus and fresh LWE noise.
    /// This is the external domain only for [`PbsOrder::BootstrapKeyswitch`].
    pub small_lwe: LweEncryptionParameters<T, M>,
    /// Number of secret polynomials in the accumulator.
    pub accumulator_dimension: GlweDimension,
    /// Accumulator polynomial length `N`.
    pub poly_length: PolyLength,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Blind-rotation GGSW decomposition and row noise at the common ciphertext modulus.
    /// The coefficient-unit noise also serves accumulator encryption and fresh
    /// external LWE encryption for [`PbsOrder::KeyswitchBootstrap`].
    pub blind_rotation: GadgetEncryptionConfig,
    /// Ring-KS decomposition and row noise at the common ciphertext modulus in
    /// both PBS orders, independent of accumulator and fresh small-LWE noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Order determining the external LWE secret domain.
    pub pbs_order: PbsOrder,
}

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Derives accumulator and gadget parameters from named independent choices.
    ///
    /// Returns accumulator/KS construction errors and the compatibility/basis
    /// errors of [`Self::try_new`]. This does not validate a noise/security budget.
    pub fn try_from_config(config: TfheConfig<T, M>) -> Result<Self, TfheParameterError> {
        let modulus = config.small_lwe.cipher_modulus();
        let size = GlweSize::try_new(config.accumulator_dimension, config.poly_length)
            .map_err(TfheParameterError::AccumulatorLayout)?;
        let inner = GlweEncryptionParameters::try_new(
            modulus,
            config.accumulator_secret_key_distr,
            config.blind_rotation.noise_standard_deviation,
        )
        .map_err(TfheParameterError::AccumulatorParameters)?;
        let blind_rotation = config
            .blind_rotation
            .decomposition
            .try_build(modulus.explicit_value())
            .map_err(|error| TfheParameterError::BootstrappingParameters(error.into()))?;
        let key_switching_basis = config
            .key_switching
            .decomposition
            .try_build(modulus.explicit_value())
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        let blind_rotation = GgswParameters::try_from_parts(size, Arc::new(inner), blind_rotation)
            .map_err(TfheParameterError::BootstrappingParameters)?;
        Self::try_new(
            config.small_lwe,
            blind_rotation,
            GadgetEncryptionConfig {
                decomposition: key_switching_basis,
                noise_standard_deviation: config.key_switching.noise_standard_deviation,
            },
            config.pbs_order,
        )
    }
}

/// Checked execution domains and sampling state for GLWE-based TFHE keys.
///
/// This type is independent of the Fourier or NTT execution backend. A
/// backend-specific context binds it to an FFT/NTT table. No plaintext modulus
/// or message codec is retained: the same keys can serve compatible programs
/// with different encodings. Programs establish their own geometry and noise budget.
#[derive(Clone)]
pub struct TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    small_lwe: LweEncryptionParameters<T, M>,
    blind_rotation_ggsw: GgswParameters<T, M>,
    glwe_key_switching: GlweKeySwitchingParameters<T, M>,
    pbs_order: PbsOrder,
}

impl<T, M> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Binds the small secret and blind-rotation gadget, deriving the padded KS target.
    ///
    /// Both gadget bases must belong to the accumulator modulus. Bootstrapping
    /// uses its layout, secret distribution and noise. Key switching targets
    /// the padded binary or ternary `small_lwe` secret and uses the independent
    /// `key_switching.noise_standard_deviation`, in coefficient units at the
    /// common ciphertext modulus. This choice does not change fresh LWE noise.
    /// The prepared key-switch basis is moved into the derived parameters.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible secrets, ciphertext moduli,
    /// dimensions or decomposition bases, a rotation domain `2N` not representable
    /// by `T`, a derived gadget layout overflow, or invalid KS noise.
    pub fn try_new(
        small_lwe: LweEncryptionParameters<T, M>,
        blind_rotation_ggsw: GgswParameters<T, M>,
        key_switching: GadgetEncryptionConfig<ApproxSignedBasis<T>>,
        pbs_order: PbsOrder,
    ) -> Result<Self, TfheParameterError> {
        let distribution = small_lwe.secret_key_distr();
        if !distribution.is_binary() && !distribution.is_ternary() {
            return Err(TfheParameterError::UnsupportedInputLweSecretKey);
        }

        let capacity = LweDimension::from(blind_rotation_ggsw.glwe_size());
        if small_lwe.dimension() > capacity {
            return Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension().get(),
                capacity: capacity.get(),
            });
        }
        if small_lwe.cipher_modulus_value() != blind_rotation_ggsw.cipher_modulus().explicit_value()
        {
            return Err(TfheParameterError::CipherModulusMismatch);
        }
        if T::try_from(blind_rotation_ggsw.poly_length().get() * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }
        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            small_lwe.secret_key_distr(),
            &blind_rotation_ggsw,
            key_switching,
        )?;
        Ok(Self {
            small_lwe,
            blind_rotation_ggsw,
            glwe_key_switching,
            pbs_order,
        })
    }

    /// Pads the already validated small secret to whole ring components.
    /// Since n <= kN, the derived layout fits within the accumulator; its
    /// modulus is inherited, while the KS basis and noise are independent.
    /// The target encrypts gadget rows and needs no ordinary plaintext codec.
    fn derive_glwe_key_switching(
        small_lwe_dimension: LweDimension,
        small_lwe_distr: SecretKeyDistr,
        accumulator: &GgswParameters<T, M>,
        key_switching: GadgetEncryptionConfig<ApproxSignedBasis<T>>,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        let output_dimension = small_lwe_dimension
            .get()
            .div_ceil(accumulator.poly_length().get());
        let output_size = GlweSize::new(
            GlweDimension::new(output_dimension),
            accumulator.poly_length(),
        );
        // The small-secret distribution is already checked at this q; the
        // independent KS noise must be validated before preparing its sampler.
        let inner = GlweEncryptionParameters::try_new(
            accumulator.cipher_modulus(),
            small_lwe_distr,
            key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        let output = GlevParameters::try_from_parts(
            output_size,
            Arc::new(inner),
            key_switching.decomposition,
        )
        .map_err(TfheParameterError::KeySwitchingParameters)?;
        GlweKeySwitchingParameters::try_new(accumulator.dimension(), output)
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))
    }

    /// Returns the small-LWE parameters used by the bootstrapping key.
    #[must_use]
    #[inline]
    pub fn small_lwe(&self) -> &LweEncryptionParameters<T, M> {
        &self.small_lwe
    }

    /// Returns the GGSW encryption and decomposition parameters for blind-rotation controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation_ggsw(&self) -> &GgswParameters<T, M> {
        &self.blind_rotation_ggsw
    }

    /// Returns the GLWE key-switching parameters shared by both PBS orders.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, M> {
        &self.glwe_key_switching
    }

    /// Returns the selected PBS execution order.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Returns the dimension of ciphertexts exposed by the client API.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order() {
            PbsOrder::BootstrapKeyswitch => self.small_lwe.dimension(),
            PbsOrder::KeyswitchBootstrap => {
                LweDimension::from(self.blind_rotation_ggsw.glwe_size())
            }
        }
    }

    /// Returns the common LWE and accumulator ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.small_lwe.cipher_modulus()
    }
}
