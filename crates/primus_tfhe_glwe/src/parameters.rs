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

/// Checked programmable-bootstrapping domains and sampling state for GLWE-based TFHE.
///
/// This type is independent of the Fourier or NTT execution backend. A
/// backend-specific context binds it to an FFT/NTT table. No plaintext modulus
/// or message codec is retained: the same keys can serve compatible programs
/// with different encodings. Programs establish their own geometry and noise budget.
/// CBS reuses these PBS-stage domains and adds [`crate::CbsParameters`].
/// Ring-KS state is optional for BR→KS ring-output CBS; ordinary PBS and
/// KS→BR input preparation require it before material generation or binding.
#[derive(Clone)]
pub struct PbsParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    small_lwe: LweEncryptionParameters<T, M>,
    blind_rotation_ggsw: GgswParameters<T, M>,
    glwe_key_switching: Option<GlweKeySwitchingParameters<T, M>>,
    pbs_order: PbsOrder,
}

impl<T, M> PbsParameters<T, M>
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
        let mut parameters = Self::try_bootstrap(small_lwe, blind_rotation_ggsw, pbs_order)?;
        parameters.glwe_key_switching = Some(Self::derive_glwe_key_switching(
            parameters.small_lwe.dimension(),
            parameters.small_lwe.secret_key_distr(),
            &parameters.blind_rotation_ggsw,
            key_switching,
        )?);
        Ok(parameters)
    }

    /// Prepares BR→KS's ring-output prefix without an unused output key switch.
    ///
    /// Used by CBS/CMux workflows. Ordinary PBS needs [`Self::try_new`];
    /// KS→BR CBS also needs its input KS. Validates the same BR domains as that constructor.
    pub fn try_without_key_switching(
        small_lwe: LweEncryptionParameters<T, M>,
        blind_rotation_ggsw: GgswParameters<T, M>,
    ) -> Result<Self, TfheParameterError> {
        Self::try_bootstrap(small_lwe, blind_rotation_ggsw, PbsOrder::BootstrapKeyswitch)
    }

    /// Adds or replaces ring KS in an already checked BR domain and selects the PBS order.
    ///
    /// Checks only the new basis and KS sampler/layout; it does not rescan the
    /// established input-secret support or rebuild the BR sampler.
    pub fn try_with_key_switching(
        mut self,
        key_switching: GadgetEncryptionConfig,
        order: PbsOrder,
    ) -> Result<Self, TfheParameterError> {
        let basis = key_switching
            .decomposition
            .try_build(self.cipher_modulus().explicit_value())
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        self.glwe_key_switching = Some(Self::derive_glwe_key_switching(
            self.small_lwe.dimension(),
            self.small_lwe.secret_key_distr(),
            &self.blind_rotation_ggsw,
            GadgetEncryptionConfig {
                decomposition: basis,
                noise_standard_deviation: key_switching.noise_standard_deviation,
            },
        )?);
        self.pbs_order = order;
        Ok(self)
    }

    /// Checks the shared BR domain once; KS preparation only adds its own basis/sampler.
    fn try_bootstrap(
        small_lwe: LweEncryptionParameters<T, M>,
        blind_rotation_ggsw: GgswParameters<T, M>,
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
        Ok(Self {
            small_lwe,
            blind_rotation_ggsw,
            glwe_key_switching: None,
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

    /// Borrows ring-KS parameters, absent in a BR→KS ring-output CBS setup.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching(&self) -> Option<&GlweKeySwitchingParameters<T, M>> {
        self.glwe_key_switching.as_ref()
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

/// Prepares the common ring/GGSW state for numerical blind-rotation configs.
pub(crate) fn prepare_blind_rotation<T: FheUint, M: RingContext<T>>(
    modulus: M,
    dimension: GlweDimension,
    poly_length: PolyLength,
    secret: SecretKeyDistr,
    gadget: GadgetEncryptionConfig,
) -> Result<GgswParameters<T, M>, TfheParameterError> {
    let size =
        GlweSize::try_new(dimension, poly_length).map_err(TfheParameterError::AccumulatorLayout)?;
    let inner = GlweEncryptionParameters::try_new(modulus, secret, gadget.noise_standard_deviation)
        .map_err(TfheParameterError::AccumulatorParameters)?;
    let basis = gadget
        .decomposition
        .try_build(modulus.explicit_value())
        .map_err(|error| TfheParameterError::BootstrappingParameters(error.into()))?;
    GgswParameters::try_from_parts(size, Arc::new(inner), basis)
        .map_err(TfheParameterError::BootstrappingParameters)
}
