//! Shared blind-rotation domains and complete GLWE PBS parameters.

mod cbs;
pub use cbs::CbsParameters;

use std::sync::Arc;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlevParameterError, GlweEncryptionParameters, GlweSize};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweEncryptionParameters;
use primus_reduce::RingContext;
use primus_tfhe::{BlindRotationMethod, ModulusConfig, ModulusConfigError, PbsMessageConfig};

use crate::{
    GadgetEncryptionConfig, GgswParameters, GlevParameters, GlweKeySwitchingParameters, PbsConfig,
    TfheParameterError,
};

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

/// Prepared GLWE PBS domain, ring KS and default message choices.
/// CBS shares the same KS material for input preparation or later LWE returns.
/// Small and ring secrets remain independent.
#[derive(Clone)]
pub struct PbsParameters<T: FheUint, M: RingContext<T>> {
    messages: PbsMessageConfig<T>,
    pbs_order: PbsOrder,
    small_lwe: LweEncryptionParameters<T, M>,
    blind_rotation_params: GgswParameters<T, M>,
    blind_rotation_method: BlindRotationMethod,
    key_switching_params: GlweKeySwitchingParameters<T, M>,
}

impl<T: FheUint, M: RingContext<T>> PbsParameters<T, M> {
    /// Prepares the common domain and ring KS from numerical choices.
    /// Checks binary/ternary controls, n <= kN and representability of 2N before
    /// returning the prepared state. Input and accumulator secrets are independent.
    pub fn try_from_config(config: PbsConfig<T, M>) -> Result<Self, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
    {
        let small_lwe = LweEncryptionParameters::try_from(config.small_lwe)
            .map_err(TfheParameterError::InputParameters)?;

        let distribution = small_lwe.secret_key_distr();
        if !distribution.is_binary() && !distribution.is_ternary() {
            return Err(TfheParameterError::UnsupportedInputLweSecretKey);
        }

        let bsk_size = GlweSize::try_new(config.bsk_dimension, config.bsk_poly_length)
            .map_err(TfheParameterError::AccumulatorLayout)?;
        let blind_rotation_ggsw = GgswParameters::try_new(
            bsk_size,
            small_lwe.cipher_modulus(),
            config.bsk_secret_distr,
            config.bsk_gadget.decomposition,
            config.bsk_gadget.noise_standard_deviation,
        )
        .map_err(|error| match error {
            GlevParameterError::Encryption(source) => {
                TfheParameterError::AccumulatorParameters(source)
            }
            source => TfheParameterError::BootstrappingParameters(source),
        })?;

        let capacity = LweDimension::from(blind_rotation_ggsw.glwe_size());
        if small_lwe.dimension() > capacity {
            return Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension().get(),
                capacity: capacity.get(),
            });
        }
        if T::try_from(blind_rotation_ggsw.poly_length().get() * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }

        let key_switching_params = Self::derive_glwe_key_switching(
            &small_lwe,
            &blind_rotation_ggsw,
            config.key_switching,
        )?;
        Ok(Self {
            small_lwe,
            blind_rotation_params: blind_rotation_ggsw,
            pbs_order: config.order,
            blind_rotation_method: config.method,
            key_switching_params,
            messages: config.messages,
        })
    }

    /// Prepares ring KS targeting the padded small secret, reusing the checked BR domain.
    /// Used for either PBS order or CBS input preparation; no BR sampler is rebuilt.
    pub fn try_key_switching_parameters(
        &self,
        config: GadgetEncryptionConfig,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        Self::derive_glwe_key_switching(self.small_lwe(), self.blind_rotation_params(), config)
    }

    /// Checks an independently prepared KS target before key generation or resource binding.
    /// Noise and decomposition may be independently selected, but geometry, q and the target
    /// secret distribution must match the padded small-LWE domain.
    pub fn check_key_switching_parameters(
        &self,
        parameters: &GlweKeySwitchingParameters<T, M>,
    ) -> Result<(), crate::KeyGenerationError> {
        let glwe = self.blind_rotation_params();
        let output = parameters.output();
        if parameters.input_dimension() != glwe.dimension()
            || output.poly_length() != glwe.poly_length()
            || output.dimension().get()
                != self
                    .small_lwe()
                    .dimension()
                    .get()
                    .div_ceil(glwe.poly_length().get())
            || output.cipher_modulus().explicit_value() != self.cipher_modulus().explicit_value()
            || output.secret_key_distr() != self.small_lwe().secret_key_distr()
        {
            return Err(crate::KeyGenerationError::IncompatibleKeySwitchingParameters);
        }
        Ok(())
    }

    /// Pads the already validated small secret to whole ring components.
    /// Since n <= kN, the derived layout fits within the accumulator; its
    /// modulus is inherited, while the KS basis and noise are independent.
    /// The target encrypts gadget rows and needs no ordinary plaintext codec.
    fn derive_glwe_key_switching(
        small_lwe: &LweEncryptionParameters<T, M>,
        accumulator: &GgswParameters<T, M>,
        key_switching: GadgetEncryptionConfig,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        let basis = ApproxSignedBasis::try_from((
            key_switching.decomposition,
            small_lwe.cipher_modulus_value(),
        ))
        .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        let output_dimension = small_lwe
            .dimension()
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
            small_lwe.secret_key_distr(),
            key_switching.noise_standard_deviation,
        )
        .map_err(TfheParameterError::KeySwitchingEncryption)?;
        let output = GlevParameters::try_from_parts(output_size, Arc::new(inner), basis)
            .map_err(TfheParameterError::KeySwitchingParameters)?;
        GlweKeySwitchingParameters::try_new(accumulator.dimension(), output)
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))
    }

    /// Returns the small LWE sampling domain used by BR controls.
    #[must_use]
    #[inline]
    pub fn small_lwe(&self) -> &LweEncryptionParameters<T, M> {
        &self.small_lwe
    }

    /// Returns the accumulator ring and BR GGSW decomposition.
    #[must_use]
    #[inline]
    pub fn blind_rotation_params(&self) -> &GgswParameters<T, M> {
        &self.blind_rotation_params
    }

    /// Checks the numerical and sampling domain independently of the BR algorithm.
    /// Separately prepared equal domains are accepted. This comparison does not
    /// establish actual secret identity.
    #[must_use]
    pub fn has_same_domain(&self, other: &Self) -> bool {
        if self.pbs_order != other.pbs_order {
            return false;
        }
        let lhs = self.small_lwe();
        let rhs = other.small_lwe();
        let lhs_ring = self.blind_rotation_params();
        let rhs_ring = other.blind_rotation_params();
        lhs.dimension() == rhs.dimension()
            && lhs.cipher_modulus_value() == rhs.cipher_modulus_value()
            && lhs.secret_key_distr() == rhs.secret_key_distr()
            && lhs.noise_standard_deviation() == rhs.noise_standard_deviation()
            && lhs_ring.glwe_size() == rhs_ring.glwe_size()
            && lhs_ring.basis() == rhs_ring.basis()
            && lhs_ring.secret_key_distr() == rhs_ring.secret_key_distr()
            && lhs_ring.noise_standard_deviation() == rhs_ring.noise_standard_deviation()
    }

    /// Selects BR material generation while sharing the same checked numerical domain.
    /// Algorithm-specific public-map validation still precedes key sampling.
    #[must_use]
    pub fn with_blind_rotation_method(
        mut self,
        blind_rotation_method: BlindRotationMethod,
    ) -> Self {
        self.blind_rotation_method = blind_rotation_method;
        self
    }

    /// Returns the selected BR material-generation algorithm.
    #[must_use]
    pub fn blind_rotation_method(&self) -> BlindRotationMethod {
        self.blind_rotation_method
    }

    /// Returns the order that determines the external input role.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Returns the client-visible LWE dimension for the selected input role.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PbsOrder::BootstrapKeyswitch => self.small_lwe().dimension(),
            PbsOrder::KeyswitchBootstrap => {
                LweDimension::from(self.blind_rotation_params().glwe_size())
            }
        }
    }

    /// Returns the common ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.small_lwe().cipher_modulus()
    }
}

impl<T: FheUint, M: RingContext<T>> AsRef<Self> for PbsParameters<T, M> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<T: FheUint, M: RingContext<T>> PbsParameters<T, M> {
    /// Borrows ring KS shared by PBS and downstream CBS LWE returns.
    #[must_use]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, M> {
        &self.key_switching_params
    }

    /// Borrows ring KS only when it prepares input before BR.
    #[must_use]
    pub fn input_key_switching(&self) -> Option<&GlweKeySwitchingParameters<T, M>> {
        if self.pbs_order == PbsOrder::KeyswitchBootstrap {
            Some(&self.key_switching_params)
        } else {
            None
        }
    }

    /// Replaces default message choices without changing the keys or samplers.
    /// Codec/program geometry and the new noise budget are checked separately.
    #[must_use]
    pub fn with_messages(mut self, messages: PbsMessageConfig<T>) -> Self {
        self.messages = messages;
        self
    }

    /// Returns default independently selectable input/output message moduli.
    #[must_use]
    pub fn messages(&self) -> PbsMessageConfig<T> {
        self.messages
    }
}
