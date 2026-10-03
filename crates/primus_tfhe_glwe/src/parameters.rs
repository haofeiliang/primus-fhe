//! Parameters for GLWE-based TFHE.

use crate::TfheParameterError;
use primus_decompose::{DecompositionConfig, primitive::ApproxSignedBasis};
use primus_glwe::{GlweParametersInner, GlweSize};
use primus_integer::FheUint;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParametersInner;
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
/// when constructing clients or compiling programs. BR and KS use accumulator noise,
/// as in [`TfheParameters::try_new`].
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>> {
    /// Small BR-control secret, dimension, ciphertext modulus and fresh LWE noise.
    /// This is the external domain only for [`PbsOrder::BootstrapKeyswitch`].
    pub small_lwe: LweParametersInner<T, M>,
    /// Number of secret polynomials in the accumulator.
    pub accumulator_dimension: GlweDimension,
    /// Accumulator polynomial length `N`.
    pub poly_length: usize,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Coefficient-unit standard deviation for accumulator, BR and return-KS encryption.
    /// Also used by external encryption for [`PbsOrder::KeyswitchBootstrap`].
    pub accumulator_noise_standard_deviation: f64,
    /// GGSW decomposition for blind rotation.
    pub blind_rotation: DecompositionConfig,
    /// Decomposition for the GLWE key switch.
    pub key_switching: DecompositionConfig,
    /// Order determining the external LWE secret domain.
    pub pbs_order: PbsOrder,
}

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Derives accumulator and gadget parameters from named independent choices.
    ///
    /// Returns accumulator construction errors and the compatibility/basis
    /// errors of [`Self::try_new`]. This does not validate a noise/security budget.
    pub fn try_from_config(config: TfheConfig<T, M>) -> Result<Self, TfheParameterError> {
        let modulus = config.small_lwe.cipher_modulus();
        let poly_length = PolyLength::try_new(config.poly_length).map_err(|_| {
            TfheParameterError::AccumulatorLayout(
                primus_lattice::GlweSizeError::InvalidPolynomialLength,
            )
        })?;
        let size = GlweSize::try_new(config.accumulator_dimension, poly_length)
            .map_err(TfheParameterError::AccumulatorLayout)?;
        let inner = GlweParametersInner::try_new(
            modulus,
            config.accumulator_secret_key_distr,
            config.accumulator_noise_standard_deviation,
        )
        .map_err(TfheParameterError::AccumulatorParameters)?;
        let blind_rotation = config
            .blind_rotation
            .try_build(modulus.explicit_value())
            .map_err(|error| TfheParameterError::BootstrappingParameters(error.into()))?;
        let key_switching = config
            .key_switching
            .try_build(modulus.explicit_value())
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        let blind_rotation = GgswParameters::try_from_parts(size, Arc::new(inner), blind_rotation)
            .map_err(TfheParameterError::BootstrappingParameters)?;
        Self::try_new(
            config.small_lwe,
            blind_rotation,
            key_switching,
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
    small_lwe: LweParametersInner<T, M>,
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
    /// uses its layout, secret distribution and noise; key switching inherits
    /// its noise while targeting the padded binary or ternary `small_lwe` secret.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible secrets, ciphertext moduli,
    /// dimensions or decomposition bases, a rotation domain `2N` not representable
    /// by `T`, or a derived gadget layout overflow.
    pub fn try_new(
        small_lwe: LweParametersInner<T, M>,
        blind_rotation_ggsw: GgswParameters<T, M>,
        key_switching_basis: ApproxSignedBasis<T>,
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
            key_switching_basis,
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
    /// modulus/noise are inherited, while the KS basis remains independent.
    /// The target encrypts gadget rows and needs no ordinary plaintext codec.
    fn derive_glwe_key_switching(
        small_lwe_dimension: LweDimension,
        small_lwe_distr: SecretKeyDistr,
        accumulator: &GgswParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<GlweKeySwitchingParameters<T, M>, TfheParameterError> {
        let output_dimension = small_lwe_dimension
            .get()
            .div_ceil(accumulator.poly_length().get());
        let output_size = GlweSize::new(
            GlweDimension::new(output_dimension),
            accumulator.poly_length(),
        );
        // These samplers were validated in the source parameters at the same q;
        // combine the small-secret distribution with the accumulator's KS noise.
        let inner = Arc::new(GlweParametersInner::new(
            accumulator.cipher_modulus(),
            small_lwe_distr,
            accumulator.noise_distribution().standard_deviation(),
        ));
        let output = GlevParameters::try_from_parts(output_size, inner, basis)
            .map_err(TfheParameterError::KeySwitchingParameters)?;
        GlweKeySwitchingParameters::try_new(accumulator.dimension(), output)
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))
    }

    /// Returns the small-LWE parameters used by the bootstrapping key.
    #[must_use]
    #[inline]
    pub fn small_lwe(&self) -> &LweParametersInner<T, M> {
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
