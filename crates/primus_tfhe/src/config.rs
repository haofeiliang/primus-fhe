//! Numerical descriptions used by operation configs, before preparing samplers.

use primus_integer::FheUint;
use primus_lwe::{LweDimension, LweEncryptionParameters, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::{Modulus, RingContext};

/// A constant-friendly modulus description with a statically selected reducer.
///
/// `M` retains the reduction representation: an explicit power of two uses
/// [`PowOf2Modulus`], a native torus uses [`NativeModulus`], and NTT primes use
/// [`BarrettModulus`]. [`TryFrom`] validates the representation and prepares
/// the reducer's ratios or masks once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulusConfig<M: Modulus> {
    /// The full-width modulus `2^M::ValueT::BITS`; valid only for NativeModulus.
    Native,
    /// A representable modulus, checked against the selected reducer's range.
    Explicit(M::ValueT),
}

/// A modulus description incompatible with its selected reduction representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModulusConfigError {
    /// Barrett requires an explicit modulus with two bits of multiplication headroom.
    #[error("Barrett requires an explicit modulus 1 < q < 2^(word_bits - 2)")]
    Barrett,
    /// An explicit power of two must be representable and greater than one.
    #[error("PowOf2 requires an explicit modulus 2^k with 1 <= k < word_bits")]
    PowOf2,
    /// The native torus is implicit; no representable explicit value equals it.
    #[error("Native requires the implicit full-width modulus")]
    Native,
}

impl<M: Modulus> From<M> for ModulusConfig<M> {
    fn from(modulus: M) -> Self {
        match modulus.explicit_value() {
            Some(value) => Self::Explicit(value),
            None => Self::Native,
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<BarrettModulus<T>>> for BarrettModulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Explicit(value) => {
                Self::try_new(value).ok_or(ModulusConfigError::Barrett)
            }
            ModulusConfig::Native => Err(ModulusConfigError::Barrett),
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<PowOf2Modulus<T>>> for PowOf2Modulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Explicit(value) if value > T::ONE && value.is_power_of_two() => {
                Ok(Self::new(value))
            }
            _ => Err(ModulusConfigError::PowOf2),
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<NativeModulus<T>>> for NativeModulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Native => Ok(Self::new()),
            ModulusConfig::Explicit(_) => Err(ModulusConfigError::Native),
        }
    }
}

/// Numerical LWE choices, with no prepared distribution or message codec.
/// Convert with `LweEncryptionParameters::try_from(config)` to validate the
/// modulus representation and prepare sampling state.
#[derive(Debug, Clone, Copy)]
pub struct LweConfig<M: Modulus> {
    /// Secret dimension.
    pub dimension: LweDimension,
    /// Ciphertext modulus and its reduction representation.
    pub cipher_modulus: ModulusConfig<M>,
    /// Secret coefficient distribution, including a public fixed weight if used.
    pub secret_key_distr: SecretKeyDistr,
    /// Fresh encryption noise standard deviation, in coefficient units.
    pub noise_standard_deviation: f64,
}

/// Failure to prepare the modulus or sampling state of an LWE description.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LweConfigError {
    /// The modulus does not fit the selected reducer.
    #[error(transparent)]
    Modulus(#[from] ModulusConfigError),
    /// The secret support or noise sampler is invalid.
    #[error(transparent)]
    Parameters(#[from] primus_lwe::LweParameterError),
}

impl<T, M> TryFrom<LweConfig<M>> for LweEncryptionParameters<T, M>
where
    T: FheUint,
    M: RingContext<T> + TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
{
    type Error = LweConfigError;

    fn try_from(config: LweConfig<M>) -> Result<Self, Self::Error> {
        Ok(Self::try_new(
            config.dimension,
            M::try_from(config.cipher_modulus)?,
            config.secret_key_distr,
            config.noise_standard_deviation,
        )?)
    }
}
