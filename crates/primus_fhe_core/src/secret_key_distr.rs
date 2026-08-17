use primus_integer::UnsignedInteger;

/// Signed coefficient type used by canonical ring secret keys.
pub type SecretCoefficient<T> = <T as UnsignedInteger>::SignedInteger;

/// Distribution used to sample secret-key coefficients.
///
/// Individual cryptosystems may support only a subset of these distributions.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum SecretKeyDistr {
    /// Uniform binary coefficients with `P(0) = P(1) = 1/2`.
    UniformBinary,
    /// Binary coefficients with the configured probability of sampling `1`.
    Binary {
        /// Probability of sampling `1`; the remaining probability belongs to `0`.
        one_probability: f64,
    },
    /// Sparse ternary coefficients with `P(0) = 1/2` and `P(-1) = P(1) = 1/4`.
    #[default]
    SparseTernary,
    /// Uniform ternary coefficients with `P(-1) = P(0) = P(1) = 1/3`.
    UniformTernary,
    /// Ternary coefficients with independently configured `-1` and `1` probabilities.
    Ternary {
        /// Probability of sampling `-1`.
        negative_one_probability: f64,
        /// Probability of sampling `1`; the remaining probability belongs to `0`.
        one_probability: f64,
    },
    /// Binary coefficients with an exact number of ones.
    FixedHammingWeightBinary {
        /// Exact number of coefficients equal to `1`.
        hamming_weight: usize,
    },
    /// Ternary coefficients with exact numbers of negative and positive ones.
    FixedHammingWeightTernary {
        /// Exact number of coefficients equal to `-1`.
        negative_one_weight: usize,
        /// Exact number of coefficients equal to `1`.
        one_weight: usize,
    },
    /// Centered discrete Gaussian coefficients with the given standard deviation.
    Gaussian(f64),
}

impl SecretKeyDistr {
    /// Returns whether the distribution produces only coefficients in `{0, 1}`.
    #[must_use]
    #[inline]
    pub const fn is_binary(self) -> bool {
        matches!(
            self,
            Self::UniformBinary | Self::Binary { .. } | Self::FixedHammingWeightBinary { .. }
        )
    }

    /// Returns whether this is one of the ternary-family distributions.
    #[must_use]
    #[inline]
    pub const fn is_ternary(self) -> bool {
        matches!(
            self,
            Self::SparseTernary
                | Self::UniformTernary
                | Self::Ternary { .. }
                | Self::FixedHammingWeightTernary { .. }
        )
    }

    /// Validates probabilities and any fixed weight for a key of `length` coefficients.
    ///
    /// Fixed-weight distributions apply to the complete logical key represented by
    /// the sampled coefficient slice.
    pub fn validate_for_length(self, length: usize) -> Result<(), SecretKeyDistrError> {
        match self {
            Self::Binary { one_probability } => validate_probability(one_probability),
            Self::Ternary {
                negative_one_probability,
                one_probability,
            } => {
                validate_probability(negative_one_probability)?;
                validate_probability(one_probability)?;
                if negative_one_probability > 1.0 - one_probability {
                    return Err(SecretKeyDistrError::TernaryProbabilitySumExceedsOne);
                }
                Ok(())
            }
            Self::FixedHammingWeightBinary { hamming_weight } => {
                if hamming_weight > length {
                    return Err(SecretKeyDistrError::HammingWeightExceedsLength);
                }
                Ok(())
            }
            Self::FixedHammingWeightTernary {
                negative_one_weight,
                one_weight,
            } => {
                if negative_one_weight
                    .checked_add(one_weight)
                    .is_none_or(|weight| weight > length)
                {
                    return Err(SecretKeyDistrError::HammingWeightExceedsLength);
                }
                Ok(())
            }
            Self::UniformBinary
            | Self::SparseTernary
            | Self::UniformTernary
            | Self::Gaussian(_) => Ok(()),
        }
    }
}

/// An invalid probability or fixed weight in a secret-key distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretKeyDistrError {
    /// A configured probability is NaN, infinite, negative, or greater than one.
    #[error("secret-key coefficient probability must be finite and in [0, 1]")]
    InvalidProbability,
    /// The configured ternary probabilities leave a negative probability for zero.
    #[error("the probabilities of -1 and 1 must sum to at most one")]
    TernaryProbabilitySumExceedsOne,
    /// A fixed Hamming weight is greater than the logical key length.
    #[error("secret-key Hamming weight exceeds the logical key length")]
    HammingWeightExceedsLength,
}

#[inline]
fn validate_probability(probability: f64) -> Result<(), SecretKeyDistrError> {
    if probability.is_finite() && (0.0..=1.0).contains(&probability) {
        Ok(())
    } else {
        Err(SecretKeyDistrError::InvalidProbability)
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretKeyDistr, SecretKeyDistrError};

    #[test]
    fn rejects_invalid_probabilities_and_weights() {
        let cases = [
            (
                SecretKeyDistr::Binary {
                    one_probability: f64::NAN,
                },
                8,
                SecretKeyDistrError::InvalidProbability,
            ),
            (
                SecretKeyDistr::Ternary {
                    negative_one_probability: 0.6,
                    one_probability: 0.5,
                },
                8,
                SecretKeyDistrError::TernaryProbabilitySumExceedsOne,
            ),
            (
                SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 9 },
                8,
                SecretKeyDistrError::HammingWeightExceedsLength,
            ),
            (
                SecretKeyDistr::FixedHammingWeightTernary {
                    negative_one_weight: 4,
                    one_weight: 5,
                },
                8,
                SecretKeyDistrError::HammingWeightExceedsLength,
            ),
        ];

        for (distribution, length, expected) in cases {
            assert_eq!(distribution.validate_for_length(length), Err(expected));
        }
    }
}
