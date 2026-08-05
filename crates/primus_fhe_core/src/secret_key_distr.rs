use primus_integer::UnsignedInteger;

/// Signed coefficient type used by canonical ring secret keys.
pub type SecretCoefficient<T> = <T as UnsignedInteger>::SignedInteger;

/// Distribution used to sample secret-key coefficients.
///
/// Individual cryptosystems may support only a subset of these distributions.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum SecretKeyDistr {
    /// Uniform binary coefficients in `{0, 1}`.
    Binary,
    /// Uniform ternary coefficients in `{-1, 0, 1}`.
    #[default]
    Ternary,
    /// Centered discrete Gaussian coefficients with the given standard deviation.
    Gaussian(f64),
}
