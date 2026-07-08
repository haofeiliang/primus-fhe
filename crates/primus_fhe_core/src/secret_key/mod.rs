mod glwe;
mod lwe;
mod ntru;
mod rlwe;

/// The distribution type of the LWE Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum LweSecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
}

/// The distribution type of the Ring Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum RingSecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
    /// Gaussian SecretKey Distribution.
    Gaussian(f64),
}

pub use glwe::{
    CrtGlweSecretKey, DcrtGlweDecryptContext, DcrtGlweSecretKey, GlweSecretKey, NttGlweSecretKey,
};
pub use lwe::LweSecretKey;
pub use ntru::{NtruSecretKey, NttNtruSecretKey};
pub use rlwe::{NttRlweSecretKey, RlweSecretKey};
