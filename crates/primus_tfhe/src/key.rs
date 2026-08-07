use primus_fhe_core::SecretCoefficient;
use primus_integer::FheUint;

/// Borrowed coefficients of an external TFHE LWE secret key.
#[derive(Clone, Copy)]
pub enum LweSecretKeyRef<'a, T: FheUint> {
    /// Secret coefficients already encoded in the ciphertext modulus.
    Encoded(&'a [T]),
    /// Canonical signed ring-secret coefficients viewed as an LWE key.
    Signed(&'a [SecretCoefficient<T>]),
}

impl<T: FheUint> LweSecretKeyRef<'_, T> {
    /// Returns the LWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        match self {
            Self::Encoded(coefficients) => coefficients.len(),
            Self::Signed(coefficients) => coefficients.len(),
        }
    }
}
