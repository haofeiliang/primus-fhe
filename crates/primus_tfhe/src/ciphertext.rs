use primus_integer::FheUint;
use primus_lwe::LweCiphertext;

/// A raw external LWE ciphertext accepted by TFHE execution backends.
///
/// Encoding and higher-level state belong to wrappers such as Boolean or
/// short-integer ciphertexts rather than to this raw container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ciphertext<T: FheUint>(LweCiphertext<T>);

impl<T: FheUint> Ciphertext<T> {
    /// Wraps an LWE ciphertext without imposing a backend-specific dimension.
    #[inline]
    pub fn from_lwe(ciphertext: LweCiphertext<T>) -> Self {
        Self(ciphertext)
    }

    /// Creates a ciphertext after checking its LWE dimension.
    pub fn try_from_lwe(
        ciphertext: LweCiphertext<T>,
        expected_dimension: usize,
    ) -> Result<Self, TfheCiphertextError> {
        let expected = expected_dimension
            .checked_add(1)
            .ok_or(TfheCiphertextError::DimensionTooLarge)?;
        let actual = ciphertext.0.len();
        if actual != expected {
            return Err(TfheCiphertextError::LengthMismatch { expected, actual });
        }
        Ok(Self(ciphertext))
    }

    /// Returns the underlying LWE ciphertext.
    #[inline]
    pub fn as_lwe(&self) -> &LweCiphertext<T> {
        &self.0
    }

    /// Returns the underlying mutable LWE ciphertext.
    #[inline]
    pub fn as_lwe_mut(&mut self) -> &mut LweCiphertext<T> {
        &mut self.0
    }

    /// Decomposes this wrapper into its underlying LWE ciphertext.
    #[inline]
    pub fn into_lwe(self) -> LweCiphertext<T> {
        self.0
    }

    /// Returns the LWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.0.dimension()
    }
}

/// An invalid raw TFHE ciphertext shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheCiphertextError {
    /// The requested LWE dimension cannot be represented as a coefficient
    /// count including the body.
    #[error("LWE ciphertext dimension is too large")]
    DimensionTooLarge,

    /// The supplied LWE ciphertext has the wrong coefficient count.
    #[error("LWE ciphertext length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Required coefficient count, including the body.
        expected: usize,
        /// Actual coefficient count.
        actual: usize,
    },
}
