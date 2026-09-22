/// Errors shared by external LWE client construction and operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The key has the wrong external LWE dimension.
    #[error("key LWE dimension mismatch: expected {expected}, got {actual}")]
    KeyDimensionMismatch {
        /// Required dimension.
        expected: usize,
        /// Supplied dimension.
        actual: usize,
    },
    /// The public key uses another ciphertext modulus.
    #[error("public-key ciphertext modulus mismatch")]
    PublicKeyModulusMismatch,
    /// The message is outside `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,
    /// The message is outside `[0, ceil(t / 2))`.
    #[error("message is outside the programmable padded domain")]
    MessageOutsidePaddedDomain,
    /// The ciphertext has the wrong external LWE dimension.
    #[error("ciphertext LWE dimension mismatch: expected {expected}, got {actual}")]
    CiphertextDimensionMismatch {
        /// Required dimension.
        expected: usize,
        /// Supplied dimension.
        actual: usize,
    },
}

/// Errors from Boolean client construction, encryption and decryption.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    /// The Boolean client requires plaintext modulus four.
    #[error("Boolean TFHE requires plaintext modulus 4")]
    PlaintextModulusMustBeFour,
    /// The decrypted message is neither zero nor one.
    #[error("decrypted value is not a valid Boolean plaintext")]
    InvalidPlaintext,
    /// Raw client construction, encryption or decryption failed.
    #[error(transparent)]
    Client(#[from] ClientError),
}
