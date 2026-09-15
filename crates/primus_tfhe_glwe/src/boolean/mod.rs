use crate::{
    GlweClientError, GlweTfheParameters, LookupTableError, LweCiphertext, TfheEvaluationError,
};
use primus_integer::FheUint;
use primus_reduce::RingContext;

mod client;
mod evaluator;

pub use client::{BooleanDecryptor, BooleanEncryptor};
pub use evaluator::{BooleanEvaluator, BooleanGate};

/// The number of bits in the external Boolean plaintext modulus: `t = 2^2 = 4`.
pub const BOOLEAN_PLAINTEXT_BITS: u32 = 2;

/// An LWE ciphertext encoding false as 0 and true as 1 modulo 4.
///
/// Uses unsigned rounded LWE encoding with plaintext modulus 4. The internal
/// gate LUT scale and post-PBS shift are handled by [`BooleanEvaluator`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct BooleanCiphertext<T: FheUint>(LweCiphertext<T>);

impl<T: FheUint> BooleanCiphertext<T> {
    /// Wraps a raw ciphertext that is known to use the Boolean encoding.
    ///
    /// This operation cannot verify the encrypted plaintext.
    #[inline]
    pub fn from_raw(ciphertext: LweCiphertext<T>) -> Self {
        Self(ciphertext)
    }

    /// Returns the underlying raw LWE ciphertext.
    #[inline]
    pub fn as_raw(&self) -> &LweCiphertext<T> {
        &self.0
    }

    /// Returns the underlying mutable raw LWE ciphertext.
    #[inline]
    pub fn as_raw_mut(&mut self) -> &mut LweCiphertext<T> {
        &mut self.0
    }

    /// Decomposes this wrapper into its raw LWE ciphertext.
    #[inline]
    pub fn into_raw(self) -> LweCiphertext<T> {
        self.0
    }
}

fn validate_boolean_parameters<T, LM, GM>(
    parameters: &GlweTfheParameters<T, LM, GM>,
) -> Result<(), BooleanError>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    if parameters.plain_modulus_value() == boolean_plaintext_modulus::<T>() {
        Ok(())
    } else {
        Err(BooleanError::PlaintextModulusMustBeFour)
    }
}

#[inline]
fn boolean_plaintext_modulus<T: FheUint>() -> T {
    T::ONE << BOOLEAN_PLAINTEXT_BITS
}

/// An error produced by the Boolean TFHE layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    /// Gate bootstrapping uses the 0/1 encoding modulo 4.
    #[error("Boolean TFHE requires plaintext modulus 4")]
    PlaintextModulusMustBeFour,

    /// A decrypted value is neither 0 nor 1 under plaintext modulus 4.
    #[error("decrypted value is not a valid Boolean plaintext")]
    InvalidPlaintext,

    /// Raw client-side encryption or decryption failed.
    #[error(transparent)]
    Client(#[from] GlweClientError),

    /// Lookup-table compilation failed.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),

    /// Backend evaluator construction failed.
    #[error(transparent)]
    Evaluation(#[from] TfheEvaluationError),
}
