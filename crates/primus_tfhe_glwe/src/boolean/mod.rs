use crate::{LookupTableError, TfheClientError, TfheEvaluationError, TfheParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;

mod client;
mod evaluator;

pub use client::{BooleanDecryptor, BooleanEncryptor};
pub use evaluator::{BooleanEvaluator, BooleanGate};

/// The number of bits in the external Boolean plaintext modulus: `t = 2^2 = 4`.
pub const BOOLEAN_PLAINTEXT_BITS: u32 = 2;

fn validate_boolean_parameters<T, LM, GM>(
    parameters: &TfheParameters<T, LM, GM>,
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
    Client(#[from] TfheClientError),

    /// Lookup-table compilation failed.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),

    /// Backend evaluator construction failed.
    #[error(transparent)]
    Evaluation(#[from] TfheEvaluationError),
}
