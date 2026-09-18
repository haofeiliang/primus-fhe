use crate::{BooleanError, TfheParameters};
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
