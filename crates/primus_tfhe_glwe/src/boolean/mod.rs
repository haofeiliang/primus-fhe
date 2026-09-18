use crate::{BooleanError, TfheParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::BOOLEAN_PLAINTEXT_BITS;

mod client;

pub use client::{BooleanDecryptor, BooleanEncryptor};

fn validate_boolean_parameters<T, LM, GM>(
    parameters: &TfheParameters<T, LM, GM>,
) -> Result<(), BooleanError>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    if parameters.plain_modulus_value() == T::ONE << BOOLEAN_PLAINTEXT_BITS {
        Ok(())
    } else {
        Err(BooleanError::PlaintextModulusMustBeFour)
    }
}
