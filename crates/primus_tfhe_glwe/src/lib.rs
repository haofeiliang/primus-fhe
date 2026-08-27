//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.

#![deny(missing_docs)]

mod client;
mod key;
mod lookup_table;
mod parameters;

mod boolean;

use num_traits::Signed;
use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};
use primus_glwe::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey,
    SecretCoefficient,
};
use primus_integer::{FheUint, SignedInteger};
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey};

pub use boolean::{
    BOOLEAN_PLAINTEXT_BITS, BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate,
};
pub use client::{GlweClientError, GlweDecryptor, GlweEncryptor};
pub use key::{GlweClientKey, GlweKeyError};
pub use parameters::{GlweParameterError, GlwePbsOrder, GlweTfheParameters};

pub use primus_tfhe::{
    Ciphertext, LookupTable, LookupTableError, LweSecretKeyRef, ManyLookupTable,
    ProgrammableBootstrap, ProgrammableBootstrapMany, TfheEvaluationError,
};

pub use primus_glwe::SecretKeyDistr;

#[inline]
fn encode_secret_coefficient<T: FheUint>(coefficient: SecretCoefficient<T>, modulus: T) -> T {
    if coefficient.is_negative() {
        debug_assert!(coefficient.unsigned_abs() < modulus);
        modulus.wrapping_add_signed(coefficient)
    } else {
        let coefficient = coefficient.cast_to_unsigned();
        debug_assert!(coefficient < modulus);
        coefficient
    }
}
