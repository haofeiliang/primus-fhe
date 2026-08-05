//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.

#![deny(missing_docs)]

mod boolean;
mod client;
mod error;
mod key;
mod lookup_table;
mod parameters;

#[doc(hidden)]
pub mod backend_support;

use num_traits::identities::ConstZero;
use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};
use primus_glwe::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey,
    SecretCoefficient,
};
use primus_integer::{FheUint, WrappingNeg};
use primus_lwe::{LweCiphertext, LweParameters, LweSecretKey};

pub use boolean::{
    BOOLEAN_PLAINTEXT_BITS, BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, ProgrammableBootstrap,
};
pub use client::{Ciphertext, Decryptor, Encryptor, TfheClientError};
pub use error::TfheEvaluationError;
pub use key::{ClientKey, LweSecretKeyRef, TfheKeyError};
pub use lookup_table::{LookupTable, LookupTableError};
pub use parameters::{PbsOrder, TfheParameterError, TfheParameters};

pub use primus_glwe::SecretKeyDistr;

#[inline]
fn encode_secret_coefficient<T: FheUint>(coefficient: SecretCoefficient<T>, modulus: T) -> T {
    if coefficient < SecretCoefficient::<T>::ZERO {
        let magnitude = T::cast_from_signed(coefficient.wrapping_neg());
        debug_assert!(magnitude < modulus);
        modulus - magnitude
    } else {
        let coefficient = T::cast_from_signed(coefficient);
        debug_assert!(coefficient < modulus);
        coefficient
    }
}
