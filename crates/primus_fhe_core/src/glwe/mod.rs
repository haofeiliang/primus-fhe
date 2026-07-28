//! GLWE (Module-LWE) ciphertext operations.
//!
//! GLWE operations are the primary implementations. RLWE operations
//! are thin wrappers that delegate to GLWE with dimension = 1.

pub mod crt;
pub mod dcrt;
mod error;
mod key_switch;
mod public_key;
mod secret_key;

pub use crt::*;
pub use dcrt::*;
pub use error::GlweSecretKeyError;
pub use key_switch::*;
pub use public_key::*;
pub use secret_key::*;

fn validate_automorphism(degree: usize, poly_length: usize) {
    assert!(
        poly_length.is_power_of_two(),
        "polynomial length must be a nonzero power of two"
    );
    assert!(
        poly_length <= 1usize << 31,
        "polynomial length exceeds the permutation representation"
    );

    let twice_poly_length = poly_length
        .checked_mul(2)
        .expect("twice the polynomial length must fit in usize");
    assert!(
        degree < twice_poly_length && degree % 2 == 1,
        "automorphism degree must be odd and less than twice the polynomial length"
    );
}
