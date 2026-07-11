//! RLWE (Ring-LWE) ciphertext operations — delegates to GLWE.

mod crt;
mod dcrt;
mod public_key;
mod secret_key;

// RLWE types are re-exported; crt/dcrt module paths are NOT re-exported
// because RLWE delegates to GLWE implementations at those paths.
pub use public_key::*;
pub use secret_key::*;
