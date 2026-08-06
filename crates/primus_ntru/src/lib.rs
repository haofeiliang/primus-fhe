//! Secret-key NTRU encryption over `Z_q[X] / (X^N + 1)`.
//!
//! The scalar ciphertext invariant is
//! `c = f^(-1) * (e + Delta * m)`.  Coefficient-domain parameters and
//! secret keys are shared by the exact NTT and native-torus Fourier backends.

#![deny(missing_docs)]

mod error;
mod parameter;
mod secret_key;

/// Fourier-domain NTRU ciphertext.
pub type FourierNtruCiphertext<T> = primus_lattice::ntru::FourierNtru<T>;
/// NTT-domain NTRU ciphertext.
pub type NttNtruCiphertext<T> = primus_lattice::ntru::NttNtru<T>;

pub use error::NtruError;
pub use parameter::NtruParameters;
pub use primus_fhe_core::{SecretCoefficient, SecretKeyDistr};
pub use secret_key::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruSecretKey, NtruSecretKey,
    NttNtruSecretKey,
};
