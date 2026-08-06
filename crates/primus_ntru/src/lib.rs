//! Secret-key NTRU encryption over `Z_q[X] / (X^N + 1)`.
//!
//! The scalar ciphertext invariant is
//! `c = f^(-1) * (e + Delta * m)`.  Coefficient-domain parameters and
//! secret keys are shared by the exact NTT and native-torus Fourier backends.

#![deny(missing_docs)]

mod ciphertext;
mod error;
mod parameter;
mod secret_key;

pub use ciphertext::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruCiphertext, NgswCiphertext,
    NlevCiphertext, NtruCiphertext, NttNgswCiphertext, NttNlevCiphertext, NttNtruCiphertext,
};
pub use error::NtruError;
pub use parameter::NtruParameters;
pub use primus_fhe_core::{SecretCoefficient, SecretKeyDistr};
pub use primus_lattice::context::{
    FourierNtruExternalProductContext, NttNtruExternalProductContext,
};
pub use secret_key::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NtruSecretKey, NttNtruGadgetEncryptContext, NttNtruSecretKey,
};
