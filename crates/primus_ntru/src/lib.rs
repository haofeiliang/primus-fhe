//! Secret-key NTRU encryption over `Z_q[X] / (X^N + 1)`.
//!
//! The scalar ciphertext invariant is
//! `c = f^(-1) * (e + Delta * m)`.  Coefficient-domain parameters and
//! secret keys are shared by the exact NTT and native-torus Fourier backends.
//!
//! Ordinary encryption provides `encrypt` / `encrypt_to`, `encrypt_centered_to`,
//! `encrypt_encoded_to` and `encrypt_zeros` / `encrypt_zeros_to`. The `_to` methods
//! reuse output storage; Fourier operations also reuse an encryption context.
//! Phase extraction returns undecoded coefficients: NTT takes a modulus and
//! table, while Fourier takes an FFT engine and decryption context. Decoding
//! methods additionally take [`NtruParameters`] for the plaintext codec.
//!
//! `encrypt_nlev_constant_to` encrypts raw ring constants without plaintext
//! scaling. In particular, `NLev[1]` maps a coefficient polynomial to an encrypted
//! NTRU accumulator through an external product. This differs from `NGSW[1]`,
//! which multiplies a ciphertext already encrypted under the same key.
//!
//! `encrypt_ngsw_signed_constant_batch_to` accepts signed coefficient-secret
//! slices directly and writes consecutive NGSWs after checking the batch once.
//! NTT requires magnitudes below `q`, and needs no message scratch or transform
//! because constants evaluate identically at every NTT point. Fourier accepts
//! all signed values, reuses a gadget context and preserves per-level native-ring
//! scaling followed by the FFT. Empty batches consume no randomness.
//!
//! Explicit-modulus conversions use bounded signed encoding: every secret
//! coefficient must have unsigned magnitude strictly less than the target
//! ciphertext modulus. [`NtruParameters`] checks this for its sampling support.
//! Callers importing coefficient keys or selecting a different target modulus
//! must establish the same bound; conversion does not perform general reduction.
//! The native Fourier representation accepts every signed coefficient.

//! Same-secret automorphism, trace/reverse trace, coefficient projection and
//! expansion use separate NTT/Fourier keys and reusable coefficient workspaces.
//! [`NttNtruSchemeSwitchKey`] / [`FourierNtruSchemeSwitchKey`] convert coefficient
//! NLev to transformed NGSW with independent key/output bases. Their
//! secret-dependent-key and f/f²-weighted noise contracts require additional
//! analysis when used for CBS in the NTRU TFHE backends.

#![deny(missing_docs)]

mod automorphism;
mod ciphertext;
mod error;
mod key_switch;
mod parameter;
mod scheme_switch;
mod secret_key;
mod trace;

pub use automorphism::{
    FourierNtruAutomorphismContext, FourierNtruAutomorphismKey, NttNtruAutomorphismContext,
    NttNtruAutomorphismKey,
};
pub use ciphertext::{
    FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruCiphertext, NgswCiphertext,
    NlevCiphertext, NtruCiphertext, NttNgswCiphertext, NttNlevCiphertext, NttNtruCiphertext,
};
pub use error::NtruError;
pub use key_switch::{FourierNtruKeySwitchingKey, NttNtruKeySwitchingKey};
pub use parameter::{NlevParameterError, NlevParameters, NtruParameters};
pub use primus_distr::SecretKeyDistr;
pub use primus_lattice::context::{
    FourierNtruExternalProductContext, NttNtruExternalProductContext,
};
pub use scheme_switch::{FourierNtruSchemeSwitchKey, NttNtruSchemeSwitchKey};
pub use secret_key::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey, NtruSecretKey, NttNtruGadgetEncryptContext, NttNtruSecretKey,
};
pub use trace::{
    FourierNtruTraceContext, FourierNtruTraceKey, NttNtruTraceContext, NttNtruTraceKey,
};
