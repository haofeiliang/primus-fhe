//! Single-modulus GLWE operations.

#![deny(missing_docs)]

mod automorphism;
mod ciphertext;
mod key_switch;
mod packing_key_switch;
mod parameter;
mod public_key;
mod scheme_switch;
mod secret_key;
mod trace;

use primus_encoding::{PlaintextEmbedding, ScaledCodec};

pub use automorphism::{
    FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace, NttGlweAutomorphismKey,
    NttGlweAutomorphismWorkspace,
};
pub use ciphertext::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, GlevCiphertext,
    GlweCiphertext, NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext,
    TruncatedGlweCiphertext,
};
pub use key_switch::{
    FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace, NttGlweKeySwitchingKey,
    NttGlweKeySwitchingWorkspace,
};
pub use packing_key_switch::{FourierLwePackingKeySwitchingKey, NttLwePackingKeySwitchingKey};
pub use parameter::{
    GadgetSize, GgswParameters, GlevParameterError, GlevParameters, GlweKeySwitchingParameters,
    GlweParameterError, GlweParameters, GlweParametersInner, GlweSize, GlweSizeError,
};
pub use primus_distr::SecretKeyDistr;
pub use public_key::{NttGlwePublicEncryptWorkspace, NttGlwePublicKey};
pub use scheme_switch::{FourierGlweSchemeSwitchKey, NttGlweSchemeSwitchKey};
pub use secret_key::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweSecretKey, GlweSecretKey, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey,
};
pub use trace::{
    FourierGlwePackingWorkspace, FourierGlweTraceKey, FourierGlweTraceWorkspace,
    NttGlwePackingWorkspace, NttGlweTraceKey, NttGlweTraceWorkspace,
};
