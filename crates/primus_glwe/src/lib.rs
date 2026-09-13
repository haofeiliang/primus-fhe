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
    FourierGlweAutomorphismContext, FourierGlweAutomorphismKey, NttGlweAutomorphismContext,
    NttGlweAutomorphismKey,
};
pub use ciphertext::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, GlevCiphertext,
    GlweCiphertext, NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext,
    TruncatedGlweCiphertext,
};
pub use key_switch::{
    FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey, NttGlweKeySwitchingContext,
    NttGlweKeySwitchingKey,
};
pub use packing_key_switch::{FourierLwePackingKeySwitchingKey, NttLwePackingKeySwitchingKey};
pub use parameter::{
    GadgetSize, GgswParameters, GlevParameterError, GlevParameters, GlweKeySwitchingParameters,
    GlweParameters, GlweParametersInner, GlweSize, GlweSizeError,
};
pub use primus_distr::SecretKeyDistr;
pub use public_key::{NttGlwePublicEncryptContext, NttGlwePublicKey};
pub use scheme_switch::{
    FourierGlweSchemeSwitchContext, FourierGlweSchemeSwitchKey, NttGlweSchemeSwitchContext,
    NttGlweSchemeSwitchKey,
};
pub use secret_key::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlweSecretKey, NttGadgetEncryptContext, NttGlweSecretKey,
};
pub use trace::{
    FourierGlwePackingContext, FourierGlweTraceContext, FourierGlweTraceKey, NttGlwePackingContext,
    NttGlweTraceContext, NttGlweTraceKey,
};
