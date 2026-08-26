//! Single-modulus GLWE operations.

#![deny(missing_docs)]

mod automorphism;
mod ciphertext;
mod key_switch;
mod parameter;
mod public_key;
mod scheme_switch;
mod secret_key;
mod trace;

use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};

pub use automorphism::{NttGlweAutomorphismContext, NttGlweAutomorphismKey};
pub use ciphertext::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, GlevCiphertext,
    GlweCiphertext, NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext,
    TruncatedGlweCiphertext,
};
pub use key_switch::{
    FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey, NttGlweKeySwitchingContext,
    NttGlweKeySwitchingKey,
};
pub use parameter::{
    GadgetDomainError, GadgetSize, GgswParameters, GlevParameters, GlweKeySwitchingParameters,
    GlweParameters, GlweParametersInner, GlweSize, GlweSizeError, NttGadgetDomain,
};
pub use primus_fhe_core::{SecretCoefficient, SecretKeyDistr};
pub use public_key::NttGlwePublicKey;
pub use scheme_switch::{NttGlweSchemeSwitchContext, NttGlweSchemeSwitchKey};
pub use secret_key::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlweSecretKey, GlweSecretKeyParameterSet, NttGadgetEncryptContext,
    NttGlweSecretKey,
};
pub use trace::{NttGlweTraceContext, NttGlweTraceKey};
