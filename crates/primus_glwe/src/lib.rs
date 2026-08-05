//! Single-modulus GLWE operations.

#![deny(missing_docs)]

mod ciphertext;
mod key_switch;
mod parameter;
mod public_key;
mod secret_key;

use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};

pub use ciphertext::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, GlweCiphertext,
    NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext, TruncatedGlweCiphertext,
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
pub use secret_key::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlweSecretKey, GlweSecretKeyParameterSet, NttGadgetEncryptContext,
    NttGlweSecretKey,
};
