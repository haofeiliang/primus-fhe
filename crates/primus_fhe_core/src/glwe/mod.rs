//! GLWE (Module-LWE) ciphertext operations.
//!
//! GLWE operations are the primary implementations. RLWE operations
//! are thin wrappers that delegate to GLWE with dimension = 1.

pub(crate) mod crt;
pub(crate) mod dcrt;
pub(crate) mod key_switch;
pub(crate) mod public_key;
pub(crate) mod secret_key;

pub use crate::ciphertext::{
    FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext, GlweCiphertext,
    NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext,
};
pub use crate::parameter::{
    GadgetDomainError, GadgetSize, GgswParameters, GlevParameters, GlweKeySwitchingParameters,
    GlweParameters, GlweParametersInner, GlweSize, GlweSizeError, NttGadgetDomain,
};
pub use crate::secret_key_type::{SecretCoefficient, SecretKeyDistr};
pub use key_switch::{
    FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey, NttGlweKeySwitchingContext,
    NttGlweKeySwitchingKey,
};
pub use secret_key::{
    FourierGadgetEncryptContext, FourierGlweDecryptContext, FourierGlweEncryptContext,
    FourierGlweSecretKey, GlweSecretKey, GlweSecretKeyParameterSet, NttGadgetEncryptContext,
    NttGlweSecretKey,
};

/// RLWE compatibility types implemented through dimension-one GLWE operations.
pub mod rlwe {
    pub use crate::ciphertext::NttRlweCiphertext;
    pub use crate::parameter::{RgswParameters, RlevParameters, RlweParameters};
    pub use crate::rlwe::{NttRlwePublicKey, NttRlweSecretKey, RlweSecretKey};
}
