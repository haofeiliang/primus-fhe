//! CRT/DCRT GLWE operations and Hybrid-RNS key switching.
//!
//! This namespace owns the RNS parameter domains, ciphertext aliases, keys,
//! reusable operation contexts, and coefficient codec. Single-modulus GLWE
//! types remain under [`crate::glwe`].

pub use crate::ciphertext::{CrtGlweCiphertext, DcrtGlweCiphertext};
pub use crate::glwe::crt::{
    CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffSyncPool, CrtGlweTraceContext, CrtGlweTraceKey,
};
pub use crate::glwe::dcrt::{
    DcrtGlweAutoKey, DcrtGlweExpandCoeffContext, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffSyncPool, DcrtGlweRevTraceContext, DcrtGlweRevTraceKey,
    DcrtGlweTraceContext, DcrtGlweTraceKey,
};
pub use crate::glwe::key_switch::{
    DcrtGlweKeySwitchingContext, DcrtGlweKeySwitchingKey, HybridRnsGlweKeySwitchingContext,
    HybridRnsGlweKeySwitchingKey,
};
pub use crate::glwe::public_key::DcrtGlwePublicKey;
pub use crate::glwe::secret_key::{DcrtGlweDecryptContext, DcrtGlweSecretKey};
pub use crate::parameter::{
    CrtGgswParameters, CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, GadgetDomainError,
    HybridRnsKeySwitchDomain, RnsGadgetSize, RnsGlweSize,
};
pub use crate::plaintext::RnsCoeffCodec;

impl<T, M> crate::glwe::GlweSecretKeyParameterSet<T> for CrtGlweParameters<T, M>
where
    T: primus_integer::FheUint,
    M: primus_reduce::FieldContext<T>,
{
    fn secret_key_size(&self) -> crate::glwe::GlweSize {
        self.size().glwe_size()
    }

    fn secret_key_distribution_type(&self) -> crate::glwe::RingSecretKeyType {
        self.secret_key_type()
    }
}
