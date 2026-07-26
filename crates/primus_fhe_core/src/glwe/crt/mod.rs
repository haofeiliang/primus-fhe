//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod hybrid_mod_down;
mod key_switch;
mod trace;

pub use automorphism::{
    CoeffAutoHelper, CrtGlweAutoContext, CrtGlweAutoKey, crt_poly_auto_inplace,
};
pub use expand_coeff::{
    CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffSyncPool,
};
pub use key_switch::{
    CrtGlweKeySwitchingContext, CrtGlweKeySwitchingKey, HybridCrtGlweKeySwitchingContext,
    HybridCrtGlweKeySwitchingKey,
};
pub use trace::{CrtGlweTraceContext, CrtGlweTraceKey};
