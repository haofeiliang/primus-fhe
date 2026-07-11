//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod key_switch;
mod trace;

pub use automorphism::{
    crt_poly_auto_inplace, CoeffAutoHelper, CrtGlweAutoContext, CrtGlweAutoKey,
};
pub use expand_coeff::{
    CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffSyncPool,
};
pub use key_switch::{CrtGlweKeySwitchingContext, CrtGlweKeySwitchingKey};
pub use trace::{CrtGlweTraceContext, CrtGlweTraceKey};
