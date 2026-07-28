//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod trace;

pub use automorphism::{CrtGlweAutoContext, CrtGlweAutoKey};
pub use expand_coeff::{
    CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffSyncPool,
};
pub use trace::{CrtGlweTraceContext, CrtGlweTraceKey};
