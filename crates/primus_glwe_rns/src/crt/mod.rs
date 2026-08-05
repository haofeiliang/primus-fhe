//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod expand_coeff_pool;
mod trace;

pub use automorphism::{CrtGlweAutoContext, CrtGlweAutoKey};
pub use expand_coeff::CrtGlweExpandCoeffKey;
pub use expand_coeff_pool::{CrtGlweExpandCoeffContext, CrtGlweExpandCoeffSyncPool};
pub use trace::{CrtGlweTraceContext, CrtGlweTraceKey};
