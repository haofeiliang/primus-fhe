//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod expand_coeff_pool;
mod trace;

pub use automorphism::{CrtGlweAutoKey, CrtGlweAutomorphismWorkspace};
pub use expand_coeff::CrtGlweExpandCoeffKey;
pub use expand_coeff_pool::{CrtGlweExpandCoeffSyncPool, CrtGlweExpandCoeffWorkspace};
pub use trace::{CrtGlweTraceKey, CrtGlweTraceWorkspace};
