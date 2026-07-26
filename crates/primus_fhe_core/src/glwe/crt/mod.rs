//! CRT-domain GLWE operations (coefficient domain, multi-modulus).

mod automorphism;
mod expand_coeff;
mod trace;

pub use automorphism::{
    CoeffAutoHelper, CrtGlweAutoContext, CrtGlweAutoKey, crt_poly_auto_inplace, secret_poly_auto_to,
};
pub use expand_coeff::{
    CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffSyncPool,
};
pub use trace::{CrtGlweTraceContext, CrtGlweTraceKey};
