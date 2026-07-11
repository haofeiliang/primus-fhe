//! GLWE / GLev / GGSW parameter types.
//!
//! - [`single`] — single-modulus parameters (`GlweParameters`, `GlevParameters`, `GgswParameters`)
//! - [`rns`]   — RNS multi-modulus parameters (`CrtGlweParameters`, `CrtGlevParameters`,
//!   `CrtGgswParameters`, plus size helpers `RNSGlweCommonSize`, `RNSGlevCommonSize`)

mod rns;
mod single;

pub use rns::{
    CrtGgswParameters, CrtGlevParameters, CrtGlweParameters, RNSGlevCommonSize, RNSGlweCommonSize,
};
pub use single::{GgswParameters, GlevParameters, GlweParameters};
