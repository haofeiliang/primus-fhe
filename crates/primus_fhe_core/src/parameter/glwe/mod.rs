//! GLWE / GLev / GGSW parameter types.
//!
//! - [`single`] — single-modulus parameters (`GlweParametersInner`, `GlweParameters`,
//!   `GlevParameters`, `GgswParameters`)
//!   and shared checked size helpers
//! - [`rns`]   — RNS multi-modulus parameters (`CrtGlweParameters`, `CrtGlevParameters`,
//!   `CrtGgswParameters`)

mod domain;
mod rns;
mod single;

pub use domain::{DcrtGadgetDomain, GadgetDomainError, HybridRnsKeySwitchDomain, NttGadgetDomain};
pub use primus_lattice::{GadgetSize, GlweSize, GlweSizeError, RnsGadgetSize, RnsGlweSize};
pub use rns::{CrtGgswParameters, CrtGlevParameters, CrtGlweParameters};
pub use single::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweParametersInner,
};
