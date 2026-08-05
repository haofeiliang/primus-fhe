//! GLWE / GLev / GGSW parameter types.
//!
//! - [`single`] — single-modulus parameters (`GlweParametersInner`, `GlweParameters`,
//!   `GlevParameters`, `GgswParameters`)
//!   and shared checked size helpers

mod domain;
mod single;

pub use domain::{GadgetDomainError, NttGadgetDomain};
pub use primus_lattice::{GadgetSize, GlweSize, GlweSizeError};
pub use single::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweParametersInner,
};
