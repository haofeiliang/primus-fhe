//! GLWE / GLev / GGSW parameter types.
//!
//! - [`single`] — single-modulus parameters (`GlweParametersInner`, `GlweParameters`,
//!   `GlevParameters`, `GgswParameters`)
//!   and shared checked size helpers

mod single;

pub use primus_lattice::{GadgetSize, GlweSize, GlweSizeError};
pub use single::{
    GgswParameters, GlevParameterError, GlevParameters, GlweKeySwitchingParameters, GlweParameters,
    GlweParametersInner,
};
