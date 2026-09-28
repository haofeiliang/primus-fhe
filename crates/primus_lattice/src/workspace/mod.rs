#[cfg(feature = "rns")]
mod dcrt_glev_mul;
mod glwe_external_product;
mod glwe_ternary_cmux;
mod ntru_cmux;
mod ntru_external_product;

#[cfg(feature = "rns")]
pub use dcrt_glev_mul::DcrtGlevMulWorkspace;
#[cfg(feature = "rns")]
pub(crate) use dcrt_glev_mul::DcrtGlevMulWorkspaceRefMut;

pub use glwe_external_product::{
    FourierGlweExternalProductWorkspace, NttGlweExternalProductWorkspace,
};
pub(crate) use glwe_external_product::{
    FourierGlweExternalProductWorkspaceRefMut, NttGlweExternalProductWorkspaceRefMut,
};
pub use glwe_ternary_cmux::{FourierGlweTernaryCmuxWorkspace, NttGlweTernaryCmuxWorkspace};
pub use ntru_external_product::{
    FourierNtruExternalProductWorkspace, NttNtruExternalProductWorkspace,
};
pub(crate) use ntru_external_product::{
    FourierNtruExternalProductWorkspaceRefMut, NttNtruExternalProductWorkspaceRefMut,
};

pub use ntru_cmux::{FourierNtruCmuxWorkspace, NttNtruCmuxWorkspace};
