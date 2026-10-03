//! Reusable scratch storage, grouped internally by transform representation.

#[cfg(feature = "rns")]
mod dcrt_glev_mul;
mod fourier;
mod ntt;

#[cfg(feature = "rns")]
pub use dcrt_glev_mul::DcrtGlevMulWorkspace;
#[cfg(feature = "rns")]
pub(crate) use dcrt_glev_mul::DcrtGlevMulWorkspaceRefMut;

pub use fourier::{
    FourierGlweExternalProductWorkspace, FourierGlweTernaryCmuxWorkspace, FourierNtruCmuxWorkspace,
    FourierNtruExternalProductWorkspace,
};
pub(crate) use fourier::{
    FourierGlweExternalProductWorkspaceRefMut, FourierNtruExternalProductWorkspaceRefMut,
};
pub use ntt::{
    NttGlweExternalProductWorkspace, NttGlweTernaryCmuxWorkspace, NttNtruCmuxWorkspace,
    NttNtruExternalProductWorkspace,
};
pub(crate) use ntt::{
    NttGlweExternalProductWorkspaceRefMut, NttNtruExternalProductWorkspaceRefMut,
};
