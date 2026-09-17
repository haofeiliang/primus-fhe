#[cfg(feature = "rns")]
mod dcrt_glev_mul;
mod glwe_external_product;
mod glwe_ternary_cmux;
mod ntru_external_product;

#[cfg(feature = "rns")]
pub use dcrt_glev_mul::DcrtGlevMulContext;
#[cfg(feature = "rns")]
pub(crate) use dcrt_glev_mul::DcrtGlevMulContextRefMut;

pub use glwe_external_product::{FourierGlweExternalProductContext, NttGlweExternalProductContext};
pub(crate) use glwe_external_product::{
    FourierGlweExternalProductContextRefMut, NttGlweExternalProductContextRefMut,
};
pub use glwe_ternary_cmux::{FourierGlweTernaryCmuxContext, NttGlweTernaryCmuxContext};
pub use ntru_external_product::{FourierNtruExternalProductContext, NttNtruExternalProductContext};
pub(crate) use ntru_external_product::{
    FourierNtruExternalProductContextRefMut, NttNtruExternalProductContextRefMut,
};
