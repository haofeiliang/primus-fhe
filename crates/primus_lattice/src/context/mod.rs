#[cfg(feature = "rns")]
mod dcrt_glev_mul;
mod glwe_external_product;
mod ntru_external_product;

#[cfg(feature = "rns")]
pub use dcrt_glev_mul::DcrtGlevMulContext;
#[cfg(feature = "rns")]
pub(crate) use dcrt_glev_mul::DcrtGlevMulContextRefMut;
pub(crate) use glwe_external_product::NttExternalProductContextRefMut;
pub use glwe_external_product::{FourierExternalProductContext, NttExternalProductContext};
pub use ntru_external_product::{FourierNtruExternalProductContext, NttNtruExternalProductContext};
