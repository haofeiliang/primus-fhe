//! RNS GLWE parameters and transform domains.

mod domain;
mod error;
mod rns;

pub use domain::{DcrtGadgetDomain, HybridRnsKeySwitchDomain, RnsDomainError};
pub use error::{CrtGlevParametersError, CrtGlweParametersError};
pub use rns::{CrtGgswParameters, CrtGlevParameters, CrtGlweParameters};

pub(crate) use domain::{validate_dcrt_table, validate_glwe_size, validate_moduli};
