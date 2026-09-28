//! RNS GLWE key-switching implementations.

mod dcrt;
mod hybrid;

pub use dcrt::{DcrtGlweKeySwitchingKey, DcrtGlweKeySwitchingWorkspace};
pub use hybrid::{HybridRnsGlweKeySwitchingKey, HybridRnsGlweKeySwitchingWorkspace};
