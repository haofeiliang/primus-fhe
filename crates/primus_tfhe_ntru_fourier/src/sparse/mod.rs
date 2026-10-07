//! Coefficient selectors and bucket aggregation for sparse NTRU PBS.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

use crate::SparseNtruBootstrappingKey;
pub(crate) use blind_rotation::{SparseWorkspace, rotate_buckets, rotate_buckets_pair};

pub use blind_rotation::SparseBlindRotationPairWorkspace;
