use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;

mod generation;
pub(super) mod layout;
pub(super) mod mod_down;
mod switching;

pub use switching::HybridRnsGlweKeySwitchingContext;

/// A GLWE key-switching key using partitioned hybrid-RNS gadget decomposition.
pub struct HybridRnsGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    qp_rns_poly_len: usize,
    qp_rns_glwe_len: usize,
    qp_rns_gadget_len: usize,
    partition_count: usize,
    input_size: RnsGlweSize,
    output_size: RnsGlweSize,
}
