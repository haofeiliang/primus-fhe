use primus_integer::FheUint;

use crate::{Ciphertext, LookupTable};

/// Minimal interface implemented by a complete TFHE programmable-bootstrap
/// backend.
pub trait ProgrammableBootstrap<T: FheUint> {
    /// Applies `lookup_table` to `input` and overwrites `output` with an LWE
    /// ciphertext under the backend's external client key.
    fn apply_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    );
}
