use primus_integer::FheUint;

use crate::{Ciphertext, LookupTable, ManyLookupTable};

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

/// Interface for one blind rotation evaluating several interleaved lookup
/// tables.
pub trait ProgrammableBootstrapMany<T: FheUint> {
    /// Applies every output in `lookup_table` to `input` and overwrites
    /// `outputs` under the backend's external client key.
    ///
    /// `outputs.len()` must equal [`ManyLookupTable::output_count`].
    fn apply_many_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [Ciphertext<T>],
    );
}
