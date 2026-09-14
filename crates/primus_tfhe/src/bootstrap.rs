use primus_integer::FheUint;

use crate::{LookupTable, LweCiphertext, ManyLookupTable};

/// Minimal interface implemented by a complete TFHE programmable-bootstrap
/// backend.
pub trait ProgrammableBootstrap<T: FheUint> {
    /// Applies `lookup_table` to `input` and overwrites `output` with an LWE
    /// ciphertext under the backend's external client key.
    ///
    /// # Correctness
    ///
    /// The raw input must use that key and the LUT's unsigned rounded input
    /// encoding. Explicit-modulus coefficients must be canonical. Actual key,
    /// plaintext encoding and noise cannot be checked from a raw ciphertext.
    /// Ordinary family-compiled functions program the front half `0..ceil(t/2)`;
    /// raw compilation may select a shorter prefix. Only the compiled input
    /// domain has the requested function values. The other half of the rotation
    /// ring is the negacyclic extension.
    /// Boolean gates deliberately use that extension and a different output scale.
    /// Input noise and modulus-switch rounding must stay within the selected LUT
    /// interval. Outputs retain the scale chosen at compilation, including raw
    /// Boolean or gadget scales; they are not automatically re-encoded.
    ///
    /// # Panics
    ///
    /// Panics before output writes if a ciphertext dimension or the LUT's
    /// polynomial length, input encoding or accumulator modulus is incompatible.
    fn apply_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut LweCiphertext<T>,
    );
}

/// Interface for one blind rotation evaluating several interleaved lookup
/// tables.
pub trait ProgrammableBootstrapMany<T: FheUint> {
    /// Applies every output in `lookup_table` to `input` and overwrites
    /// `outputs` under the backend's external client key.
    ///
    /// `outputs.len()` must equal [`ManyLookupTable::output_count`]. All outputs
    /// share a blind rotation and ring key switch; only extraction is repeated.
    ///
    /// # Correctness
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s key,
    /// encoding and noise requirements. The rotation resolution is `N / k` for
    /// `k` outputs. Account for the coarser per-coefficient modulus switching
    /// when choosing a noise budget; a valid layout alone does not ensure recovery.
    ///
    /// # Panics
    ///
    /// In addition to the single-output contract, rejects a wrong output count
    /// or any wrong output dimension before writing any output.
    fn apply_many_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    );
}
