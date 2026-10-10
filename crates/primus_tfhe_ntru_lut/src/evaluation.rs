//! Request checks and mutually exclusive one-hot projection destinations.

use primus_integer::FheUint;
use primus_tfhe::LweCiphertext;

/// Each input chunk has one fixed role: full coefficient NLEV for the first
/// table layer, or transformed nonzero NGSW for rotations and later layers.
/// V is T in NTT and Complex64 in Fourier; these representations stay explicit.
pub(crate) enum SelectorOutput<'a, T, V> {
    Nlev(&'a mut [T]),
    Ngsw(&'a mut [V]),
}

/// Checks all chunk counts and LWE dimensions before evaluation writes any data.
/// Panics on a shape mismatch; key identity, encoding and noise are not checked here.
pub(crate) fn check_io<T: FheUint>(
    layout: crate::lookup_table::Layout,
    input: &[LweCiphertext<T>],
    output: &[LweCiphertext<T>],
    dimension: primus_lattice::LweDimension,
) {
    assert_eq!(
        input.len(),
        layout.config.input_chunk_count,
        "lookup input chunk count mismatch"
    );
    assert_eq!(
        output.len(),
        layout.config.output_chunk_count,
        "lookup output chunk count mismatch"
    );
    let len = dimension.ciphertext_len();
    assert!(
        input.iter().all(|c| c.lwe_len() == len),
        "lookup input LWE dimension mismatch"
    );
    assert!(
        output.iter().all(|c| c.lwe_len() == len),
        "lookup output LWE dimension mismatch"
    );
}
