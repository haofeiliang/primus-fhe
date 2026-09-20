use primus_integer::FheUint;

use crate::{ApproxSignedBasisError, primitive::ApproxSignedBasis};

/// Signed gadget decomposition before binding it to a ciphertext modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompositionConfig {
    /// Base-2 logarithm of the radix; must lie in `2..T::BITS`.
    pub log_basis: u32,
    /// Retained high levels, or `None` for the full decomposition.
    /// A specified count must be nonzero and no larger than the full count.
    pub level_count: Option<usize>,
}

impl DecompositionConfig {
    /// Prepares a single-limb basis, checking [`ApproxSignedBasis::try_new`]'s
    /// radix and retained-level constraints.
    ///
    /// `None` selects the implicit native modulus `2^T::BITS`; `Some(q)` selects
    /// an explicit modulus. Validation is deferred until the modulus and `T` are known.
    pub fn try_build<T: FheUint>(
        self,
        modulus: Option<T>,
    ) -> Result<ApproxSignedBasis<T>, ApproxSignedBasisError> {
        ApproxSignedBasis::try_new(modulus, self.log_basis, self.level_count)
    }
}
