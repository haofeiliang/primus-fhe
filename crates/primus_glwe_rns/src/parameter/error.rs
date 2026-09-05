use primus_decompose::ApproxSignedBasisError;
use primus_integer::FheUint;

/// An invalid decomposition basis for CRT GLev/GGSW parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrtGlevParametersError<T: FheUint> {
    /// The decomposition parameters are invalid for the product modulus.
    #[error(transparent)]
    InvalidDecomposition(#[from] ApproxSignedBasisError),
    /// The fast centered lift requires the basis to be smaller than every modulus.
    #[error(
        "decomposition basis {basis:?} must be smaller than RNS modulus {modulus:?} at index {index}"
    )]
    BasisNotSmallerThanModulus {
        /// Decomposition radix.
        basis: T,
        /// RNS modulus that violates the centered-lift precondition.
        modulus: T,
        /// Index in the ordered RNS base.
        index: usize,
    },
}
