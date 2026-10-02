use primus_decompose::ApproxSignedBasisError;
use primus_integer::FheUint;
use primus_lattice::GlweSizeError;

/// An invalid decomposition basis or layout for CRT GLev/GGSW parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrtGlevParametersError<T: FheUint> {
    /// A derived gadget storage length is not representable.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
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
