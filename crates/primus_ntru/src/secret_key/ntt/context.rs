//! Reusable secret workspaces.

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient buffer for NTT NLev/NGSW generation.
/// Sensitive message coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct NttNtruGadgetEncryptContext<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
}

impl<T: FheUint> NttNtruGadgetEncryptContext<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            encoded: PolynomialOwned::zero(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for NttNtruGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        // Vec::zeroize clears the length; explicit workspace erasure must keep it.
        self.encoded.as_mut().iter_mut().zeroize();
        self.encoded.0.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for NttNtruGadgetEncryptContext<T> {}

impl<T: FheUint> Drop for NttNtruGadgetEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
