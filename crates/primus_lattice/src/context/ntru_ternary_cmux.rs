use primus_integer::FheUint;

use crate::ngsw::NttNgsw;

use super::NttNtruExternalProductContext;

/// Fixed-layout scratch for [`NttNgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined NGSW and an external-product context whose digit buffer
/// first holds the monomial NTT factor. The output NTRU supplies the coefficient
/// difference buffer. This binds lengths, not a modulus, basis or transform table.
pub struct NttNtruTernaryCmuxContext<T: FheUint> {
    pub(crate) combined_control: NttNgsw<Vec<T>>,
    pub(crate) external_product: NttNtruExternalProductContext<T>,
}

impl<T: FheUint> NttNtruTernaryCmuxContext<T> {
    /// Allocates all buffers for `decompose_length` NGSW levels of length `N`.
    ///
    /// # Panics
    /// Panics unless `poly_length` is a power of two of at least two and
    /// `decompose_length` is nonzero, or their product overflows `usize`.
    #[must_use]
    pub fn new(poly_length: usize, decompose_length: usize) -> Self {
        assert!(
            poly_length >= 2 && poly_length.is_power_of_two(),
            "NTRU polynomial length must be a power of two of at least two"
        );
        assert!(decompose_length > 0, "NGSW must contain at least one level");
        let control_length = poly_length
            .checked_mul(decompose_length)
            .expect("NGSW ciphertext length must fit in usize");
        Self {
            combined_control: NttNgsw::zero(control_length),
            external_product: NttNtruExternalProductContext::new(poly_length),
        }
    }

    /// Returns the polynomial length shared by input, output and control levels.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.external_product.poly_length()
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn decompose_length(&self) -> usize {
        self.combined_control.as_ref().len() / self.poly_length()
    }
}
