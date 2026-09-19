use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::ngsw::{FourierNgsw, NttNgsw};

use super::{FourierNtruExternalProductContext, NttNtruExternalProductContext};

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

/// Fixed-layout scratch for [`FourierNgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined Fourier NGSW and an external-product context. Its
/// coefficient and Fourier digit buffers first hold the integer monomial and
/// its transform; decomposition overwrites both afterwards. The output NTRU
/// supplies the coefficient difference buffer. This does not bind an FFT table.
pub struct FourierNtruTernaryCmuxContext<T: TorusFftValue> {
    pub(crate) combined_control: FourierNgsw<Vec<Complex64>>,
    pub(crate) external_product: FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierNtruTernaryCmuxContext<T> {
    /// Allocates all buffers for `decompose_length` Fourier NGSW levels.
    ///
    /// # Panics
    /// Panics unless `poly_length` is a power of two of at least two and
    /// `decompose_length` is nonzero, or `(poly_length / 2) * decompose_length`
    /// overflows `usize`.
    #[must_use]
    pub fn new(poly_length: usize, decompose_length: usize) -> Self {
        assert!(
            poly_length >= 2 && poly_length.is_power_of_two(),
            "NTRU polynomial length must be a power of two of at least two"
        );
        assert!(decompose_length > 0, "NGSW must contain at least one level");
        let control_length = (poly_length / 2)
            .checked_mul(decompose_length)
            .expect("Fourier NGSW ciphertext length must fit in usize");
        Self {
            combined_control: FourierNgsw::zero(control_length),
            external_product: FourierNtruExternalProductContext::new(poly_length),
        }
    }

    /// Returns the coefficient polynomial length shared by input and output.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.external_product.poly_length()
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn decompose_length(&self) -> usize {
        self.combined_control.as_ref().len() / (self.poly_length() / 2)
    }
}
