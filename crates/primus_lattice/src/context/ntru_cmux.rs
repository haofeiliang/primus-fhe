use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use super::{FourierNtruExternalProductContext, NttNtruExternalProductContext};

/// Shared scratch for [`NttNlev::lift_monomial_to`](crate::nlev::NttNlev::lift_monomial_to) and [`NttNgsw::cmux_ternary_monomial_to`](crate::ngsw::NttNgsw::cmux_ternary_monomial_to).
///
/// Holds one combined NLEV or NGSW and an external-product context whose digit buffer
/// first holds the monomial NTT factor. The output NTRU supplies the coefficient
/// difference buffer. This binds lengths, not a modulus, basis or transform table.
pub struct NttNtruCmuxContext<T: FheUint> {
    pub(crate) combined_control: Vec<T>,
    pub(crate) external_product: NttNtruExternalProductContext<T>,
}

impl<T: FheUint> NttNtruCmuxContext<T> {
    /// Allocates all buffers for `decompose_length` gadget levels of length `N`.
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
        assert!(
            decompose_length > 0,
            "gadget must contain at least one level"
        );
        let control_length = poly_length
            .checked_mul(decompose_length)
            .expect("gadget ciphertext length must fit in usize");
        Self {
            combined_control: vec![T::ZERO; control_length],
            external_product: NttNtruExternalProductContext::new(poly_length),
        }
    }

    /// Returns the polynomial length shared by input, output and control levels.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.external_product.poly_length()
    }

    /// Borrows the existing external-product scratch for initialization or key switching.
    ///
    /// Its length must stay unchanged. The next lift or ternary CMUX overwrites its contents,
    /// so alternating these operations requires neither extra storage nor a reset.
    #[must_use]
    pub fn external_product_context(&mut self) -> &mut NttNtruExternalProductContext<T> {
        &mut self.external_product
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn decompose_length(&self) -> usize {
        self.combined_control.len() / self.poly_length()
    }
}

/// Shared scratch for [`FourierNlev::lift_monomial_to`](crate::nlev::FourierNlev::lift_monomial_to) and [`FourierNgsw::cmux_ternary_monomial_to`](crate::ngsw::FourierNgsw::cmux_ternary_monomial_to).
///
/// Holds one combined Fourier NLEV or NGSW and an external-product context. Its
/// coefficient and Fourier digit buffers first hold the integer monomial and
/// its transform; decomposition overwrites both afterwards. The output NTRU
/// supplies the coefficient difference buffer. This does not bind an FFT table.
pub struct FourierNtruCmuxContext<T: TorusFftValue> {
    pub(crate) combined_control: Vec<Complex64>,
    pub(crate) external_product: FourierNtruExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierNtruCmuxContext<T> {
    /// Allocates all buffers for `decompose_length` Fourier gadget levels.
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
        assert!(
            decompose_length > 0,
            "gadget must contain at least one level"
        );
        let control_length = (poly_length / 2)
            .checked_mul(decompose_length)
            .expect("Fourier gadget ciphertext length must fit in usize");
        Self {
            combined_control: vec![Complex64::default(); control_length],
            external_product: FourierNtruExternalProductContext::new(poly_length),
        }
    }

    /// Returns the coefficient polynomial length shared by input and output.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.external_product.poly_length()
    }

    /// Borrows the existing external-product scratch for initialization or key switching.
    ///
    /// Its length must stay unchanged. The next lift or ternary CMUX overwrites its contents,
    /// so alternating these operations requires neither extra storage nor a reset.
    #[must_use]
    pub fn external_product_context(&mut self) -> &mut FourierNtruExternalProductContext<T> {
        &mut self.external_product
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn decompose_length(&self) -> usize {
        self.combined_control.len() / (self.poly_length() / 2)
    }
}
