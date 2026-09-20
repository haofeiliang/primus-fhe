use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::{
    GadgetSize,
    ggsw::{FourierGgsw, NttGgsw},
};

use super::{FourierGlweExternalProductContext, NttGlweExternalProductContext};

/// Fixed-layout scratch for [`FourierGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined Fourier GGSW, one length-`N/2` integer-scale monomial
/// transform, and an external-product context whose digit buffer first holds
/// the coefficient monomial. The output GLWE supplies the difference buffer.
/// Does not bind an FFT table; see the operation's representation requirements.
pub struct FourierGlweTernaryCmuxContext<T: TorusFftValue> {
    pub(crate) combined_control: FourierGgsw<Vec<Complex64>>,
    pub(crate) control_factor_fourier: Vec<Complex64>,
    pub(crate) external_product: FourierGlweExternalProductContext<T>,
}

impl<T: TorusFftValue> FourierGlweTernaryCmuxContext<T> {
    /// Allocates all buffers for the given gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        Self {
            combined_control: FourierGgsw::zero(size.fourier_ggsw_len()),
            control_factor_fourier: vec![Complex64::default(); size.glwe_size().fourier_poly_len()],
            external_product: FourierGlweExternalProductContext::new(size),
        }
    }

    /// Reuses external-product buffers between ternary rotations at another
    /// decomposition depth, restoring the control layout even on unwind.
    /// The combined-control allocation retains its original BR basis.
    ///
    /// # Panics
    /// Panics before the operation if `size` changes the GLWE layout.
    pub fn with_external_product<R>(
        &mut self,
        size: GadgetSize,
        operation: impl FnOnce(&mut FourierGlweExternalProductContext<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}

/// Fixed-layout scratch for [`NttGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined GGSW, one length-`N` monomial NTT vector, and an
/// external-product context. The output GLWE supplies the coefficient-domain
/// difference buffer. See the operation's modulus and representation requirements.
pub struct NttGlweTernaryCmuxContext<T: FheUint> {
    pub(crate) combined_control: NttGgsw<Vec<T>>,
    /// NTT of `-X^-exponent`, shared by every polynomial of the negative control.
    pub(crate) control_factor_ntt: Vec<T>,
    pub(crate) external_product: NttGlweExternalProductContext<T>,
}

impl<T: FheUint> NttGlweTernaryCmuxContext<T> {
    /// Allocates all buffers for the given gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        Self {
            combined_control: NttGgsw::zero(size.ggsw_len()),
            control_factor_ntt: vec![T::ZERO; size.glwe_size().poly_length()],
            external_product: NttGlweExternalProductContext::new(size),
        }
    }

    /// Reuses external-product buffers between ternary rotations at another
    /// decomposition depth, restoring the control layout even on unwind.
    /// The combined-control allocation retains its original BR basis.
    ///
    /// # Panics
    /// Panics before the operation if `size` changes the GLWE layout.
    pub fn with_external_product<R>(
        &mut self,
        size: GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductContext<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}
