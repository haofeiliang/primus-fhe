use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::{
    GadgetSize,
    ggsw::{FourierGgsw, NttGgsw},
};

use super::{FourierGlweExternalProductContext, NttGlweExternalProductContext};

/// Reusable scratch for [`FourierGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined Fourier GGSW, one length-`N/2` integer-scale monomial
/// transform, and an external-product context. The latter's digit buffer also
/// holds the coefficient monomial before decomposition starts. The output GLWE
/// supplies the difference buffer; evaluation allocates nothing and needs no reset.
///
/// The size fixes polynomial length, GLWE dimension, and decomposition levels.
/// It does not bind an FFT table: controls must use the supplied engine's exact
/// table instance and normalized torus scale, with a matching native basis.
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

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}

/// Reusable scratch for [`NttGgsw::cmux_ternary_monomial_to`].
///
/// Holds one combined GGSW, one length-`N` monomial NTT vector, and an
/// external-product context. The output GLWE supplies the coefficient-domain
/// difference buffer. Evaluation allocates nothing and needs no manual reset.
///
/// The size fixes polynomial length, GLWE dimension, and decomposition levels;
/// callers must still supply compatible controls, basis, modulus, and NTT table.
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

    /// Returns the layout used by both controls and the combined-control scratch.
    #[must_use]
    pub fn size(&self) -> GadgetSize {
        self.external_product.size()
    }
}
