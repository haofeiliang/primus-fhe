//! Reusable encryption and decryption workspaces.

use primus_fft::Complex64;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_poly::{FourierPolynomialOwned, PolynomialOwned};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient-domain workspace for Fourier GLWE encryption.
pub struct FourierGlweEncryptContext<T: FheUint> {
    pub(super) coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierGlweEncryptContext<T> {
    /// Creates an encryption workspace for coefficient polynomials of length `poly_length`.
    ///
    /// # Panics
    ///
    /// Panics if the length is not a power of two in the supported GLWE range.
    #[inline]
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two(),
            "invalid Fourier workspace polynomial length"
        );
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }

    fn resize(&mut self, poly_length: usize) {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two(),
            "invalid Fourier workspace polynomial length"
        );
        if self.coeff.as_ref().len() != poly_length {
            self.coeff.0.resize(poly_length, T::ZERO);
        }
    }

    pub(super) fn assert_poly_length(&self, poly_length: usize) {
        assert_eq!(
            self.coeff.as_ref().len(),
            poly_length,
            "Fourier encryption workspace length mismatch"
        );
    }
}

impl<T: FheUint> Zeroize for FourierGlweEncryptContext<T> {
    #[inline]
    fn zeroize(&mut self) {
        self.coeff.0.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGlweEncryptContext<T> {}

impl<T: FheUint> Drop for FourierGlweEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable Fourier-domain workspace for Fourier GLWE decryption.
pub struct FourierGlweDecryptContext {
    pub(super) phase: FourierPolynomialOwned,
}

impl FourierGlweDecryptContext {
    /// Creates a decryption workspace for coefficient polynomials of length `poly_length`.
    ///
    /// # Panics
    ///
    /// Panics if the length is not a power of two in the supported GLWE range.
    #[inline]
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two(),
            "invalid Fourier workspace polynomial length"
        );
        Self {
            phase: FourierPolynomialOwned::zero(poly_length / 2),
        }
    }
}

impl Zeroize for FourierGlweDecryptContext {
    #[inline]
    fn zeroize(&mut self) {
        for value in self.phase.as_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
    }
}

impl ZeroizeOnDrop for FourierGlweDecryptContext {}

impl Drop for FourierGlweDecryptContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable workspace for Fourier GLev/GGSW generation.
///
/// GLev requires only a matching polynomial length. GGSW also requires the
/// configured decomposition level count; use [`Self::resize`] to change it.
pub struct FourierGadgetEncryptContext<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
    pub(super) level_transforms: Vec<Complex64>,
    pub(super) glwe: FourierGlweEncryptContext<T>,
}

impl<T: FheUint> FourierGadgetEncryptContext<T> {
    /// Creates reusable workspace for a checked gadget layout.
    #[must_use]
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();
        let decompose_length = size.decompose_length();
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            level_transforms: vec![
                Complex64::default();
                decompose_length * glwe_size.fourier_poly_len()
            ],
            glwe: FourierGlweEncryptContext::new(poly_length),
        }
    }

    /// Rebinds this workspace to another checked gadget layout.
    pub fn resize(&mut self, size: GadgetSize) {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();

        self.encoded.0.resize(poly_length, T::ZERO);
        self.level_transforms.resize(
            size.decompose_length() * glwe_size.fourier_poly_len(),
            Complex64::default(),
        );
        self.glwe.resize(poly_length);
    }

    pub(crate) fn assert_glev_compatible(&self, size: GadgetSize) {
        let poly_length = size.glwe_size().poly_length();
        assert_eq!(
            self.encoded.as_ref().len(),
            poly_length,
            "gadget polynomial workspace length mismatch"
        );
        self.glwe.assert_poly_length(poly_length);
    }

    pub(crate) fn assert_ggsw_compatible(&self, size: GadgetSize) {
        self.assert_glev_compatible(size);
        assert_eq!(
            self.level_transforms.len(),
            size.decompose_length() * size.glwe_size().fourier_poly_len(),
            "gadget level workspace length mismatch"
        );
    }
}

impl<T: FheUint> Zeroize for FourierGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.encoded.as_mut().iter_mut().zeroize();
        for value in &mut self.level_transforms {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.glwe.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierGadgetEncryptContext<T> {}

impl<T: FheUint> Drop for FourierGadgetEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
