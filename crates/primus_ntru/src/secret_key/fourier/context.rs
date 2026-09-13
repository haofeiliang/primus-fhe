//! Reusable secret workspaces.

use primus_fft::Complex64;
use primus_integer::FheUint;
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_poly::{FourierPolynomialOwned, PolynomialOwned};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable coefficient buffer for Fourier NTRU encryption.
/// Sensitive coefficients are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruEncryptContext<T: FheUint> {
    pub(super) coeff: PolynomialOwned<T>,
}

impl<T: FheUint> FourierNtruEncryptContext<T> {
    /// Creates an encryption workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        Self {
            coeff: PolynomialOwned::zero(poly_length),
        }
    }
}

impl<T: FheUint> Zeroize for FourierNtruEncryptContext<T> {
    fn zeroize(&mut self) {
        self.coeff.as_mut().iter_mut().zeroize();
        self.coeff.0.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruEncryptContext<T> {}

impl<T: FheUint> Drop for FourierNtruEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable Fourier buffer for NTRU phase computation and decryption.
/// Sensitive phase values are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruDecryptContext {
    pub(super) phase: FourierPolynomialOwned,
}

impl FourierNtruDecryptContext {
    /// Creates a decryption workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        Self {
            phase: FourierPolynomialOwned::zero(poly_length / 2),
        }
    }
}

impl Zeroize for FourierNtruDecryptContext {
    fn zeroize(&mut self) {
        for value in self.phase.as_mut() {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.phase.0.spare_capacity_mut().zeroize();
    }
}

impl ZeroizeOnDrop for FourierNtruDecryptContext {}

impl Drop for FourierNtruDecryptContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Reusable buffers for Fourier NLev/NGSW generation.
/// Sensitive message coefficients and transforms are securely erased on drop.
/// Explicit zeroization preserves buffer lengths so the workspace can be reused.
pub struct FourierNtruGadgetEncryptContext<T: FheUint> {
    pub(super) encoded: PolynomialOwned<T>,
    pub(super) transformed: Vec<Complex64>,
    pub(super) ntru: FourierNtruEncryptContext<T>,
}

impl<T: FheUint> FourierNtruGadgetEncryptContext<T> {
    /// Creates a generation workspace for polynomials of length `poly_length`.
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            encoded: PolynomialOwned::zero(poly_length),
            transformed: vec![Complex64::default(); poly_length / 2],
            ntru: FourierNtruEncryptContext::new(poly_length),
        }
    }

    // Drop leaves the nested encryption workspace to its own destructor;
    // explicit zeroization must also erase that still-live workspace.
    fn zeroize_message_buffers(&mut self) {
        self.encoded.as_mut().iter_mut().zeroize();
        self.encoded.0.spare_capacity_mut().zeroize();
        for value in &mut self.transformed {
            value.re.zeroize();
            value.im.zeroize();
        }
        self.transformed.spare_capacity_mut().zeroize();
    }
}

impl<T: FheUint> Zeroize for FourierNtruGadgetEncryptContext<T> {
    fn zeroize(&mut self) {
        self.zeroize_message_buffers();
        self.ntru.zeroize();
    }
}

impl<T: FheUint> ZeroizeOnDrop for FourierNtruGadgetEncryptContext<T> {}

impl<T: FheUint> Drop for FourierNtruGadgetEncryptContext<T> {
    fn drop(&mut self) {
        self.zeroize_message_buffers();
    }
}
