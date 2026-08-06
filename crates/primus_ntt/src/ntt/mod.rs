use num_traits::{ConstOne, ConstZero};
use primus_data::{DataMut, RawData};
use primus_factor::{FactorMul, ShoupFactor};
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttError, root::PrimitiveRoot};

mod prime32;
mod prime64;
mod primitive;

pub use prime32::U32NttTable;
pub use prime64::U64NttTable;
pub use primitive::UintNttTable;

/// Abstract interface for Number Theory Transform (NTT).
///
/// # Slice length contract
///
/// Every input or output slice must contain exactly [`Self::poly_length`]
/// coefficients. Implementations must enforce this contract in release builds
/// before mutating the slice or entering an unchecked transform kernel.
pub trait NttTable: Sized + Send + Sync {
    /// The value type.
    type ValueT: PrimitiveRoot;

    /// Creates a new [`NttTable`].
    fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>;

    /// Get the polynomial length.
    fn poly_length(&self) -> usize;

    /// Returns the coefficient modulus used to build this table.
    fn modulus(&self) -> Self::ValueT;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial to a ntt polynomial.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        poly: Polynomial<S>,
    ) -> NttPolynomial<S>;

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial to a polynomial.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
        &self,
        values: NttPolynomial<S>,
    ) -> Polynomial<S>;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, 4*modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, 4*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, 2*modulus)`
    /// to a polynomial slice with coefficient in `[0, 2*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, modulus)`
    /// to a polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);
}

/// NTT table data required to transform monomials directly.
///
/// This capability is separate from [`NttTable`] because a full polynomial
/// transform does not require ordinal root powers or a bit-reversed index map.
/// Implementations only expose those two tables; the monomial algorithms are
/// shared by every implementation through the default methods below.
pub trait MonomialNttTable: NttTable {
    /// Returns `[1, w, w^2, ..., w^(2N-1)]` in ordinal order.
    ///
    /// Implementations must return exactly `2 * self.poly_length()` entries.
    fn ordinal_root_powers(&self) -> &[Self::ValueT];

    /// Returns the bit-reversal of each index in `0..N`.
    ///
    /// Implementations must return exactly `self.poly_length()` entries.
    fn reverse_lsbs(&self) -> &[usize];

    /// Transforms the monomial `coeff * X^degree` directly into NTT form.
    fn transform_monomial(&self, coeff: Self::ValueT, degree: usize, values: &mut [Self::ValueT]) {
        let n = self.poly_length();
        assert_ntt_length(values.len(), n);

        if coeff == Self::ValueT::ZERO {
            values.fill(Self::ValueT::ZERO);
            return;
        }

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let ordinal_root_powers = self.ordinal_root_powers();
        let reverse_lsbs = self.reverse_lsbs();
        assert!(n.is_power_of_two());
        let ordinal_root_count = n.checked_mul(2).expect("NTT polynomial length overflow");
        assert_eq!(ordinal_root_powers.len(), ordinal_root_count);
        assert_eq!(reverse_lsbs.len(), n);

        let modulus = self.modulus();
        let mask = ordinal_root_count - 1;

        if coeff == Self::ValueT::ONE {
            values
                .iter_mut()
                .zip(reverse_lsbs)
                .for_each(|(value, &index)| {
                    let root_index = ((2 * index + 1) * degree) & mask;
                    // `root_index <= mask == ordinal_root_powers.len() - 1`.
                    *value = unsafe { *ordinal_root_powers.get_unchecked(root_index) };
                });
        } else if coeff == modulus - Self::ValueT::ONE {
            values
                .iter_mut()
                .zip(reverse_lsbs)
                .for_each(|(value, &index)| {
                    let root_index = (((2 * index + 1) * degree) & mask) ^ n;
                    // XOR toggles the `n` bit, so the index remains below `2 * n`.
                    *value = unsafe { *ordinal_root_powers.get_unchecked(root_index) };
                });
        } else {
            let coeff = ShoupFactor::new(coeff, modulus);
            values
                .iter_mut()
                .zip(reverse_lsbs)
                .for_each(|(value, &index)| {
                    let root_index = ((2 * index + 1) * degree) & mask;
                    // `root_index <= mask == ordinal_root_powers.len() - 1`.
                    let root = unsafe { *ordinal_root_powers.get_unchecked(root_index) };
                    *value = coeff.factor_mul_modulo(root, modulus);
                });
        }
    }

    /// Transforms the monomial `X^degree` directly into NTT form.
    #[inline]
    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        self.transform_monomial(Self::ValueT::ONE, degree, values);
    }

    /// Transforms the monomial `-X^degree` directly into NTT form.
    #[inline]
    fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        self.transform_monomial(self.modulus() - Self::ValueT::ONE, degree, values);
    }
}

#[track_caller]
#[inline]
fn assert_ntt_length(actual: usize, expected: usize) {
    assert_eq!(
        actual, expected,
        "NTT polynomial length mismatch: expected {expected}, got {actual}"
    );
}
