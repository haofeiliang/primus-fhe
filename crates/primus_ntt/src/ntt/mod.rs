use num_traits::{ConstOne, ConstZero};
use primus_data::DataMut;
use primus_factor::{FactorMul, ShoupFactor};
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{NttError, reverse::ReverseLsbs, root::PrimitiveRoot};

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
/// [`Self::poly_length`] must be a non-zero power of two.
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
    fn transform_inplace<S: DataMut<Elem = Self::ValueT>>(
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
    fn inverse_transform_inplace<S: DataMut<Elem = Self::ValueT>>(
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

/// NTT root data required to transform monomials directly.
///
/// This capability is separate from [`NttTable`]. Implementations expose the
/// forward and inverse roots already used by the full transforms, while the
/// shared default methods derive the required indices as needed.
pub trait MonomialNttTable: NttTable {
    /// Returns the first `N` root powers in bit-reversed order.
    ///
    /// Implementations must return exactly `N` entries.
    ///
    /// For `0 <= k < N`, entry `reverse_bits(k)` must represent `w^k`.
    fn root_powers(&self) -> &[Self::ValueT];

    /// Returns the inverse root powers in the scrambled order used by the
    /// inverse NTT. Implementations must return exactly `N` entries.
    ///
    /// Entry zero represents one. For `1 <= k < N`, entry
    /// `reverse_bits(k - 1) + 1` must represent `w^-k`.
    fn inv_root_powers(&self) -> &[Self::ValueT];

    /// Transforms the monomial `coeff * X^degree` directly into NTT form.
    ///
    /// # Correctness
    ///
    /// `coeff` must be a canonical residue modulo [`NttTable::modulus`], that
    /// is, it must lie in `[0, self.modulus())`. This method does not reduce
    /// `coeff` before using it.
    fn transform_monomial(&self, coeff: Self::ValueT, degree: usize, values: &mut [Self::ValueT]) {
        let n = self.poly_length();
        assert_ntt_length(values.len(), n);

        if coeff == Self::ValueT::ZERO {
            values.fill(Self::ValueT::ZERO);
            return;
        }

        let twice_n = n.checked_mul(2).expect("NTT polynomial length overflow");
        let degree = degree & (twice_n - 1);

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let modulus = self.modulus();
        if degree == n {
            values.fill(modulus - coeff);
            return;
        }

        let root_powers = self.root_powers();

        if degree.is_power_of_two() {
            let shift = degree.trailing_zeros();
            let index_shift = shift + 1;
            let index_prefix = n >> index_shift;
            return transform_monomial_from_root_indices(
                self,
                coeff,
                values,
                root_powers,
                index_shift,
                |group_index| (index_prefix | group_index, false),
            );
        }

        let inverse_degree = twice_n - degree;
        if inverse_degree.is_power_of_two() {
            let inv_root_powers = self.inv_root_powers();

            let shift = inverse_degree.trailing_zeros();
            let index_shift = shift + 1;
            let index_prefix = n - (n >> shift) + 1;
            return transform_monomial_from_root_indices(
                self,
                coeff,
                values,
                inv_root_powers,
                index_shift,
                |group_index| (index_prefix + group_index, false),
            );
        }

        let log_n = n.trailing_zeros();
        let group_log = degree.trailing_zeros() + 1;
        let exponent_mask = twice_n - 1;
        let power_mask = n - 1;
        transform_monomial_from_root_indices(
            self,
            coeff,
            values,
            root_powers,
            group_log,
            |group_index| {
                let evaluation_index = group_index.reverse_lsbs(log_n - group_log);
                let exponent = ((2 * evaluation_index + 1) * degree) & exponent_mask;
                let power_index = (exponent & power_mask).reverse_lsbs(log_n);
                (power_index, exponent & n != 0)
            },
        );
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

#[inline]
fn transform_monomial_from_root_indices<Table, IndexFn>(
    table: &Table,
    coeff: Table::ValueT,
    values: &mut [Table::ValueT],
    root_powers: &[Table::ValueT],
    group_log: u32,
    root_index: IndexFn,
) where
    Table: MonomialNttTable,
    IndexFn: Fn(usize) -> (usize, bool),
{
    if group_log == 1 {
        return transform_monomial_from_root_pairs(table, coeff, values, root_powers, root_index);
    }

    let modulus = table.modulus();
    let root_at = |group_index| {
        let (index, negate) = root_index(group_index);
        // The caller's root-index formula produces indices in `0..N`.
        let root = unsafe { *root_powers.get_unchecked(index) };
        if negate { modulus - root } else { root }
    };
    let group_size = 1usize << group_log;
    let half_group_size = group_size >> 1;

    if coeff == Table::ValueT::ONE {
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let first = root_at(group_index);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(first);
                second_half.fill(modulus - first);
            });
    } else if coeff == modulus - Table::ValueT::ONE {
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let second = root_at(group_index);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(modulus - second);
                second_half.fill(second);
            });
    } else {
        let coeff = ShoupFactor::new(coeff, modulus);
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let first = coeff.factor_mul_modulo(root_at(group_index), modulus);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(first);
                second_half.fill(modulus - first);
            });
    }
}

#[inline]
fn transform_monomial_from_root_pairs<Table, IndexFn>(
    table: &Table,
    coeff: Table::ValueT,
    values: &mut [Table::ValueT],
    root_powers: &[Table::ValueT],
    root_index: IndexFn,
) where
    Table: MonomialNttTable,
    IndexFn: Fn(usize) -> (usize, bool),
{
    let modulus = table.modulus();
    let root_at = |pair_index| {
        let (index, negate) = root_index(pair_index);
        // The caller's root-index formula produces indices in `0..N`.
        let root = unsafe { *root_powers.get_unchecked(index) };
        if negate { modulus - root } else { root }
    };

    if coeff == Table::ValueT::ONE {
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let first = root_at(pair_index);
                pair[0] = first;
                pair[1] = modulus - first;
            });
    } else if coeff == modulus - Table::ValueT::ONE {
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let second = root_at(pair_index);
                pair[0] = modulus - second;
                pair[1] = second;
            });
    } else {
        let coeff = ShoupFactor::new(coeff, modulus);
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let first = coeff.factor_mul_modulo(root_at(pair_index), modulus);
                pair[0] = first;
                pair[1] = modulus - first;
            });
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
