use core::slice::Iter;

use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::{BigUint, BigUintIter, BigUintIterMut, FheUint};
use primus_poly::{BigUintPolynomial, CrtPolynomial};
use primus_reduce::FieldContext;

use super::RNSBase;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Reconstructs the canonical representative for one residue vector.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// The returned value has [`big_uint_value_len`](Self::big_uint_value_len)
    /// little-endian limbs and is reduced modulo the product of the basis moduli.
    pub fn compose(&self, residues: &[T]) -> BigUint<Vec<T>> {
        debug_assert_eq!(self.moduli_count(), residues.len());

        let value_len = self.big_uint_value_len();
        let moduli_product = &self.moduli_product();

        let mut value = BigUint(vec![T::ZERO; value_len]);

        izip!(
            residues,
            &self.inv_punctured_product_mod_modulus,
            BigUintIter::new(&self.punctured_product, value_len),
            &self.moduli
        )
        .for_each(
            |(&ri, &inv_mi, mi, &modulus): (&T, &ShoupFactor<T>, BigUint<&[T]>, &M)| {
                let product = inv_mi.factor_mul_modulo(ri, unsafe { modulus.value_unchecked() });
                let carry = mi.mul_value_add_to(product, &mut value);
                if !carry.is_zero() || value.cmp(moduli_product).is_ge() {
                    let _ = value.sub_assign(moduli_product);
                }
            },
        );

        value
    }

    /// Reconstructs one residue vector into caller-provided big-integer storage.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// `value.len()` must equal [`big_uint_value_len`](Self::big_uint_value_len).
    /// The buffer is cleared before the composed canonical representative is
    /// written into it.
    pub fn compose_to(&self, residues: &[T], value: &mut BigUint<&mut [T]>) {
        debug_assert_eq!(self.moduli_count(), residues.len());
        debug_assert_eq!(self.big_uint_value_len(), value.len());

        let value_len = self.moduli_product.len();
        let moduli_product = &self.moduli_product();

        value.set_zero();

        izip!(
            residues,
            &self.inv_punctured_product_mod_modulus,
            BigUintIter::new(&self.punctured_product, value_len),
            &self.moduli
        )
        .for_each(
            |(&ri, &inv_mi, mi, &modulus): (&T, &ShoupFactor<T>, BigUint<&[T]>, &M)| {
                let product = inv_mi.factor_mul_modulo(ri, unsafe { modulus.value_unchecked() });
                let carry = mi.mul_value_add_to(product, value);
                if !carry.is_zero() || value.cmp(moduli_product).is_ge() {
                    let _ = value.sub_assign(moduli_product);
                }
            },
        );
    }

    /// Reconstructs many values from a flattened multi-residue layout.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// read in modulus-major layout: chunk `i` of length `value_count` contains
    /// residues modulo `moduli()[i]`.
    ///
    /// `big_uint_values.len()` must equal
    /// `value_count * big_uint_value_len()`. It receives `value_count`
    /// consecutive little-endian integers, each with
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    ///
    /// `scratch.len()` must equal `moduli_count()`. It is scratch storage for
    /// one coefficient's residue vector and is overwritten for each value.
    pub fn compose_multiple_values_to(
        &self,
        multi_residues: &[T],
        big_uint_values: &mut [T],
        value_count: usize,
        scratch: &mut [T],
    ) {
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );
        debug_assert_eq!(scratch.len(), self.moduli_count());

        let big_uint_value_len = self.big_uint_value_len();

        let mut iters: Vec<Iter<'_, T>> = multi_residues
            .chunks_exact(value_count)
            .map(|s| s.iter())
            .collect();

        for ref mut value in BigUintIterMut::new(big_uint_values, big_uint_value_len) {
            for (iter, residue) in iters.iter_mut().zip(scratch.iter_mut()) {
                *residue = *iter.next().unwrap();
            }
            self.compose_to(scratch, value);
        }
    }

    /// Reconstructs a CRT polynomial into big-integer coefficient form.
    ///
    /// `crt_poly.as_slice().len()` must equal `moduli_count() * poly_length`
    /// and is read in modulus-major layout.
    ///
    /// `big_uint_poly.as_mut_slice().len()` must equal
    /// `poly_length * big_uint_value_len()`. It receives `poly_length`
    /// consecutive little-endian coefficients.
    ///
    /// `scratch.len()` must equal `moduli_count()`. It stores one coefficient's
    /// residue vector while composing each coefficient.
    #[inline]
    pub fn compose_polynomial_to<A, B>(
        &self,
        crt_poly: &CrtPolynomial<A>,
        big_uint_poly: &mut BigUintPolynomial<B>,
        poly_length: usize,
        scratch: &mut [T],
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.compose_multiple_values_to(
            crt_poly.as_slice(),
            big_uint_poly.as_mut_slice(),
            poly_length,
            scratch,
        );
    }
}
