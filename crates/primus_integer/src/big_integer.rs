use core::cmp::Ordering;
use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use primus_data::{Data, DataMut, RawData};
use serde::{Deserialize, Serialize};

use crate::{UnsignedInteger, impl_iters};

/// A big unsigned integer backed by externally provided limb storage.
///
/// `BigUint<S>` is designed to work as a lightweight view or container over an
/// existing limb buffer instead of as a normalized arbitrary-precision integer.
/// The storage backend `S` can therefore be borrowed or owned, for example:
///
/// - `BigUint<&[T]>`
/// - `BigUint<&mut [T]>`
/// - `BigUint<Vec<T>>`
/// - `BigUint<Box<[T]>>`
///
/// The limb order is little-endian: index `0` stores the least significant
/// limb.
///
/// # Design note
///
/// Most arithmetic and comparison methods in this type are intended for
/// buffer-based, fixed-width style usage in higher-level crates, where
/// operands are expected to have the same limb length. This type does not try
/// to canonicalize away leading zero limbs automatically.
///
/// Equality compares the complete fixed-width representation, so values with
/// different storage lengths are not equal even when their extra high limbs
/// are zero. [`cmp`](BigUint::cmp) and the arithmetic methods require all
/// participating [`BigUint`]s to have the same storage length. Public batch
/// operations validate this once before entering their per-value kernels.
#[derive(Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct BigUint<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: UnsignedInteger;

impl_iters!(BigUint, big_uint);

/// Owned [`BigUint`] backed by a [`Vec`].
pub type BigUintOwned<T> = BigUint<Vec<T>>;
/// Borrowed [`BigUint`] backed by an immutable slice.
pub type BigUintRef<'a, T> = BigUint<&'a [T]>;
/// Mutably borrowed [`BigUint`] backed by a mutable slice.
pub type BigUintMut<'a, T> = BigUint<&'a mut [T]>;

impl<S> Clone for BigUint<S>
where
    S: RawData + Clone,
    <S as RawData>::Elem: UnsignedInteger,
{
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> Copy for BigUint<S>
where
    S: RawData + Copy,
    <S as RawData>::Elem: UnsignedInteger,
{
}

impl<S, T, I: SliceIndex<[T]>> Index<I> for BigUint<S>
where
    S: Data<Elem = T>,
    T: UnsignedInteger,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(self.0.as_slice(), index)
    }
}

impl<S, T, I: SliceIndex<[T]>> IndexMut<I> for BigUint<S>
where
    S: RawData<Elem = T> + DataMut,
    T: UnsignedInteger,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(self.0.as_mut_slice(), index)
    }
}

impl<S, A, T> PartialEq<BigUint<A>> for BigUint<S>
where
    S: Data<Elem = T>,
    A: Data<Elem = T>,
    T: UnsignedInteger,
{
    #[inline]
    fn eq(&self, other: &BigUint<A>) -> bool {
        self.digits() == other.digits()
    }
}

impl<T> From<BigUint<&[T]>> for BigUint<Vec<T>>
where
    T: UnsignedInteger,
{
    #[inline]
    fn from(BigUint(value): BigUint<&[T]>) -> Self {
        BigUint(value.to_vec())
    }
}

impl<T> From<BigUint<&mut [T]>> for BigUint<Vec<T>>
where
    T: UnsignedInteger,
{
    #[inline]
    fn from(BigUint(value): BigUint<&mut [T]>) -> Self {
        BigUint(value.to_vec())
    }
}

impl<S, T> BigUint<S>
where
    S: Data<Elem = T>,
    T: UnsignedInteger,
{
    /// Returns the number of limbs in the backing storage.
    ///
    /// This is the storage length, not the effective mathematical bit length.
    #[allow(clippy::len_without_is_empty)]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the limbs as a slice in little-endian order.
    #[inline(always)]
    pub fn digits(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Returns an iterator over the limbs from least significant to most
    /// significant.
    #[inline(always)]
    pub fn iter<'a>(&'a self) -> std::slice::Iter<'a, T> {
        self.0.iter()
    }

    /// Returns `true` if all limbs are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.iter().all(T::is_zero)
    }

    /// Returns the effective bit width of the represented value.
    ///
    /// Leading zero limbs are ignored.
    #[must_use]
    #[inline]
    pub fn bits_count(&self) -> u32 {
        self.iter()
            .enumerate()
            .rev()
            .find(|(_, v)| !v.is_zero())
            .map_or(0, |(i, v)| T::BITS * (i as u32 + 1) - v.leading_zeros())
    }

    /// Borrows the same value as an immutable slice-backed [`BigUint`].
    #[inline(always)]
    pub fn view(&self) -> BigUint<&[T]> {
        BigUint(self.0.as_slice())
    }

    /// Adds a value to the big integer, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_value_to<A>(&self, value: T, output: &mut BigUint<A>) -> bool
    where
        A: DataMut<Elem = T>,
    {
        debug_assert!(!self.0.as_slice().is_empty());
        debug_assert_eq!(self.len(), output.len());

        let mut carry;

        let mut a_iter = self.iter();
        let mut b_iter = output.iter_mut();

        let a_first = a_iter.next().unwrap();
        let b_first = b_iter.next().unwrap();

        (*b_first, carry) = a_first.overflowing_add(value);

        while carry {
            if let Some(a_next) = a_iter.next()
                && let Some(b_next) = b_iter.next()
            {
                (*b_next, carry) = a_next.overflowing_add(T::ONE);
            } else {
                return carry;
            }
        }

        for (a, b) in a_iter.zip(b_iter) {
            *b = *a;
        }

        carry
    }

    /// Subtracts a value to the big integer, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_value_to<A>(&self, value: T, output: &mut BigUint<A>) -> bool
    where
        A: DataMut<Elem = T>,
    {
        debug_assert!(!self.0.as_slice().is_empty());
        debug_assert_eq!(self.len(), output.len());

        let mut borrow;

        let mut a_iter = self.iter();
        let mut b_iter = output.iter_mut();

        let a_first = a_iter.next().unwrap();
        let b_first = b_iter.next().unwrap();

        (*b_first, borrow) = a_first.overflowing_sub(value);

        while borrow {
            if let Some(a_next) = a_iter.next()
                && let Some(b_next) = b_iter.next()
            {
                (*b_next, borrow) = a_next.overflowing_sub(T::ONE);
            } else {
                return borrow;
            }
        }

        for (a, b) in a_iter.zip(b_iter) {
            *b = *a;
        }

        borrow
    }

    /// Multiplies the big integer by a value, storing the result in another big integer.
    #[must_use]
    #[inline]
    pub fn mul_value_to<A>(&self, value: T, output: &mut BigUint<A>) -> T
    where
        A: DataMut<Elem = T>,
    {
        debug_assert_eq!(output.len(), self.len());

        if value.is_zero() {
            output.set_zero();
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for (ele, res) in self.iter().zip(output.iter_mut()) {
            (*res, carry) = value.carrying_mul(*ele, carry);
        }

        carry
    }

    /// Multiplies the big integer by a value, then add to another big integer.
    #[must_use]
    #[inline]
    pub fn mul_value_add_to<A>(&self, value: T, acc: &mut BigUint<A>) -> T
    where
        A: DataMut<Elem = T>,
    {
        debug_assert_eq!(acc.len(), self.len());

        if value.is_zero() {
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for (ele, res) in self.iter().zip(acc.iter_mut()) {
            (*res, carry) = value.carrying_mul_add(*ele, *res, carry);
        }

        carry
    }

    /// Adds two big integers to the result, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_to<A, B>(&self, other: &BigUint<A>, output: &mut BigUint<B>) -> bool
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());
        debug_assert_eq!(self.len(), output.len());

        let mut carry = false;
        for ((xs, ys), zs) in self.iter().zip(other.iter()).zip(output.iter_mut()) {
            (*zs, carry) = xs.carrying_add(*ys, carry);
        }

        carry
    }

    /// Subtracts another big integer from this one, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_to<A, B>(&self, other: &BigUint<A>, output: &mut BigUint<B>) -> bool
    where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());
        debug_assert_eq!(self.len(), output.len());

        let mut borrow = false;
        for ((xs, ys), zs) in self.iter().zip(other.iter()).zip(output.iter_mut()) {
            (*zs, borrow) = xs.borrowing_sub(*ys, borrow);
        }

        borrow
    }

    /// Compares this big integer with another, returning an [`Ordering`].
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn cmp<A>(&self, other: &BigUint<A>) -> Ordering
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        for (a, b) in self.iter().rev().zip(other.iter().rev()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                neq => return neq,
            }
        }

        Ordering::Equal
    }

    /// Adds two reduced big integers and writes the result modulo `modulus`.
    ///
    /// This single-correction kernel requires `self` and `other` to be
    /// strictly less than `modulus`. All operands must have the same limb
    /// length.
    #[inline]
    pub fn add_modulo_to<A, B, C>(
        &self,
        other: &BigUint<A>,
        output: &mut BigUint<B>,
        modulus: &BigUint<C>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert!(
            self.len() == other.len() && self.len() == output.len() && self.len() == modulus.len()
        );

        let carry = self.add_to(other, output);
        if carry || output.cmp(modulus).is_ge() {
            let _ = output.sub_assign(modulus);
        }
    }

    /// Subtracts two reduced big integers and writes the result modulo
    /// `modulus`.
    ///
    /// This single-correction kernel requires `self` and `other` to be
    /// strictly less than `modulus`. All operands must have the same limb
    /// length.
    #[inline]
    pub fn sub_modulo_to<A, B, C>(
        &self,
        other: &BigUint<A>,
        output: &mut BigUint<B>,
        modulus: &BigUint<C>,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
        C: Data<Elem = T>,
    {
        debug_assert!(
            self.len() == other.len() && self.len() == output.len() && self.len() == modulus.len()
        );

        if self.sub_to(other, output) {
            let _ = output.add_assign(modulus);
        }
    }

    /// Negates a reduced big integer modulo `modulus`.
    ///
    /// This kernel requires `self` to be strictly less than `modulus`. The
    /// input, output, and modulus must have the same limb length.
    #[inline]
    pub fn neg_modulo_to<A, B>(&self, output: &mut BigUint<A>, modulus: &BigUint<B>)
    where
        A: DataMut<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == output.len() && self.len() == modulus.len());

        if self.is_zero() {
            output.set_zero();
        } else {
            let mut borrow = false;
            for ((xs, ys), zs) in self.iter().zip(modulus.iter()).zip(output.iter_mut()) {
                (*zs, borrow) = ys.borrowing_sub(*xs, borrow);
            }
        }
    }
}

impl<S, T> BigUint<S>
where
    S: DataMut<Elem = T>,
    T: UnsignedInteger,
{
    /// Returns the limbs as a mutable slice in little-endian order.
    #[inline(always)]
    pub fn digits_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns a mutable iterator over the limbs from least significant to most
    /// significant.
    #[inline(always)]
    pub fn iter_mut<'a>(&'a mut self) -> std::slice::IterMut<'a, T> {
        self.0.iter_mut()
    }

    /// Sets all limbs to zero.
    #[inline(always)]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Borrows the same value as a mutable slice-backed [`BigUint`].
    #[inline(always)]
    pub fn view_mut(&mut self) -> BigUint<&mut [T]> {
        BigUint(self.0.as_mut_slice())
    }

    /// Left shifts the big integer by fewer than one limb.
    ///
    /// This is a carry-propagating limb kernel rather than a general
    /// arbitrary-width shift. `bits` must be less than `T::BITS`; a zero
    /// shift leaves the value unchanged. The returned limb contains the bits
    /// shifted out of the most-significant limb.
    ///
    /// Values greater than or equal to `T::BITS` are unsupported and may
    /// panic.
    #[must_use]
    #[inline]
    pub fn left_shift_assign(&mut self, bits: u32) -> T {
        if bits != 0 {
            let mut pre = T::ZERO;
            let mut temp = T::ZERO;
            let right_shift_bits = T::BITS - bits;
            self.iter_mut().for_each(|value| {
                temp = *value;
                *value = *value << bits | pre >> right_shift_bits;
                pre = temp;
            });
            pre >> right_shift_bits
        } else {
            T::ZERO
        }
    }

    /// Right shifts the big integer by fewer than one limb.
    ///
    /// This is a carry-propagating limb kernel rather than a general
    /// arbitrary-width shift. `bits` must be less than `T::BITS`; a zero
    /// shift leaves the value unchanged.
    ///
    /// Values greater than or equal to `T::BITS` are unsupported and may
    /// panic.
    #[inline]
    pub fn right_shift_assign(&mut self, bits: u32) {
        if bits != 0 {
            let mut pre = T::ZERO;
            let mut temp = T::ZERO;
            let left_shift_bits = T::BITS - bits;
            self.iter_mut().rev().for_each(|value| {
                temp = *value;
                *value = pre << left_shift_bits | *value >> bits;
                pre = temp;
            });
        }
    }

    /// Adds a value to the big integer, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_value_assign(&mut self, value: T) -> bool {
        let mut carry;
        match self.digits_mut() {
            [first, other @ ..] => {
                (*first, carry) = first.overflowing_add(value);
                for v in other.iter_mut() {
                    if !carry {
                        return false;
                    }
                    (*v, carry) = (*v).overflowing_add(T::ONE);
                }
                carry
            }
            _ => unreachable!(),
        }
    }

    /// Subtracts a value from the big integer, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_value_assign(&mut self, value: T) -> bool {
        let mut borrow;
        match self.digits_mut() {
            [first, other @ ..] => {
                (*first, borrow) = first.overflowing_sub(value);
                for v in other.iter_mut() {
                    if !borrow {
                        return false;
                    }
                    (*v, borrow) = (*v).overflowing_sub(T::ONE);
                }
                borrow
            }
            _ => unreachable!(),
        }
    }

    /// Multiplies the big integer by a value, returning any carry that results.
    #[must_use]
    #[inline]
    pub fn mul_value_assign(&mut self, value: T) -> T {
        if value.is_zero() {
            self.set_zero();
            return T::ZERO;
        }

        let mut carry = T::ZERO;
        for ele in self.iter_mut() {
            (*ele, carry) = value.carrying_mul(*ele, carry);
        }

        carry
    }

    /// Adds another big integer to this one, returning true if there was a carry.
    #[must_use]
    #[inline]
    pub fn add_assign<A>(&mut self, other: &BigUint<A>) -> bool
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        let mut carry = false;

        for (xs, ys) in self.iter_mut().zip(other.iter()) {
            (*xs, carry) = xs.carrying_add(*ys, carry);
        }

        carry
    }

    /// Subtracts another big integer from this one, returning true if there was a borrow.
    #[must_use]
    #[inline]
    pub fn sub_assign<A>(&mut self, other: &BigUint<A>) -> bool
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(self.len(), other.len());

        let mut borrow = false;

        for (xs, ys) in self.iter_mut().zip(other.iter()) {
            (*xs, borrow) = xs.borrowing_sub(*ys, borrow);
        }

        borrow
    }

    /// Adds another reduced big integer to this one modulo `modulus`.
    ///
    /// This single-correction kernel requires both operands to be strictly
    /// less than `modulus`. Both operands and the modulus must have the same
    /// limb length.
    #[inline]
    pub fn add_modulo_assign<A, B>(&mut self, other: &BigUint<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == other.len() && self.len() == modulus.len());

        let carry = self.add_assign(other);
        if carry || self.cmp(modulus).is_ge() {
            let _ = self.sub_assign(modulus);
        }
    }

    /// Performs `self = other - self` modulo `modulus`.
    ///
    /// This single-correction kernel requires both operands to be strictly
    /// less than `modulus`. Both operands and the modulus must have the same
    /// limb length.
    #[inline]
    pub fn sub_modulo_rev_assign<A, B>(&mut self, other: &BigUint<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == other.len() && self.len() == modulus.len());

        let mut borrow = false;
        for (self_limb, &other_limb) in self.iter_mut().zip(other.iter()) {
            let old = *self_limb;
            (*self_limb, borrow) = other_limb.borrowing_sub(old, borrow);
        }

        if borrow {
            let _ = self.add_assign(modulus);
        }
    }

    /// Subtracts another reduced big integer from this one modulo `modulus`.
    ///
    /// This single-correction kernel requires both operands to be strictly
    /// less than `modulus`. Both operands and the modulus must have the same
    /// limb length.
    #[inline]
    pub fn sub_modulo_assign<A, B>(&mut self, other: &BigUint<A>, modulus: &BigUint<B>)
    where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        debug_assert!(self.len() == other.len() && self.len() == modulus.len());

        if self.sub_assign(other) {
            let _ = self.add_assign(modulus);
        }
    }

    /// Negates this reduced big integer modulo `modulus`.
    ///
    /// This kernel requires `self` to be strictly less than `modulus`. The
    /// value and modulus must have the same limb length.
    #[inline]
    pub fn neg_modulo_assign<A>(&mut self, modulus: &BigUint<A>)
    where
        A: Data<Elem = T>,
    {
        debug_assert!(self.len() == modulus.len());

        if !self.is_zero() {
            let mut borrow = false;
            for (xs, ys) in self.iter_mut().zip(modulus.iter()) {
                (*xs, borrow) = ys.borrowing_sub(*xs, borrow);
            }
        }
    }
}

/// Multiplies many values together, returning the result as a big integer slice.
///
/// # Panics
///
/// Panics if `values` is empty.
pub fn multiply_many_values<T: UnsignedInteger>(values: &[T]) -> BigUint<Vec<T>> {
    let (&first, remaining) = values.split_first().expect("values must be nonempty");
    let mut result = BigUint(Vec::with_capacity(values.len()));
    result.0.push(first);
    for &v in remaining {
        let carry = result.mul_value_assign(v);
        if !carry.is_zero() {
            result.0.push(carry);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use rand::RngExt;
    use rand::distr::{Distribution, Uniform};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    type ValueT = u32;

    fn compose(value: &[ValueT]) -> u128 {
        assert!(value.len() <= 4);
        let mut result = 0u128;
        for &r in value.iter().rev() {
            result <<= ValueT::BITS;
            result |= r as u128;
        }
        result
    }

    fn compose_u64(value: &[u64]) -> u128 {
        assert!(value.len() <= 2);
        let mut result = 0u128;
        for &r in value.iter().rev() {
            result <<= u64::BITS;
            result |= r as u128;
        }
        result
    }

    /// Verifies that the public product helper rejects an undefined empty
    /// product instead of relying on a debug-only precondition.
    #[test]
    #[should_panic(expected = "values must be nonempty")]
    fn multiply_many_values_rejects_empty_input() {
        let _ = multiply_many_values::<u32>(&[]);
    }

    /// Verifies that equality includes the fixed limb width rather than only
    /// comparing the shared low-limb prefix.
    #[test]
    fn fixed_width_equality_includes_limb_count() {
        assert_eq!(BigUint(&[1u32, 2][..]), BigUint(vec![1u32, 2]));
        assert_ne!(BigUint(&[1u32][..]), BigUint(&[1u32, 0][..]));
        assert_ne!(BigUint(&[1u32, 2][..]), BigUint(&[1u32, 3][..]));
    }

    /// Verifies that chunk iterators reject zero-width or truncated layouts at
    /// construction instead of silently omitting data.
    #[test]
    fn big_uint_iter_rejects_inexact_chunks() {
        assert!(std::panic::catch_unwind(|| BigUintIter::new(&[0u32; 2], 0)).is_err());
        assert!(std::panic::catch_unwind(|| BigUintIter::new(&[0u32; 3], 2)).is_err());

        let mut values = [0u32; 3];
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = BigUintIterMut::new(&mut values, 2);
            }))
            .is_err()
        );
    }

    #[test]
    fn test_big_uint_ops() {
        let mut rng = rand::rng();
        let moduli: [ValueT; 3] = [134215681, 134176769, 132120577];
        let modulus = multiply_many_values(&moduli);
        let m_raw = compose(modulus.digits());

        assert_eq!(128 - m_raw.leading_zeros(), modulus.bits_count());

        let distr = moduli.map(|m| Uniform::new(0, m).unwrap());

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let mut a_raw = compose(a.digits());

        a.right_shift_assign(3);
        a_raw >>= 3;
        assert_eq!(a_raw, compose(a.digits()));

        let carry = a.left_shift_assign(3);
        assert_eq!(carry, 0);
        a_raw <<= 3;
        assert_eq!(a_raw, compose(a.digits()));

        let v: ValueT = rng.random();
        let _r = a.add_value_assign(v);
        a_raw += v as u128;
        assert_eq!(a_raw, compose(a.digits()));

        let _r = a.sub_value_assign(v);
        a_raw -= v as u128;
        assert_eq!(a_raw, compose(a.digits()));

        let r = a.mul_value_assign(v);
        let mut p = a.clone();
        p.0.push(r);
        a_raw *= v as u128;
        assert_eq!(a_raw, compose(p.digits()));

        let mut result = BigUint(vec![0; a.len()]);
        a_raw = compose(a.digits());
        let _carry = a.add_value_to(v, &mut result);
        assert_eq!(a_raw + v as u128, compose(result.digits()));

        let _borrow = a.sub_value_to(v, &mut result);
        assert_eq!(a_raw - v as u128, compose(result.digits()));

        let r = a.mul_value_to(v, &mut result);
        result.0.push(r);
        assert_eq!(a_raw * v as u128, compose(result.digits()));

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let b_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let b = multiply_many_values(&b_residues);
        let a_raw = compose(a.digits());
        let b_raw = compose(b.digits());

        let mut result = b.clone();
        let carry = a.mul_value_add_to(v, &mut result);
        result.0.push(carry);
        assert_eq!(a_raw * v as u128 + b_raw, compose(result.digits()));

        let _r = a.add_assign(&b);
        assert_eq!(a_raw + b_raw, compose(a.digits()));

        let _r = a.sub_assign(&b);
        assert_eq!(a_raw, compose(a.digits()));

        a.add_modulo_assign(&b, &modulus);
        let r = (a_raw + b_raw) % m_raw;
        assert_eq!(r, compose(a.digits()));

        let a_residues = distr.map(|distr| distr.sample(&mut rng));
        let b_residues = distr.map(|distr| distr.sample(&mut rng));
        let mut a = multiply_many_values(&a_residues);
        let b = multiply_many_values(&b_residues);
        let a_raw = compose(a.digits());
        let b_raw = compose(b.digits());

        a.sub_modulo_assign(&b, &modulus);
        let r = (a_raw + m_raw - b_raw) % m_raw;
        assert_eq!(r, compose(a.digits()));

        let mut c = a.clone();
        c.neg_modulo_assign(&modulus);
        let r = a.add_assign(&c);
        assert!(!r);
        assert!(a.is_zero() || a == modulus);
    }

    #[test]
    fn add_value_to_stops_after_carry_chain() {
        let input = [u32::MAX, u32::MAX, 7, 9];
        let mut result = [0u32; 4];

        let carry = BigUint(&input[..]).add_value_to(1, &mut BigUint(&mut result[..]));

        assert!(!carry);
        assert_eq!(result, [0, 0, 8, 9]);
    }

    #[test]
    fn add_value_to_reports_final_carry() {
        let input = [u32::MAX, u32::MAX];
        let mut result = [1u32; 2];

        let carry = BigUint(&input[..]).add_value_to(1, &mut BigUint(&mut result[..]));

        assert!(carry);
        assert_eq!(result, [0, 0]);
    }

    #[test]
    fn sub_value_to_stops_after_borrow_chain() {
        let input = [0u32, 0, 7, 9];
        let mut result = [0u32; 4];

        let borrow = BigUint(&input[..]).sub_value_to(1, &mut BigUint(&mut result[..]));

        assert!(!borrow);
        assert_eq!(result, [u32::MAX, u32::MAX, 6, 9]);
    }

    #[test]
    fn sub_value_to_reports_final_borrow() {
        let input = [0u32, 0];
        let mut result = [1u32; 2];

        let borrow = BigUint(&input[..]).sub_value_to(1, &mut BigUint(&mut result[..]));

        assert!(borrow);
        assert_eq!(result, [u32::MAX, u32::MAX]);
    }

    // Coverage for u64 BigUint multi-limb operations.
    // Builds 2-limb u64 BigUints by decomposing u128 values, so we always
    // exercise the multi-limb path and can cross-check against u128 arithmetic.
    // `mul_value` is omitted because a 2-limb u64 * u64 value can exceed u128.
    #[test]
    fn test_big_uint_ops_u64_two_limbs() {
        let mut rng = StdRng::seed_from_u64(0xCAFE_BABE_0000_0005);

        // Modulus: a 2-limb u64 value strictly less than 2^128.
        let m_raw: u128 = 0xc0ff_ee15_dead_beef_face_b00c_1337_4242;
        let modulus = BigUint::<Vec<u64>>(vec![m_raw as u64, (m_raw >> 64) as u64]);

        assert_eq!(128 - m_raw.leading_zeros(), modulus.bits_count());

        let split = |v: u128| -> Vec<u64> { vec![v as u64, (v >> 64) as u64] };

        let a_raw: u128 = rng.random_range(0..m_raw);
        let b_raw: u128 = rng.random_range(0..m_raw);

        let mut a = BigUint::<Vec<u64>>(split(a_raw));
        let b = BigUint::<Vec<u64>>(split(b_raw));

        // shift
        let mut a_shifted = a.clone();
        a_shifted.right_shift_assign(5);
        assert_eq!(a_raw >> 5, compose_u64(a_shifted.digits()));
        let carry = a_shifted.left_shift_assign(5);
        assert_eq!(carry, 0);
        assert_eq!((a_raw >> 5) << 5, compose_u64(a_shifted.digits()));

        // add_value / sub_value within range that doesn't overflow the BigUint
        let v: u64 = rng.random_range(0u64..(1 << 32));
        let mut a_av = a.clone();
        let _r = a_av.add_value_assign(v);
        assert_eq!(a_raw.wrapping_add(v as u128), compose_u64(a_av.digits()));
        let _r = a_av.sub_value_assign(v);
        assert_eq!(a_raw, compose_u64(a_av.digits()));

        // add_modulo / sub_modulo / neg_modulo
        // Compute expected results without intermediate u128 overflow.
        let (sum, sum_overflow) = a_raw.overflowing_add(b_raw);
        let expected_add = if sum_overflow || sum >= m_raw {
            sum.wrapping_sub(m_raw)
        } else {
            sum
        };
        let expected_sub = if a_raw >= b_raw {
            a_raw - b_raw
        } else {
            m_raw - (b_raw - a_raw)
        };

        let mut s = a.clone();
        s.add_modulo_assign(&b, &modulus);
        assert_eq!(expected_add, compose_u64(s.digits()));

        let mut s = a.clone();
        s.sub_modulo_assign(&b, &modulus);
        assert_eq!(expected_sub, compose_u64(s.digits()));

        let mut c = a.clone();
        c.neg_modulo_assign(&modulus);
        let r = a.add_assign(&c);
        assert!(!r);
        assert!(a.is_zero() || a == modulus);
    }
}
