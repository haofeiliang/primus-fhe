use core::cmp::Ordering;
use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use primus_data::{Data, DataMut, RawData};
use serde::{Deserialize, Serialize};

use crate::{UnsignedInteger, impl_iters};

/// A fixed-width unsigned integer backed by little-endian limb storage.
///
/// `BigUint<S>` is a lightweight view or container over borrowed or owned
/// storage. It does not remove leading zero limbs: the limb count is part of
/// the representation and equality. Operations involving multiple `BigUint`s
/// require matching limb counts; higher-level callers are responsible for
/// validating their buffer layouts.
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
    pub fn iter<'a>(&'a self) -> core::slice::Iter<'a, T> {
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

    /// Writes `self + value` to `output` and returns the carry beyond its fixed width.
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

    /// Writes `self - value` to `output` and returns the final borrow.
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

    /// Writes the low limbs of `self * value` to `output` and returns the high limb.
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

    /// Accumulates `self * value` into `acc` and returns the carry beyond its fixed width.
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

    /// Writes `self + other` to `output` and returns the carry beyond its fixed width.
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

    /// Writes `self - other` to `output` and returns the final borrow.
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
    /// Requires `self` and `other` to be less than `modulus` and all operands
    /// to have the same limb count.
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

    /// Subtracts two reduced big integers and writes the result modulo `modulus`.
    ///
    /// Requires `self` and `other` to be less than `modulus` and all operands
    /// to have the same limb count.
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
    /// Requires `self < modulus` and equal limb counts for the input, output,
    /// and modulus.
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

    /// Shifts left within the fixed width and returns the bits shifted out.
    ///
    /// `bits` must be less than `T::BITS`; larger shifts are unsupported and
    /// may panic. A zero shift leaves the value unchanged.
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

    /// Shifts right within the fixed width, discarding the low bits.
    ///
    /// `bits` must be less than `T::BITS`; larger shifts are unsupported and
    /// may panic. A zero shift leaves the value unchanged.
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

    /// Adds `value` and returns the carry beyond the fixed width.
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

    /// Subtracts `value` and returns the final borrow.
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

    /// Multiplies by `value` and returns the high limb beyond the fixed width.
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

    /// Adds `other` and returns the carry beyond the fixed width.
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

    /// Subtracts `other` and returns the final borrow.
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
    /// Requires both operands to be less than `modulus` and to have the same
    /// limb count as the modulus.
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
    /// Requires both operands to be less than `modulus` and to have the same
    /// limb count as the modulus.
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
    /// Requires both operands to be less than `modulus` and to have the same
    /// limb count as the modulus.
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
    /// Requires `self < modulus` and matching limb counts.
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

/// Multiplies the values and returns their product as an owned [`BigUint`].
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
