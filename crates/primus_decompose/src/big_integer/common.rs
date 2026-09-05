use core::{iter::FusedIterator, num::NonZeroU32, slice::Iter};

use primus_integer::{BigUint, FheUint};

/// How to initialize the carry bit and adjust a `BigUint` input before decomposition.
///
/// `threshold` is the split value: inputs `>= threshold` are adjusted by `add`.
/// `index` and `mask` select the limb and bit used to extract the initial carry.
#[derive(Debug, Clone)]
pub(super) enum BigUintValueCarryInitMode<T: FheUint> {
    /// Both adjust the value and extract a carry bit.
    AdjustAndCarry {
        /// Values `>= threshold` are adjusted.
        threshold: BigUint<Vec<T>>,
        /// Amount added to adjust the value.
        add: BigUint<Vec<T>>,
        /// Limb index used to extract the initial carry.
        index: usize,
        /// Mask applied to extract the initial carry.
        mask: T,
    },
    /// Adjust the value without extracting a carry bit.
    AdjustOnly {
        /// Values `>= threshold` are adjusted.
        threshold: BigUint<Vec<T>>,
        /// Amount added to adjust the value.
        add: BigUint<Vec<T>>,
    },
}

/// Mask to extract a window of bits from a multi-limb `BigUint`.
///
/// The window spans `bit_len(mask)` bits, starting at bit position `shr_bits`
/// within `value[index]`. When the window crosses a limb boundary (i.e.
/// `shr_bits + bit_len(mask) > T::BITS`), the upper part spills into
/// `value[index + 1]` and must be shifted back into place with `shl_bits`.
#[derive(Debug, Clone, Copy)]
pub(super) struct ValueMask<T: FheUint> {
    /// The bitmask applied after shifting — equal to `basis - 1`.
    mask: T,
    /// Which limb to read from `value[index]`.
    index: usize,
    /// Right-shift amount applied to the lower limb.
    shr_bits: u32,
    /// Left-shift amount for the upper limb, when the window crosses a limb
    /// boundary. `None` means the window fits entirely in one limb.
    ///
    /// Invariant: when `Some(n)`, `n == T::BITS - shr_bits` and `n > 0`.
    shl_bits: Option<NonZeroU32>,
}

impl<T: FheUint> ValueMask<T> {
    /// Creates a mask starting at bit offset `drop_bits`.
    ///
    /// `drop_bits` may span multiple limbs — `index` advances past whole limbs,
    /// `shr_bits` is the remainder within the current limb.
    #[inline]
    pub fn new(mask: T, drop_bits: u32) -> Self {
        let index = (drop_bits / T::BITS) as usize;
        let shr_bits = drop_bits % T::BITS;

        // The window crosses a limb boundary iff the highest set bit of `mask`,
        // left-shifted by `shr_bits`, would exceed the first limb.
        // `mask.leading_zeros()` = T::BITS - bit_len(mask), so this is:
        //     shr_bits + bit_len(mask) > T::BITS.
        let shl_bits = if mask.leading_zeros() < shr_bits {
            NonZeroU32::new(T::BITS - shr_bits)
        } else {
            None
        };

        Self {
            mask,
            index,
            shr_bits,
            shl_bits,
        }
    }

    /// Extracts the masked window from `value` using shift-then-AND.
    ///
    /// On the happy path (no limb cross), this is simply
    /// `(value[index] >> shr_bits) & mask`, matching the primitive version.
    /// When the window straddles two limbs, we shift each limb independently
    /// to align the bits and OR them together before masking.
    #[inline]
    fn get_value(&self, value: &[T]) -> T {
        let lower = value[self.index] >> self.shr_bits;

        if let Some(shl_bits) = self.shl_bits {
            (lower | (value[self.index + 1] << shl_bits.get())) & self.mask
        } else {
            lower & self.mask
        }
    }
}

/// An iterator over the signed decomposition operators for [`BigUint`] values.
///
/// [`BigUint`]: primus_integer::BigUint
pub struct BigUintSignedDecomposerIter<'a, T: FheUint> {
    pub(super) value_masks: Iter<'a, ValueMask<T>>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: &'a [T],
}

impl<'a, T: FheUint> BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn make_item(&self, value_mask: &ValueMask<T>) -> OnceBigUintSignedDecomposer<'a, T> {
        OnceBigUintSignedDecomposer {
            value_mask: *value_mask,
            carry_mask: self.carry_mask,
            basis_minus_one: self.basis_minus_one,
            modulus_minus_basis: BigUint(self.modulus_minus_basis),
        }
    }
}

impl<'a, T: FheUint> Iterator for BigUintSignedDecomposerIter<'a, T> {
    type Item = OnceBigUintSignedDecomposer<'a, T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.value_masks.next().map(|v| self.make_item(v))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth(n).map(|v| self.make_item(v))
    }

    #[inline]
    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a, T: FheUint> FusedIterator for BigUintSignedDecomposerIter<'a, T> {}

impl<'a, T: FheUint> core::iter::DoubleEndedIterator for BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.value_masks.next_back().map(|v| self.make_item(v))
    }

    #[inline]
    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.value_masks.nth_back(n).map(|v| self.make_item(v))
    }
}

impl<'a, T: FheUint> ExactSizeIterator for BigUintSignedDecomposerIter<'a, T> {
    #[inline]
    fn len(&self) -> usize {
        self.value_masks.len()
    }
}

/// Extracts one signed digit from an initialized multi-limb input.
///
/// Obtain operators from [`super::BigUintApproxSignedBasis::decomposer_iter`]
/// and apply them in order to the same adjusted value. The first carry comes
/// from initialization; later carries come from the preceding level.
/// A carry can be true even when the returned digit is zero.
///
/// Full-width values have exactly the basis's `big_uint_value_len()`
/// little-endian limbs. Batch buffers are value-major, with all limbs of each
/// value contiguous. Unsigned digit outputs instead use one limb per value.
pub struct OnceBigUintSignedDecomposer<'a, T: FheUint> {
    pub(super) value_mask: ValueMask<T>,
    pub(super) carry_mask: T,
    pub(super) basis_minus_one: T,
    pub(super) modulus_minus_basis: BigUint<&'a [T]>,
}

impl<'a, T: FheUint> OnceBigUintSignedDecomposer<'a, T> {
    #[inline]
    fn big_uint_value_len(&self) -> usize {
        // `modulus_minus_basis` is computed in-place from the fixed-width modulus,
        // so it always has the same number of limbs as an input value.
        self.modulus_minus_basis.len()
    }

    /// Extracts a retained window plus the incoming carry, in [0, B], and
    /// advances `carry` to the next level.
    /// The signed digit is temp - next_carry*B. In particular, temp == B
    /// produces digit zero but must still carry into the next level.
    /// The two-bit mask tests temp >= B/2, including the overflow bit at B.
    #[inline]
    fn extract_with_carry(&self, value: &[T], carry: &mut bool) -> T {
        let temp = self.value_mask.get_value(value) + T::as_from(*carry);
        *carry = !(temp & self.carry_mask).is_zero();
        temp
    }

    /// Allocates a digit encoded modulo `Q` and returns the next carry.
    ///
    /// The signed digit lies in `[-B/2, B/2)`. Negative digits are represented
    /// by `Q + digit`. `value` must have exactly `big_uint_value_len()` limbs;
    /// both it and `carry` must follow this operator's initialization protocol.
    #[inline]
    pub fn decompose(&self, value: &[T], mut carry: bool) -> (Vec<T>, bool) {
        debug_assert_eq!(value.len(), self.big_uint_value_len());
        let temp = self.extract_with_carry(value, &mut carry);
        let mut result = BigUint(vec![T::ZERO; value.len()]);
        if carry {
            if temp <= self.basis_minus_one {
                let _ = self.modulus_minus_basis.add_value_to(temp, &mut result);
            }
        } else {
            result[0] = temp;
        }

        (result.0, carry)
    }

    /// Returns a signed digit encoded modulo `B`, and the next carry.
    ///
    /// The result is in `[0, B)`: values below `B/2` encode themselves, and
    /// values at or above `B/2` encode `result - B`. For example, `B - 1`
    /// encodes `-1`, not a positive digit. Unlike [`Self::decompose`], this
    /// returns one limb rather than a residue modulo `Q`.
    /// Input shape and initialization requirements match [`Self::decompose`].
    #[inline]
    pub fn unsigned_decompose(&self, value: &[T], mut carry: bool) -> (T, bool) {
        debug_assert_eq!(value.len(), self.big_uint_value_len());
        let temp = self.extract_with_carry(value, &mut carry);

        (temp & self.basis_minus_one, carry)
    }

    /// Writes a digit modulo `Q` and advances `carry`, as in [`Self::decompose`].
    ///
    /// Both value slices must contain exactly `big_uint_value_len()` limbs.
    /// The output is overwritten, not accumulated.
    #[inline]
    pub fn decompose_to(&self, value: &[T], decomposed_value: &mut [T], carry: &mut bool) {
        debug_assert_eq!(value.len(), self.big_uint_value_len());
        debug_assert_eq!(decomposed_value.len(), self.big_uint_value_len());
        self.decompose_to_kernel(value, decomposed_value, carry);
    }

    #[inline]
    fn decompose_to_kernel(&self, value: &[T], decomposed_value: &mut [T], carry: &mut bool) {
        let temp = self.extract_with_carry(value, carry);

        if *carry {
            if temp > self.basis_minus_one {
                decomposed_value.fill(T::ZERO);
            } else {
                let _ = self
                    .modulus_minus_basis
                    .add_value_to(temp, &mut BigUint(decomposed_value));
            }
        } else {
            decomposed_value.fill(T::ZERO);
            decomposed_value[0] = temp;
        }
    }

    /// Writes a digit modulo `B` and advances `carry`, as in [`Self::unsigned_decompose`].
    /// The output is overwritten, not accumulated.
    #[inline]
    pub fn unsigned_decompose_to(
        &self,
        value: &[T],
        decomposed_unsigned_value: &mut T,
        carry: &mut bool,
    ) {
        debug_assert_eq!(value.len(), self.big_uint_value_len());
        self.unsigned_decompose_to_kernel(value, decomposed_unsigned_value, carry);
    }

    #[inline]
    fn unsigned_decompose_to_kernel(
        &self,
        value: &[T],
        decomposed_unsigned_value: &mut T,
        carry: &mut bool,
    ) {
        let temp = self.extract_with_carry(value, carry);

        *decomposed_unsigned_value = temp & self.basis_minus_one;
    }

    /// Writes full-width digits modulo `Q` and advances the corresponding carries.
    ///
    /// Both value buffers must have length `carries.len() * big_uint_value_len()`
    /// in value-major layout. Inputs follow [`Self::decompose`]; all output
    /// limbs are overwritten, not accumulated.
    #[inline]
    pub fn decompose_slice_to(
        &self,
        big_uint_values: &[T],
        decomposed_big_uint_values: &mut [T],
        carries: &mut [bool],
    ) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(decomposed_big_uint_values.len(), big_uint_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        for ((value, decomposed_value), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(decomposed_big_uint_values.chunks_exact_mut(big_uint_value_len))
            .zip(carries)
        {
            self.decompose_to_kernel(value, decomposed_value, carry);
        }
    }

    /// Writes one digit modulo `B` per adjusted input and advances its carry.
    ///
    /// `big_uint_values.len()` must equal `carries.len() * big_uint_value_len()`
    /// in value-major layout. The digit output must have `carries.len()` limbs.
    /// Inputs follow [`Self::unsigned_decompose`]; outputs are overwritten.
    #[inline]
    pub fn unsigned_decompose_slice_to(
        &self,
        big_uint_values: &[T],
        decomposed_unsigned_values: &mut [T],
        carries: &mut [bool],
    ) {
        let big_uint_value_len = self.big_uint_value_len();
        debug_assert_eq!(carries.len(), decomposed_unsigned_values.len());
        debug_assert_eq!(big_uint_values.len(), carries.len() * big_uint_value_len);
        for ((value, decomposed_unsigned_value), carry) in big_uint_values
            .chunks_exact(big_uint_value_len)
            .zip(decomposed_unsigned_values.iter_mut())
            .zip(carries)
        {
            self.unsigned_decompose_to_kernel(value, decomposed_unsigned_value, carry);
        }
    }
}
