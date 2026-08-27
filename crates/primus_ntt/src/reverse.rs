use primus_integer::UnsignedInteger;

/// Defines a function that reverses the `bits` least-significant bits of `Self`
/// and sets all other bits to zero.
pub trait ReverseLsbs {
    /// Reverses the `bits` least-significant bits of `self` and sets all
    /// higher-order bits to zero.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// assert_eq!(0b00001101u8.reverse_lsbs(4), 0b00001011u8);
    /// assert_eq!(0b01101101u8.reverse_lsbs(4), 0b00001011u8);
    /// ```
    fn reverse_lsbs(self, bits: u32) -> Self;
}

impl<T: UnsignedInteger> ReverseLsbs for T {
    #[inline]
    fn reverse_lsbs(self, bits: u32) -> Self {
        debug_assert!(bits <= T::BITS);
        if self == T::ZERO || bits == 0 {
            T::ZERO
        } else {
            self.reverse_bits() >> (T::BITS - bits)
        }
    }
}
