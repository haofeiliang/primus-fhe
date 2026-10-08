//! Uniform chunk geometry and optional cleartext machine-word conversion.

use primus_integer::UnsignedInteger;

/// A chunk width that cannot represent `M` and `t=2*M` in host indexing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("chunk bit width must be positive and below usize::BITS - 1, got {chunk_bits}")]
pub struct ChunkFormatError {
    /// The rejected bit width.
    pub chunk_bits: u32,
}

/// Common bit width for independently encrypted high-precision LUT chunks.
///
/// A chunk holds `0..M`, where `M=2^bits`; padded encryption uses plaintext
/// modulus `t=2*M`. The width is positive and below `usize::BITS - 1`, so M
/// and t fit in host indexing. Compilation separately checks the complete
/// input domain, coefficient partition and storage size.
///
/// This type owns no codec or buffers and does not fix either chunk count.
/// Machine-word conversion is optional: a LUT callback may produce separate
/// output chunks whose combined width exceeds any one machine word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkFormat(u32);

impl ChunkFormat {
    /// Checks that the width represents at least two values and host-sized t.
    pub const fn try_new(chunk_bits: u32) -> Result<Self, ChunkFormatError> {
        if chunk_bits > 0 && chunk_bits < usize::BITS - 1 {
            Ok(Self(chunk_bits))
        } else {
            Err(ChunkFormatError { chunk_bits })
        }
    }

    /// Creates a uniform chunk format.
    ///
    /// # Panics
    /// Panics when [`Self::try_new`] rejects the width.
    #[must_use]
    pub const fn new(chunk_bits: u32) -> Self {
        match Self::try_new(chunk_bits) {
            Ok(format) => format,
            Err(_) => panic!("chunk bit width must be positive and below usize::BITS - 1"),
        }
    }

    /// Returns the common input/output chunk width.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns M, the number of values per chunk.
    #[must_use]
    pub const fn radix(self) -> usize {
        1usize << self.0
    }

    /// Returns M-1, the unsigned digit mask.
    #[must_use]
    pub const fn mask(self) -> usize {
        self.radix() - 1
    }

    /// Returns t=2*M for a Rounded codec at the chosen ciphertext modulus.
    ///
    /// # Panics
    /// Panics if t does not fit the requested unsigned word type.
    #[must_use]
    pub fn plaintext_modulus<T: UnsignedInteger>(self) -> T {
        T::try_from(self.radix() * 2)
            .expect("chunk plaintext modulus does not fit the requested word type")
    }

    /// Returns the combined width of an independently chosen chunk count.
    ///
    /// # Panics
    /// Panics if the bit count exceeds u32. This does not check
    /// whether a machine word, ring polynomial or full table can hold it.
    #[must_use]
    pub fn bit_count(self, chunk_count: usize) -> u32 {
        u32::try_from(chunk_count)
            .ok()
            .and_then(|count| count.checked_mul(self.0))
            .expect("chunk bit count exceeds u32")
    }

    /// Extracts one least-significant-first digit from a zero-extended word.
    /// Indices above the word's represented bits return zero; a partial top
    /// digit contains the remaining bits. No full-width shift is performed.
    #[must_use]
    pub fn chunk<T: UnsignedInteger>(self, value: T, index: usize) -> T {
        if index > ((T::BITS - 1) / self.0) as usize {
            return T::ZERO;
        }
        let mask = T::MAX >> T::BITS.saturating_sub(self.0);
        (value >> (index as u32 * self.0)) & mask
    }

    /// Splits a word into caller-owned, least-significant-first chunks.
    /// Overwrites the whole slice without allocating or silently truncating.
    /// An empty output accepts only zero.
    ///
    /// # Panics
    /// Panics before writes if the requested combined width exceeds T's word
    /// capacity, exceeds u32, or cannot represent value.
    pub fn split_to<T: UnsignedInteger>(self, value: T, output: &mut [T]) {
        let bits = self.check_word_capacity::<T>(output.len());
        assert!(
            bits == T::BITS || value >> bits == T::ZERO,
            "value exceeds the requested chunk count"
        );
        let mask = T::MAX >> T::BITS.saturating_sub(self.0);
        for (index, chunk) in output.iter_mut().enumerate() {
            *chunk = (value >> (index as u32 * self.0)) & mask;
        }
    }

    /// Joins least-significant-first chunks into an unsigned machine word.
    /// An empty input represents zero; no buffer is allocated.
    ///
    /// # Panics
    /// Panics if the combined width exceeds T's capacity or u32, or a digit
    /// lies outside 0..M. Arbitrarily long chunk sequences remain usable by
    /// the LUT API but cannot be joined into one such word.
    #[must_use]
    pub fn join<T: UnsignedInteger>(self, input: &[T]) -> T {
        self.check_word_capacity::<T>(input.len());
        let mask = T::MAX >> T::BITS.saturating_sub(self.0);
        let mut value = T::ZERO;
        for (index, &chunk) in input.iter().enumerate() {
            assert!(chunk <= mask, "chunk value is outside 0..M");
            value |= chunk << (index as u32 * self.0);
        }
        value
    }

    /// Derives the same format at the raw codec boundary. A representable
    /// power-of-two t>=4 implies the constructor's width range already holds.
    pub(crate) fn from_plaintext_modulus<T: UnsignedInteger>(modulus: T) -> Option<Self> {
        let modulus: usize = modulus.try_into().ok()?;
        (modulus >= 4 && modulus.is_power_of_two()).then(|| Self(modulus.trailing_zeros() - 1))
    }

    /// Checks total capacity once before word conversion. Exact-width packing
    /// is legal; the individual digit shifts are still strictly below T::BITS.
    fn check_word_capacity<T: UnsignedInteger>(self, chunk_count: usize) -> u32 {
        let bits = self.bit_count(chunk_count);
        assert!(bits <= T::BITS, "chunks exceed the word capacity");
        bits
    }
}
