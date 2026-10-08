use primus_tfhe_ntru_lut::{ChunkFormat, ChunkFormatError};
use std::panic::{AssertUnwindSafe, catch_unwind};

// Compare digits to an independent shift/mask oracle, including exact word
// capacity, a partial top digit and zero extension without oversized shifts.
#[test]
fn word_conversion_preserves_least_significant_first_digits() {
    let format = ChunkFormat::new(2);
    assert_eq!(format.radix(), 4);
    assert_eq!(format.mask(), 3);
    assert_eq!(format.plaintext_modulus::<u32>(), 8);
    assert_eq!(format.plaintext_modulus::<u64>(), 8);
    for value in [0, 0b10_10_10_11_11_00_11_01, u32::MAX] {
        let mut digits = [0u32; 16];
        format.split_to(value, &mut digits);
        for (index, &digit) in digits.iter().enumerate() {
            assert_eq!(digit, (value >> (2 * index)) & 3);
        }
        assert_eq!(format.join(&digits), value);
    }
    for value in [0, 1u64 << 63, u64::MAX] {
        let mut digits = [0u64; 32];
        format.split_to(value, &mut digits);
        for (index, &digit) in digits.iter().enumerate() {
            assert_eq!(digit, (value >> (2 * index)) & 3);
        }
        assert_eq!(format.join(&digits), value);
    }
    let format = ChunkFormat::new(3);
    assert_eq!(format.chunk(u32::MAX, 10), 3);
    assert_eq!(format.chunk(u32::MAX, 11), 0);
    assert_eq!(format.chunk(u64::MAX, usize::MAX), 0);
    // The conversion helper is not restricted to u64; the LUT callback still
    // supports outputs too wide to join into any one word.
    let format = ChunkFormat::new(2);
    let mut digits = [0u128; 64];
    format.split_to(u128::MAX, &mut digits);
    assert_eq!(digits, [3; 64]);
    assert_eq!(format.join(&digits), u128::MAX);
    format.split_to(0u32, &mut []);
    assert_eq!(format.join::<u32>(&[]), 0);
}

// Raw word helpers own their capacity/digit checks. Splitting rejects before
// output writes, so a failed conversion cannot silently truncate client data.
#[test]
fn conversion_rejects_invalid_width_capacity_and_digits() {
    for chunk_bits in [0, usize::BITS - 1, usize::BITS, u32::MAX] {
        assert_eq!(
            ChunkFormat::try_new(chunk_bits),
            Err(ChunkFormatError { chunk_bits })
        );
    }
    let format = ChunkFormat::new(2);
    let mut digits = [7u32; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| format.split_to(16, &mut digits))).is_err());
    assert_eq!(digits, [7; 2]);
    let mut too_many = [7u32; 17];
    assert!(catch_unwind(AssertUnwindSafe(|| format.split_to(0, &mut too_many))).is_err());
    assert_eq!(too_many, [7; 17]);
    assert!(catch_unwind(|| format.join(&[0u32; 17])).is_err());
    assert!(catch_unwind(|| format.join(&[4u32])).is_err());
    assert!(catch_unwind(|| format.split_to(1u32, &mut [])).is_err());
    assert!(catch_unwind(|| format.bit_count(usize::MAX)).is_err());
    // Large counts do not allocate; the result itself must fit u32.
    assert_eq!(ChunkFormat::new(1).bit_count(u32::MAX as usize), u32::MAX);
    let last_count = (u32::MAX / 2) as usize;
    assert_eq!(format.bit_count(last_count), u32::MAX - 1);
    assert!(catch_unwind(|| format.bit_count(last_count + 1)).is_err());
    if usize::BITS > u32::BITS {
        assert!(catch_unwind(|| ChunkFormat::new(31).plaintext_modulus::<u32>()).is_err());
    }
    let widest = ChunkFormat::new(usize::BITS - 2);
    assert_eq!(
        widest.plaintext_modulus::<usize>(),
        1usize << (usize::BITS - 1)
    );
}
