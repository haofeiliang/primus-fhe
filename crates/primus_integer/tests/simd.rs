#![cfg(feature = "simd")]
#![cfg_attr(feature = "simd", feature(portable_simd))]

use std::simd::{Mask, Simd};

use primus_integer::{BorrowingSub, CarryingAdd, CarryingMul, SimdInteger, WideningMul};

#[test]
fn slice_helpers_preserve_chunks_and_tail() {
    let lane_count = <u32 as SimdInteger>::LANE_COUNT;
    let mut values: Vec<u32> = (0..lane_count as u32 + 3).collect();

    let (chunks, tail) = u32::simd_as_chunks(&values);
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        tail,
        &[
            lane_count as u32,
            lane_count as u32 + 1,
            lane_count as u32 + 2
        ]
    );

    let (chunks, tail) = u32::simd_as_chunks_mut(&mut values);
    chunks[0].fill(7);
    tail.fill(9);
    assert!(values[..lane_count].iter().all(|&value| value == 7));
    assert_eq!(&values[lane_count..], &[9, 9, 9]);
}

#[test]
fn u32_simd_word_operations_match_scalar_lanes() {
    let lhs = Simd::<u32, 8>::from_array([
        0,
        1,
        u32::MAX,
        u32::MAX,
        0x8000_0000,
        0x7fff_ffff,
        123_456_789,
        4_000_000_000,
    ]);
    let rhs = Simd::<u32, 8>::from_array([
        0,
        u32::MAX,
        1,
        u32::MAX,
        0x8000_0000,
        2,
        987_654_321,
        500_000_000,
    ]);
    let carry = Simd::<u32, 8>::from_array([0, 1, 2, 3, 4, 5, 6, 7]);
    let add = Simd::<u32, 8>::from_array([7, 6, 5, 4, 3, 2, 1, 0]);
    let mask = Mask::<i32, 8>::from_array([false, true, false, true, true, false, true, false]);

    let lhs_array = lhs.to_array();
    let rhs_array = rhs.to_array();
    let carry_array = carry.to_array();
    let add_array = add.to_array();
    let mask_array = mask.to_array();

    let (sum, sum_carry) = CarryingAdd::carrying_add(lhs, rhs, mask);
    let (difference, borrow) = BorrowingSub::borrowing_sub(lhs, rhs, mask);
    let (product_low, product_high) = WideningMul::widening_mul(lhs, rhs);
    let product_high_only = WideningMul::widening_mul_hw(lhs, rhs);
    let (carry_low, carry_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
    let carry_high_only = CarryingMul::carrying_mul_hw(lhs, rhs, carry);
    let (add_low, add_high) = CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
    let add_high_only = CarryingMul::carrying_mul_add_hw(lhs, rhs, carry, add);

    for index in 0..8 {
        assert_eq!(
            (sum[index], sum_carry.test(index)),
            CarryingAdd::carrying_add(lhs_array[index], rhs_array[index], mask_array[index]),
        );
        assert_eq!(
            (difference[index], borrow.test(index)),
            BorrowingSub::borrowing_sub(lhs_array[index], rhs_array[index], mask_array[index]),
        );
        assert_eq!(
            (product_low[index], product_high[index]),
            WideningMul::widening_mul(lhs_array[index], rhs_array[index]),
        );
        assert_eq!(product_high_only[index], product_high[index]);
        assert_eq!(
            (carry_low[index], carry_high[index]),
            CarryingMul::carrying_mul(lhs_array[index], rhs_array[index], carry_array[index]),
        );
        assert_eq!(carry_high_only[index], carry_high[index]);
        assert_eq!(
            (add_low[index], add_high[index]),
            CarryingMul::carrying_mul_add(
                lhs_array[index],
                rhs_array[index],
                carry_array[index],
                add_array[index],
            ),
        );
        assert_eq!(add_high_only[index], add_high[index]);
    }
}

#[test]
fn u64_simd_multiplication_matches_scalar_lanes() {
    let lhs = Simd::<u64, 4>::from_array([0, 1, u64::MAX, 0x8000_0000_0000_0001]);
    let rhs = Simd::<u64, 4>::from_array([u64::MAX, 7, u64::MAX, 0x7fff_ffff_ffff_ffff]);
    let carry = Simd::<u64, 4>::from_array([1, 2, 3, 4]);

    let lhs_array = lhs.to_array();
    let rhs_array = rhs.to_array();
    let carry_array = carry.to_array();
    let (product_low, product_high) = WideningMul::widening_mul(lhs, rhs);
    let product_high_only = WideningMul::widening_mul_hw(lhs, rhs);
    let (carry_low, carry_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
    let carry_high_only = CarryingMul::carrying_mul_hw(lhs, rhs, carry);

    for index in 0..4 {
        assert_eq!(
            (product_low[index], product_high[index]),
            WideningMul::widening_mul(lhs_array[index], rhs_array[index]),
        );
        assert_eq!(product_high_only[index], product_high[index]);
        assert_eq!(
            (carry_low[index], carry_high[index]),
            CarryingMul::carrying_mul(lhs_array[index], rhs_array[index], carry_array[index]),
        );
        assert_eq!(carry_high_only[index], carry_high[index]);
    }
}
