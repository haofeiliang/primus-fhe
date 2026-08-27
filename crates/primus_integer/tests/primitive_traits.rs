use std::sync::Arc;

use primus_integer::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedNeg, CheckedRem, CheckedShl, CheckedShr, CheckedSub,
    OverflowingAdd, OverflowingMul, OverflowingSub, Size,
};

#[test]
fn checked_traits_cover_unsigned_and_signed_edges() {
    assert_eq!(CheckedAdd::checked_add(u32::MAX, 1), None);
    assert_eq!(CheckedSub::checked_sub(0u32, 1), None);
    assert_eq!(CheckedMul::checked_mul(u32::MAX, 2), None);
    assert_eq!(CheckedDiv::checked_div(10u32, 0), None);
    assert_eq!(CheckedRem::checked_rem(10u32, 0), None);
    assert_eq!(CheckedNeg::checked_neg(1u32), None);
    assert_eq!(CheckedShl::checked_shl(1u32, u32::BITS), None);
    assert_eq!(CheckedShr::checked_shr(1u32, u32::BITS), None);

    assert_eq!(CheckedAdd::checked_add(i32::MAX, 1), None);
    assert_eq!(CheckedSub::checked_sub(i32::MIN, 1), None);
    assert_eq!(CheckedMul::checked_mul(i32::MIN, -1), None);
    assert_eq!(CheckedDiv::checked_div(i32::MIN, -1), None);
    assert_eq!(CheckedRem::checked_rem(i32::MIN, -1), None);
    assert_eq!(CheckedNeg::checked_neg(i32::MIN), None);
}

#[test]
fn overflowing_traits_delegate_to_primitive_arithmetic() {
    assert_eq!(OverflowingAdd::overflowing_add(u32::MAX, 1), (0, true));
    assert_eq!(OverflowingSub::overflowing_sub(0u32, 1), (u32::MAX, true));
    assert_eq!(
        OverflowingMul::overflowing_mul(u32::MAX, 2),
        (u32::MAX - 1, true)
    );

    assert_eq!(
        OverflowingAdd::overflowing_add(i32::MAX, 1),
        (i32::MIN, true)
    );
    assert_eq!(
        OverflowingSub::overflowing_sub(i32::MIN, 1),
        (i32::MAX, true)
    );
    assert_eq!(
        OverflowingMul::overflowing_mul(i32::MIN, -1),
        (i32::MIN, true)
    );
}

#[test]
fn size_counts_each_supported_storage_backend() {
    let values = [1u32, 2, 3, 4];
    let slice: &[u32] = &values;
    let boxed: Box<[u32]> = values.into();
    let arc: Arc<[u32]> = Arc::from(values);

    assert_eq!(values.byte_count(), 16);
    assert_eq!(values.to_vec().byte_count(), 16);
    assert_eq!(slice.byte_count(), 16);
    assert_eq!(boxed.byte_count(), 16);
    assert_eq!(arc.byte_count(), 16);
}
