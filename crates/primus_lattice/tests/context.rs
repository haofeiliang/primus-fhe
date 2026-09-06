#![cfg(feature = "rns")]

use primus_lattice::{GlweSize, RnsGadgetSize, RnsGlweSize, context::DcrtGlevMulContext};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

#[test]
fn dcrt_workspace_reuse_depends_on_layout_and_limb_width() {
    let size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 8), 2), 3);
    let small = RNSBase::new(&[17u32, 97].map(BarrettModulus::new)).unwrap();
    let other_small = RNSBase::new(&[19u32, 101].map(BarrettModulus::new)).unwrap();
    let large = RNSBase::new(&[65537u32, 65539].map(BarrettModulus::new)).unwrap();
    let context = DcrtGlevMulContext::new(size, &small);

    assert_eq!(small.big_uint_value_len(), 1);
    assert_eq!(large.big_uint_value_len(), 2);
    assert!(context.is_compatible(size, &small));
    assert!(context.is_compatible(size, &other_small));
    assert!(!context.is_compatible(size, &large));
    let other_size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 16), 2), 3);
    assert!(!context.is_compatible(other_size, &small));
}
