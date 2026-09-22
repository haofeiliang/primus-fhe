//! Checked layout boundaries and RNS scratch compatibility.

use primus_lattice::{
    GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGlweSize,
};
#[cfg(feature = "rns")]
use primus_modulus::BarrettModulus;

#[test]
fn checked_sizes_reject_empty_and_overflowing_layouts() {
    assert_eq!(GlweSize::try_new(0, 2), Err(GlweSizeError::ZeroDimension));
    assert_eq!(
        GlweSize::try_new(1, 0),
        Err(GlweSizeError::InvalidPolynomialLength)
    );
    assert!(GlweSize::try_new(1, MIN_POLY_LENGTH).is_ok());
    assert!(GlweSize::try_new(1, MAX_POLY_LENGTH).is_ok());
    assert_eq!(
        GlweSize::try_new(1, MAX_POLY_LENGTH << 1),
        Err(GlweSizeError::InvalidPolynomialLength)
    );

    let glwe = GlweSize::new(1, 2);
    assert_eq!(
        RnsGlweSize::try_new(glwe, 0),
        Err(GlweSizeError::ZeroModuliCount)
    );
    assert_eq!(
        GadgetSize::try_new(glwe, 0),
        Err(GlweSizeError::ZeroDecomposeLength)
    );
    assert!(matches!(
        GlweSize::try_new(usize::MAX, 2),
        Err(GlweSizeError::LengthOverflow(_))
    ));
    assert!(matches!(
        RnsGlweSize::try_new(glwe, usize::MAX),
        Err(GlweSizeError::LengthOverflow(_))
    ));
}

#[cfg(feature = "rns")]
#[test]
fn dcrt_workspace_reuse_depends_on_layout_and_limb_width() {
    use primus_lattice::{RnsGadgetSize, context::DcrtGlevMulContext};
    use primus_rns::RNSBase;
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
