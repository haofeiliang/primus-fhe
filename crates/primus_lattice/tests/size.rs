use primus_lattice::{
    GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGlweSize,
};

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
