//! Checked layout boundaries and RNS scratch compatibility.

use primus_lattice::{
    GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGlweSize,
};
use primus_modulus::{BarrettModulus, NativeModulus};

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
    use primus_lattice::{RnsGadgetSize, workspace::DcrtGlevMulWorkspace};
    use primus_rns::RNSBase;
    let size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 8), 2), 3);
    let small = RNSBase::new(&[17u32, 97].map(BarrettModulus::new)).unwrap();
    let other_small = RNSBase::new(&[19u32, 101].map(BarrettModulus::new)).unwrap();
    let large = RNSBase::new(&[65537u32, 65539].map(BarrettModulus::new)).unwrap();
    let workspace = DcrtGlevMulWorkspace::new(size, &small);

    assert_eq!(small.big_uint_value_len(), 1);
    assert_eq!(large.big_uint_value_len(), 2);
    assert!(workspace.is_compatible(size, &small));
    assert!(workspace.is_compatible(size, &other_small));
    assert!(!workspace.is_compatible(size, &large));
    let other_size = RnsGadgetSize::new(RnsGlweSize::new(GlweSize::new(1, 16), 2), 3);
    assert!(!workspace.is_compatible(other_size, &small));
}

#[test]
fn serial_external_product_restores_ternary_layout_on_unwind() {
    use primus_lattice::workspace::{FourierGlweTernaryCmuxWorkspace, NttGlweTernaryCmuxWorkspace};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // Rebinding changes the serial consumer's level count, never its GLWE
    // geometry. An unwinding consumer must not leave that temporary binding.
    const N: usize = 16;
    let original = GadgetSize::new(GlweSize::new(1, N), 3);
    let temporary = GadgetSize::new(GlweSize::new(1, N), 2);
    let mut ntt = NttGlweTernaryCmuxWorkspace::<u32>::new(original);
    let mut fourier = FourierGlweTernaryCmuxWorkspace::<u64>::new(original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| ntt.with_external_product(
            temporary,
            |scratch| {
                assert_eq!(scratch.size(), temporary);
                panic!("interrupted consumer");
            }
        )))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| fourier.with_external_product(
            temporary,
            |scratch| {
                assert_eq!(scratch.size(), temporary);
                panic!("interrupted consumer");
            }
        )))
        .is_err()
    );
    assert_eq!(ntt.size(), original);
    assert_eq!(fourier.size(), original);

    // A shape mismatch is rejected before invoking the consumer, leaving the
    // workspace available for its original layout in release as well as debug.
    let different = GadgetSize::new(GlweSize::new(1, 2 * N), 3);
    let mut called = false;
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            ntt.with_external_product(different, |_| called = true);
        }))
        .is_err()
    );
    assert!(!called);
    assert_eq!(ntt.size(), original);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            fourier.with_external_product(different, |_| called = true);
        }))
        .is_err()
    );
    assert!(!called);
    assert_eq!(fourier.size(), original);
}

#[test]
fn consuming_negation_reuses_aligned_and_borrowed_storage() {
    use primus_lattice::lwe::Lwe;

    // ABox supports the same DataMut contract as an ordinary mutable slice;
    // consuming a wrapper must keep its allocation, including for u64 torus data.
    let ciphertext = Lwe::new(aligned_vec::avec![0u64, u64::MAX, u64::MAX - 6].into_boxed_slice());
    let original_pointer = ciphertext.as_ref().as_ptr();
    let ciphertext = ciphertext.neg(NativeModulus::new());
    assert_eq!(ciphertext.as_ref().as_ptr(), original_pointer);
    assert_eq!(ciphertext.as_ref(), &[0, 1, 7]);

    let mut storage = [99u32, 0, 96, 45, 99];
    let ciphertext = Lwe::new(&mut storage[1..4]).neg(BarrettModulus::new(97));
    assert_eq!(ciphertext.as_ref(), &[0, 1, 52]);
    assert_eq!(storage, [99, 0, 1, 52, 99]);
}
