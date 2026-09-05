use primus_decompose::{ApproxSignedBasisError, big_integer::BigUintApproxSignedBasis};
use primus_integer::BigUint;

#[test]
fn try_new_validates_big_uint_basis_parameters() {
    let modulus = BigUint([17_u32 * 97]);

    assert!(BigUintApproxSignedBasis::try_new(modulus.view(), 4, None).is_ok());
    assert_eq!(
        BigUintApproxSignedBasis::try_new(modulus.view(), 1, None).unwrap_err(),
        ApproxSignedBasisError::InvalidLogBasis {
            log_basis: 1,
            limb_bits: 32,
        }
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(modulus.view(), 32, None).unwrap_err(),
        ApproxSignedBasisError::InvalidLogBasis {
            log_basis: 32,
            limb_bits: 32,
        }
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(modulus.view(), 4, Some(0)).unwrap_err(),
        ApproxSignedBasisError::ZeroReverseLength
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(modulus.view(), 4, Some(3)).unwrap_err(),
        ApproxSignedBasisError::ReverseLengthTooLarge {
            reverse_length: 3,
            full_length: 2,
        }
    );

    assert_eq!(
        BigUintApproxSignedBasis::try_new(BigUint(&[3_u32]), 2, None).unwrap_err(),
        ApproxSignedBasisError::BasisExceedsModulus
    );

    for invalid in [&[][..], &[0][..], &[0, 0][..], &[1649, 0][..]] {
        assert_eq!(
            BigUintApproxSignedBasis::<u32>::try_new(BigUint(invalid), 4, None).unwrap_err(),
            ApproxSignedBasisError::InvalidModulusRepresentation
        );
    }
    // Zero low limbs are valid; only redundant high zero limbs are rejected.
    assert!(BigUintApproxSignedBasis::try_new(BigUint(&[0_u32, 1]), 4, None).is_ok());
}
