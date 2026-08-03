use primus_decompose::big_integer::{BigUintApproxSignedBasis, BigUintApproxSignedBasisError};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

#[test]
fn try_new_validates_big_uint_basis_parameters() {
    let moduli = [BarrettModulus::new(17_u32), BarrettModulus::new(97)];
    let rns_base = RNSBase::new(&moduli).unwrap();

    assert!(BigUintApproxSignedBasis::try_new(&rns_base, 4, None).is_ok());
    assert_eq!(
        BigUintApproxSignedBasis::try_new(&rns_base, 1, None).unwrap_err(),
        BigUintApproxSignedBasisError::InvalidLogBasis {
            log_basis: 1,
            limb_bits: 32,
        }
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(&rns_base, 32, None).unwrap_err(),
        BigUintApproxSignedBasisError::InvalidLogBasis {
            log_basis: 32,
            limb_bits: 32,
        }
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(&rns_base, 4, Some(0)).unwrap_err(),
        BigUintApproxSignedBasisError::ZeroReverseLength
    );
    assert_eq!(
        BigUintApproxSignedBasis::try_new(&rns_base, 4, Some(3)).unwrap_err(),
        BigUintApproxSignedBasisError::ReverseLengthTooLarge {
            reverse_length: 3,
            full_length: 2,
        }
    );

    let small_base = RNSBase::new(&[BarrettModulus::new(3_u32)]).unwrap();
    assert_eq!(
        BigUintApproxSignedBasis::try_new(&small_base, 2, None).unwrap_err(),
        BigUintApproxSignedBasisError::BasisExceedsModulus
    );
}
