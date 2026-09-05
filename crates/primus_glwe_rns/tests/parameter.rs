use primus_decompose::ApproxSignedBasisError;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlevParametersError, CrtGlweParameters, SecretKeyDistr,
};
use primus_modulus::BarrettModulus;

#[test]
fn gadget_basis_must_fit_every_rns_modulus() {
    // The restrictive modulus is deliberately not the first one.
    let moduli = [97u64, 17].map(BarrettModulus::new);
    let glwe = CrtGlweParameters::new(
        1,
        8,
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        &moduli,
        SecretKeyDistr::UniformTernary,
        1.0,
    );
    assert!(CrtGlevParameters::try_with_glwe_params(&glwe, 4, None).is_ok());
    for log_basis in [5, 6] {
        assert!(matches!(
            CrtGlevParameters::try_with_glwe_params(&glwe, log_basis, None),
            Err(CrtGlevParametersError::BasisNotSmallerThanModulus { basis, modulus: 17, index: 1 })
                if basis == 1 << log_basis
        ));
    }
    assert!(matches!(
        CrtGlevParameters::try_with_glwe_params(&glwe, 1, None),
        Err(CrtGlevParametersError::InvalidDecomposition(
            ApproxSignedBasisError::InvalidLogBasis { .. }
        ))
    ));
}
