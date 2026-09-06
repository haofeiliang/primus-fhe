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

#[test]
fn cached_weights_and_centered_digits_follow_rns_order() {
    let moduli = [134_215_681u32, 134_176_769];
    let q: u64 = moduli.iter().map(|&modulus| u64::from(modulus)).product();
    let glwe = CrtGlweParameters::new(
        1,
        8,
        BarrettModulus::new(3),
        BarrettModulus::new(101),
        &moduli.map(BarrettModulus::new),
        SecretKeyDistr::UniformTernary,
        1.0,
    );
    // Two-limb values, including centered boundaries and a SIMD tail.
    let values: Vec<u32> = [0, 1, q / 2, q - 1]
        .into_iter()
        .chain((1..=13).map(|index| index * (q / 17)))
        .flat_map(|value| [value as u32, (value >> 32) as u32])
        .collect();
    let count = values.len() / 2;
    for (log_basis, retained) in [(3, None), (5, Some(2))] {
        let params = CrtGlevParameters::with_glwe_params(&glwe, log_basis, retained);
        let basis = params.basis();
        assert_eq!(params.scalar_residue_iter().len(), basis.decompose_length());
        for (level, residues) in params.scalar_residue_iter().enumerate() {
            let weight = 1u64 << (basis.drop_bits() + level as u32 * log_basis);
            assert_eq!(
                residues.as_ref(),
                moduli.map(|modulus| (weight % u64::from(modulus)) as u32)
            );
        }

        let mut adjusted = vec![0; values.len()];
        let mut carries = vec![false; count];
        basis.init_value_carry_slice_to(&values, &mut adjusted, &mut carries);
        let mut signed_digits = vec![0; values.len()];
        let mut unsigned_digits = vec![0; count];
        let mut residues = vec![0; count * moduli.len()];
        for decomposer in basis.decomposer_iter() {
            let mut unsigned_carries = carries.clone();
            decomposer.decompose_slice_to(&adjusted, &mut signed_digits, &mut carries);
            decomposer.unsigned_decompose_slice_to(
                &adjusted,
                &mut unsigned_digits,
                &mut unsigned_carries,
            );
            assert_eq!(carries, unsigned_carries);
            params.base_q().wrapping_decompose_small_values_to(
                &unsigned_digits,
                &mut residues,
                basis.basis_value(),
            );
            // Lifted digits are modulus-major, while full-width digits are value-major.
            for (&modulus, chunk) in moduli.iter().zip(residues.chunks_exact(count)) {
                for (&residue, digit) in chunk.iter().zip(signed_digits.chunks_exact(2)) {
                    let digit = u64::from(digit[0]) | (u64::from(digit[1]) << 32);
                    assert_eq!(u64::from(residue), digit % u64::from(modulus));
                }
            }
        }
    }
}
