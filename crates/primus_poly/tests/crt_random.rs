use primus_distr::SignedDiscreteGaussian;
use primus_modulus::CompactModulus;
use primus_poly::CrtPolynomial;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn add_gaussian_uses_one_sample_for_all_crt_residues() {
    const POLY_LENGTH: usize = 16;
    const MODULI_VALUES: [u64; 3] = [97, 113, 193];

    let moduli = MODULI_VALUES.map(CompactModulus::new);
    let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
    let initial = (0..POLY_LENGTH * MODULI_VALUES.len())
        .map(|index| (index as u64 * 7 + 3) % MODULI_VALUES[index / POLY_LENGTH])
        .collect::<Vec<_>>();

    let mut expected = CrtPolynomial::new(initial.clone());
    let mut noise = CrtPolynomial::<Vec<u64>>::zero(POLY_LENGTH * MODULI_VALUES.len());
    let mut expected_rng = StdRng::seed_from_u64(0x4352_542d_4741_5553);
    noise.random_gaussian_assign(POLY_LENGTH, &MODULI_VALUES, &gaussian, &mut expected_rng);
    expected.add_assign(&noise, POLY_LENGTH, &moduli);

    let mut actual = CrtPolynomial::new(initial);
    let mut actual_rng = StdRng::seed_from_u64(0x4352_542d_4741_5553);
    actual.add_random_gaussian_assign(POLY_LENGTH, &gaussian, &moduli, &mut actual_rng);

    assert_eq!(actual, expected);
}
