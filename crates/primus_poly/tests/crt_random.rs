use primus_distr::SignedDiscreteGaussian;
use primus_modulus::CompactModulus;
use primus_poly::CrtPolynomial;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn add_gaussian_uses_one_sample_for_all_crt_residues() {
    const POLY_LENGTH: usize = 16;
    const MODULI_VALUES: [u64; 3] = [97, 113, 193];

    let moduli = MODULI_VALUES.map(CompactModulus::new);
    let gaussian = SignedDiscreteGaussian::<i64>::new(3.2).unwrap();
    let initial = (0..POLY_LENGTH * MODULI_VALUES.len())
        .map(|index| (index as u64 * 7 + 3) % MODULI_VALUES[index / POLY_LENGTH])
        .collect::<Vec<_>>();

    // Draw N signed samples independently of CRT packing, then reduce the
    // same sample under each modulus. Sampling N * limb_count times is wrong.
    let mut expected_rng = StdRng::seed_from_u64(0x4352_542d_4741_5553);
    let noise = gaussian.sample_vec(POLY_LENGTH, &mut expected_rng);
    let expected: Vec<_> = initial
        .as_chunks::<POLY_LENGTH>()
        .0
        .iter()
        .zip(MODULI_VALUES)
        .flat_map(|(limb, q)| {
            limb.iter().zip(&noise).map(move |(&value, &noise)| {
                (value as i128 + noise as i128).rem_euclid(q as i128) as u64
            })
        })
        .collect();

    let mut actual = CrtPolynomial::new(initial);
    let mut actual_rng = StdRng::seed_from_u64(0x4352_542d_4741_5553);
    actual.add_random_gaussian_assign(POLY_LENGTH, &gaussian, &moduli, &mut actual_rng);

    assert_eq!(actual.as_slice(), expected);
    assert_eq!(actual_rng.next_u64(), expected_rng.next_u64());
}
