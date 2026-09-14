use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::CoeffAutomorphismPermutation;

#[test]
fn coefficient_permutation_matches_monomial_substitution() {
    const Q: u32 = 257;
    let modulus = BarrettModulus::new(Q);
    for n in [2, 16, 128] {
        let input: Vec<i32> = (0..n).map(|i| i as i32 - n as i32 / 2).collect();
        let residues: Vec<u32> = input
            .iter()
            .map(|&x| x.rem_euclid(Q as i32) as u32)
            .collect();
        for degree in (1..2 * n).step_by(2) {
            let permutation = CoeffAutomorphismPermutation::new(degree, n);
            assert_eq!(permutation.poly_length(), n);
            let mut expected = vec![0i32; n];
            // Independent scatter oracle in the coefficient ring.
            for (i, &value) in input.iter().enumerate() {
                let power = i * degree;
                expected[power % n] = if power / n % 2 == 0 { value } else { -value };
            }
            let mut signed = vec![i32::MAX; n];
            permutation.apply_signed_to::<u32>(&input, &mut signed);
            assert_eq!(signed, expected);
            let mut output = vec![u32::MAX; n];
            permutation.apply_to(&residues, &mut output, modulus);
            for (actual, expected) in output.into_iter().zip(expected) {
                assert_eq!(actual, expected.rem_euclid(Q as i32) as u32);
            }
        }
    }
    // Full-width bit patterns use modular negation, not signed-key negation.
    let permutation = CoeffAutomorphismPermutation::new(3, 2);
    let mut output = [0; 2];
    permutation.apply_to(&[0u32, i32::MIN as u32], &mut output, NativeModulus::new());
    assert_eq!(output, [0, i32::MIN as u32]);

    for (degree, n) in [
        (1, 0),
        (1, 1),
        (1, 3),
        (0, 16),
        (2, 16),
        (33, 16),
        (1, 1usize << (usize::BITS - 1)),
    ] {
        assert!(std::panic::catch_unwind(|| CoeffAutomorphismPermutation::new(degree, n)).is_err());
    }
}
