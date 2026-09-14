use primus_modulus::BarrettModulus;
use primus_ntt::{NttAutomorphismPermutation, NttTable, UintNttTable};
use primus_poly::CoeffAutomorphismPermutation;

#[test]
fn ntt_permutation_matches_coefficient_automorphism() {
    const Q: u32 = 257;
    let modulus = BarrettModulus::new(Q);
    for log_n in [1, 4, 7] {
        let n = 1 << log_n;
        let ntt = UintNttTable::new(log_n, modulus).unwrap();
        let input: Vec<u32> = (0..n).map(|index| (19 * index as u32 + 5) % Q).collect();
        let mut input_ntt = input.clone();
        ntt.transform_slice(&mut input_ntt);
        for degree in (1..2 * n).step_by(2) {
            let coefficient = CoeffAutomorphismPermutation::new(degree, n);
            let permutation = NttAutomorphismPermutation::new(degree, n);
            assert_eq!(permutation.poly_length(), n);
            let mut expected = vec![0; n];
            coefficient.apply_to(&input, &mut expected, modulus);
            ntt.transform_slice(&mut expected);
            let mut actual = vec![0; n];
            permutation.apply_to(&input_ntt, &mut actual);
            assert_eq!(actual, expected, "n={n}, degree={degree}");
        }
    }
    for (degree, n) in [
        (1, 0),
        (1, 1),
        (1, 3),
        (0, 16),
        (2, 16),
        (33, 16),
        (1, 1usize << (usize::BITS - 1)),
    ] {
        assert!(std::panic::catch_unwind(|| NttAutomorphismPermutation::new(degree, n)).is_err());
    }
}
