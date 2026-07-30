use core::range::Range;

use primus_modulus::BarrettModulus;
use primus_reduce::TryReduceInv;
use primus_rns::{HybridRNS, RNSError};

type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;

fn make_hybrid(
    q: &[ValueT],
    p: &[ValueT],
    decomposition_count: usize,
) -> HybridRNS<ValueT, ModulusT> {
    let q_moduli: Vec<_> = q.iter().copied().map(ModulusT::new).collect();
    let p_moduli: Vec<_> = p.iter().copied().map(ModulusT::new).collect();
    HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap()
}

#[test]
fn construction_partitions_q_and_precomputes_p() {
    let q = [17, 41, 73, 89, 97];
    let p = [101, 103];
    let hybrid = make_hybrid(&q, &p, 4);
    let ranges: Vec<_> = hybrid
        .partitions()
        .map(|partition| partition.q_range())
        .collect();

    assert_eq!(hybrid.q_moduli_count(), 5);
    assert_eq!(hybrid.p_moduli_count(), 2);
    assert_eq!(hybrid.qp_moduli_count(), 7);
    assert_eq!(hybrid.decomposition_count(), 4);
    assert_eq!(hybrid.partition_moduli_count(), 2);
    assert_eq!(hybrid.partition_count(), 3);
    assert_eq!(
        ranges,
        [Range::from(0..2), Range::from(2..4), Range::from(4..5)],
    );

    assert!(matches!(
        HybridRNS::new(&[ModulusT::new(17)], &[ModulusT::new(41)], 0),
        Err(RNSError::InvalidDecompositionCount),
    ));
    let p_product = p.into_iter().product::<u64>();

    for ((&qi, &p_mod_qi), &inv_p_mod_qi) in
        q.iter().zip(hybrid.p_mod_q()).zip(hybrid.inv_p_mod_q())
    {
        let modulus = ModulusT::new(qi);
        let expected = p_product % qi;
        assert_eq!(p_mod_qi, expected);
        assert_eq!(inv_p_mod_qi, modulus.try_reduce_inv(expected).unwrap());
    }
}

#[test]
fn approximate_mod_up_writes_a_complete_qp_digit() {
    let hybrid = make_hybrid(&[17, 41, 73], &[89, 97], 2);
    let poly_length = 4;
    let polynomial_q = [
        1, 2, 3, 4, // q_0
        11, 12, 13, 14, // q_1
        21, 22, 23, 24, // q_2
    ];
    let expected_digits: [[ValueT; 20]; 2] = [
        [
            1, 2, 3, 4, // q_0: copied
            11, 12, 13, 14, // q_1: copied
            19, 20, 21, 22, // q_2: converted
            37, 38, 39, 40, // p_0: converted
            70, 71, 72, 73, // p_1: converted
        ],
        [
            4, 5, 6, 7, // q_0: converted
            21, 22, 23, 24, // q_1: converted
            21, 22, 23, 24, // q_2: copied
            21, 22, 23, 24, // p_0: converted
            21, 22, 23, 24, // p_1: converted
        ],
    ];

    for (partition, expected_digit) in hybrid.partitions().zip(&expected_digits) {
        let mut digit_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
        let mut scratch = vec![0; partition.mod_up_scratch_len(poly_length)];
        partition.approx_mod_up(&polynomial_q, &mut digit_qp, poly_length, &mut scratch);
        assert_eq!(digit_qp, expected_digit);
    }
}

#[test]
fn polynomial_mod_down_matches_scalar_conversion_with_multiple_p_moduli() {
    let hybrid = make_hybrid(&[17, 41, 73], &[89, 97], 2);
    let poly_length = 5;
    let mut polynomial_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
    let qp_moduli = [17, 41, 73, 89, 97];

    for (modulus_index, (limb, &modulus)) in polynomial_qp
        .chunks_exact_mut(poly_length)
        .zip(&qp_moduli)
        .enumerate()
    {
        for (coefficient, value) in limb.iter_mut().enumerate() {
            *value = (7 * modulus_index + 11 * coefficient + 3) as u64 % modulus;
        }
    }

    let original = polynomial_qp.clone();
    let mut converted_p = vec![0; hybrid.q_moduli_count() * poly_length];
    let mut scratch = vec![0; hybrid.mod_down_scratch_len(poly_length)];
    hybrid.approx_mod_down(
        &mut polynomial_qp,
        poly_length,
        &mut converted_p,
        &mut scratch,
    );

    for coefficient in 0..poly_length {
        let residues_qp: Vec<_> = original
            .chunks_exact(poly_length)
            .map(|limb| limb[coefficient])
            .collect();
        let mut output_q = vec![0; hybrid.q_moduli_count()];
        let mut scalar_scratch = vec![0; hybrid.mod_down_scalar_scratch_len()];
        hybrid.approx_mod_down_scalar(&residues_qp, &mut output_q, &mut scalar_scratch);

        assert!(
            polynomial_qp[..hybrid.q_moduli_count() * poly_length]
                .chunks_exact(poly_length)
                .map(|limb| limb[coefficient])
                .eq(output_q),
        );
    }
}
