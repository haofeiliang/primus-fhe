use core::range::Range;

use primus_modulus::BarrettModulus;
use primus_rns::{HybridRNS, HybridRNSPartitioning, RNSError};

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
fn construction_uses_fixed_partitioning_and_precomputes_p() {
    let q_moduli = [17, 41, 73, 89, 97].map(ModulusT::new);
    let p_moduli = [101, 103].map(ModulusT::new);
    let hybrid = HybridRNS::new(&q_moduli, &p_moduli, 3).unwrap();
    let ranges: Vec<_> = hybrid
        .partitions()
        .map(|partition| partition.q_range())
        .collect();

    assert_eq!(hybrid.decomposition_count(), 3);
    assert_eq!(hybrid.partition_moduli_count(), 2);
    assert_eq!(hybrid.partitioning().full_q_moduli_count(), 5);
    assert_eq!(
        ranges,
        [Range::from(0..2), Range::from(2..4), Range::from(4..5)],
    );

    let partitioning = hybrid.partitioning();
    let active = HybridRNS::from_partitioning(&q_moduli[..3], &p_moduli, partitioning).unwrap();
    let active_ranges: Vec<_> = active
        .partitions()
        .map(|partition| partition.q_range())
        .collect();
    assert_eq!(active.partitioning(), partitioning);
    assert_eq!(active_ranges, [Range::from(0..2), Range::from(2..3)]);

    assert!(matches!(
        HybridRNSPartitioning::new(5, 4),
        Err(RNSError::IncompatibleDecompositionCount {
            q_moduli_count: 5,
            decomposition_count: 4,
        }),
    ));
    assert!(matches!(
        HybridRNS::from_partitioning(
            &q_moduli,
            &p_moduli,
            HybridRNSPartitioning::new(4, 2).unwrap(),
        ),
        Err(RNSError::ActiveBaseTooLarge {
            actual: 5,
            maximum: 4,
        }),
    ));
    assert_eq!(hybrid.p_mod_q(), [16, 30, 37, 79, 24]);
    assert_eq!(hybrid.inv_p_mod_q(), [16, 26, 2, 80, 93]);
}

#[test]
fn mod_up_full_and_streaming_outputs_match() {
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

    for (partition, expected) in hybrid.partitions().zip(&expected_digits) {
        let q_range = partition.q_range();
        let partition_elements =
            Range::from(q_range.start * poly_length..q_range.end * poly_length);

        let mut digit_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
        let mut scratch = vec![0; partition.mod_up_scratch_len(poly_length)];
        partition.approx_mod_up_to(&polynomial_q, &mut digit_qp, poly_length, &mut scratch);
        assert_eq!(digit_qp, expected);

        let mut streamed = vec![0; hybrid.qp_moduli_count() * poly_length];
        streamed[partition_elements].copy_from_slice(&polynomial_q[partition_elements]);
        let mut output_limb = vec![0; poly_length];
        partition.for_each_approx_mod_up_complement_limb(
            &polynomial_q,
            &mut output_limb,
            poly_length,
            &mut scratch,
            |modulus_index, converted_limb| {
                let limb_start = modulus_index * poly_length;
                streamed[limb_start..limb_start + poly_length].copy_from_slice(converted_limb);
            },
        );
        assert_eq!(streamed, expected);
    }
}

#[test]
fn mod_down_matches_expected_output_with_multiple_p_moduli() {
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
    let q_len = hybrid.q_moduli_count() * poly_length;
    let expected_q = [
        0, 0, 0, 16, 0, // q_0
        38, 38, 38, 37, 38, // q_1
        48, 48, 48, 47, 48, // q_2
    ];
    let mut converted_p = vec![0; hybrid.q_moduli_count() * poly_length];
    let mut scratch = vec![0; hybrid.mod_down_scratch_len(poly_length)];
    hybrid.approx_mod_down_q_assign(
        &mut polynomial_qp,
        poly_length,
        &mut converted_p,
        &mut scratch,
    );

    assert_eq!(&polynomial_qp[..q_len], expected_q);
    assert_eq!(&polynomial_qp[q_len..], &original[q_len..]);
}
