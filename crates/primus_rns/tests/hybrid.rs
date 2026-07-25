//! Tests for hybrid RNS gadget decomposition.

use primus_modulo::prelude::*;
use primus_modulus::BarrettModulus;
use primus_rns::HybridRNS;

type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;

fn make_hybrid(q: &[ValueT], p: &[ValueT], partitions: usize) -> HybridRNS<ValueT, ModulusT> {
    let q_moduli: Vec<_> = q.iter().copied().map(ModulusT::new).collect();
    let p_moduli: Vec<_> = p.iter().copied().map(ModulusT::new).collect();
    HybridRNS::new(&q_moduli, &p_moduli, partitions).unwrap()
}

#[test]
fn construction_uses_only_non_empty_partitions() {
    let hybrid = make_hybrid(&[17, 41, 73, 89, 97], &[113], 4);
    let ranges: Vec<_> = hybrid
        .partitions()
        .map(|partition| partition.q_range())
        .collect();

    assert_eq!(hybrid.q_moduli_count(), 5);
    assert_eq!(hybrid.p_moduli_count(), 1);
    assert_eq!(hybrid.qp_moduli_count(), 6);
    assert_eq!(hybrid.partition_count(), 3);
    assert_eq!(hybrid.max_partition_moduli_count(), 2);
    assert_eq!(ranges, [0..2, 2..4, 4..5]);
}

#[test]
fn construction_rejects_zero_partitions() {
    let q_moduli = [ModulusT::new(17)];
    let p_moduli = [ModulusT::new(41)];

    assert!(matches!(
        HybridRNS::new(&q_moduli, &p_moduli, 0),
        Err(primus_rns::RNSError::InvalidPartitionCount),
    ));
}

#[test]
fn p_mod_q_and_inverse_are_precomputed_in_basis_order() {
    let q = [17, 41, 73];
    let p = [89, 97];
    let hybrid = make_hybrid(&q, &p, 2);
    let p_product = p.into_iter().product::<u64>();

    for ((&qi, &p_mod_qi), &inv_p_mod_qi) in
        q.iter().zip(hybrid.p_mod_q()).zip(hybrid.inv_p_mod_q())
    {
        let modulus = ModulusT::new(qi);
        let expected = p_product % qi;
        assert_eq!(p_mod_qi, expected);
        assert_eq!(inv_p_mod_qi, expected.try_inv_modulo(modulus).unwrap());
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

    for partition in hybrid.partitions() {
        let range = partition.q_range();
        let mut digit_qp = vec![0; hybrid.qp_moduli_count() * poly_length];
        let mut scratch = vec![0; partition.moduli_count() * poly_length];
        partition.approx_mod_up(&polynomial_q, &mut digit_qp, poly_length, &mut scratch);

        assert_eq!(
            &digit_qp[range.start * poly_length..range.end * poly_length],
            &polynomial_q[range.start * poly_length..range.end * poly_length],
        );

        for coefficient in 0..poly_length {
            let scalar_input: Vec<_> = range
                .clone()
                .map(|q_index| polynomial_q[q_index * poly_length + coefficient])
                .collect();
            let mut scalar_output = vec![0; partition.mod_up_converter().output_moduli_count()];
            let mut scalar_scratch = vec![0; partition.moduli_count()];
            partition.mod_up_converter().fast_convert(
                &scalar_input,
                &mut scalar_output,
                &mut scalar_scratch,
            );

            let scattered_output = digit_qp
                .chunks_exact(poly_length)
                .enumerate()
                .filter(|(index, _)| !range.contains(index))
                .map(|(_, limb)| limb[coefficient]);
            assert!(scattered_output.eq(scalar_output));
        }
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
    let mut scratch = vec![0; hybrid.p_moduli_count() * poly_length];
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
        let mut residues_q = vec![0; hybrid.q_moduli_count()];
        let mut scalar_scratch = vec![0; hybrid.p_moduli_count()];
        hybrid.approx_mod_down_scalar(&residues_qp, &mut residues_q, &mut scalar_scratch);

        assert!(
            polynomial_qp[..hybrid.q_moduli_count() * poly_length]
                .chunks_exact(poly_length)
                .map(|limb| limb[coefficient])
                .eq(residues_q),
        );
    }
}
