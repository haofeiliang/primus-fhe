//! Unit tests for the hybrid RNS gadget infrastructure.

use primus_modulo::prelude::*;
use primus_modulus::BarrettModulus;
use primus_reduce::Modulus;
use primus_rns::HybridRNS;

type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;

fn make_hybrid(q: &[ValueT], p: &[ValueT], num_parts: usize) -> HybridRNS<ValueT, ModulusT> {
    let q_moduli: Vec<_> = q.iter().copied().map(ModulusT::new).collect();
    let p_moduli: Vec<_> = p.iter().copied().map(ModulusT::new).collect();
    HybridRNS::new(&q_moduli, &p_moduli, num_parts).unwrap()
}

#[test]
fn hybrid_construction() {
    let q = [1125899906826241u64, 1125899906629633];
    let p = [1125899906031617u64];
    let h = make_hybrid(&q, &p, 2);

    assert_eq!(h.q_moduli_count(), 2);
    assert_eq!(h.p_moduli_count(), 1);
    assert_eq!(h.qp_moduli_count(), 3);
    assert_eq!(h.num_parts(), 2);

    let rows: Vec<_> = h.iter_gadget_scalar_residues().collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 3);
    // Partition 0: q_0 has P, q_1=0, p_0=0
    assert_ne!(rows[0][0], 0);
    assert_eq!(rows[0][1], 0);
    assert_eq!(rows[0][2], 0);
    // Partition 1: q_0=0, q_1 has P, p_0=0
    assert_eq!(rows[1][0], 0);
    assert_ne!(rows[1][1], 0);
    assert_eq!(rows[1][2], 0);
}

#[test]
fn p_mod_and_inv() {
    let q = [1125899906826241u64, 1125899906629633];
    let p = [1125899906031617u64];
    let h = make_hybrid(&q, &p, 1);

    let p_val = p[0];
    for (i, &qi) in q.iter().enumerate() {
        assert_eq!(h.p_mod_q()[i], p_val % qi);
        let qi_mod = ModulusT::new(qi);
        let expected_inv = (p_val % qi).try_inv_modulo(qi_mod).unwrap();
        assert_eq!(h.p_inv_mod_q()[i], expected_inv);
    }
}

/// Test the scalar hybrid gadget identity:
/// ModDown( Σ_j ModUp_j(x) * λ_j ) = x mod Q
/// (using NON-centered r in ModDown, matching OpenFHE)
#[test]
fn scalar_hybrid_gadget_identity() {
    let q = [1125899906826241u64, 1125899906629633];
    let p = [1125899906031617u64];
    let h = make_hybrid(&q, &p, 2);

    let q_count = h.q_moduli_count();
    let p_count = h.p_moduli_count();
    let qp_count = h.qp_moduli_count();

    let test_values = [0u64, 1, 12345, q[0] - 1];

    for &x in &test_values {
        let x_q = [x % q[0], x % q[1]];

        // Σ_j ModUp_j(x) * λ_j
        let mut sum_qp = vec![0u64; qp_count];

        for (j, part) in h.partitions().iter().enumerate() {
            let part_size = part.q_indices.len();
            let mut part_res = vec![0u64; part_size];
            for (local, global) in part.q_indices.clone().enumerate() {
                part_res[local] = x_q[global];
            }

            let converter = &h.mod_up_converters()[j];
            let compl_count = converter.output_moduli_count();
            let mut compl_res = vec![0u64; compl_count];
            {
                let mut sc = vec![0u64; part_size];
                h.mod_up_scalar(j, &part_res, &mut compl_res, &mut sc);
            }

            // Assemble QP digit
            let mut digit_qp = vec![0u64; qp_count];
            for (local, global) in part.q_indices.clone().enumerate() {
                digit_qp[global] = part_res[local];
            }
            for (out_idx, &value) in compl_res.iter().enumerate() {
                let qp_pos = if out_idx < part.q_indices.start {
                    out_idx
                } else if out_idx < q_count - part_size {
                    out_idx + part_size
                } else {
                    q_count + (out_idx - (q_count - part_size))
                };
                digit_qp[qp_pos] = value;
            }

            let gadget = h.iter_gadget_scalar_residues().nth(j).unwrap();
            for qi in 0..qp_count {
                let m = unsafe { h.qp_base().moduli()[qi].value_unchecked() };
                let prod = ((digit_qp[qi] as u128) * (gadget[qi] as u128) % (m as u128)) as u64;
                sum_qp[qi] = ((sum_qp[qi] as u128 + prod as u128) % (m as u128)) as u64;
            }
        }

        // ModDown: QP → Q (matching OpenFHE: NO centering)
        let p_res = &sum_qp[q_count..];
        let mut r_p = vec![0u64; p_count];
        r_p.copy_from_slice(p_res);

        let mut r_q = vec![0u64; q_count];
        {
            let mut sc = vec![0u64; p_count];
            h.mod_down_converter().fast_convert(&r_p, &mut r_q, &mut sc);
        }

        let p_inv = h.p_inv_mod_q();
        let q_moduli = h.q_base().moduli();
        for qi in 0..q_count {
            let z = sum_qp[qi];
            let r = r_q[qi];
            let m = unsafe { q_moduli[qi].value_unchecked() };
            let diff = if z >= r { z - r } else { m - r + z };
            // Use u128 to avoid overflow (values are up to ~2^100)
            let result = ((diff as u128) * (p_inv[qi] as u128) % (m as u128)) as u64;

            assert_eq!(
                result, x_q[qi],
                "x={}: ModDown mismatch at q[{}]: expected {} got {}",
                x, qi, x_q[qi], result
            );
        }
    }
}

#[test]
fn polynomial_mod_up_uses_modulus_major_layout() {
    let q = [1125899906826241u64, 1125899906629633];
    let p = [1125899906031617u64];
    let h = make_hybrid(&q, &p, 2);
    let poly_length = 4;

    let input = [
        1, 2, 3, 4, // q_0
        11, 12, 13, 14, // q_1
    ];

    for (part_idx, part) in h.partitions().iter().enumerate() {
        let converter = &h.mod_up_converters()[part_idx];
        let output_count = converter.output_moduli_count();
        let mut polynomial_output = vec![0; output_count * poly_length];
        let mut polynomial_scratch = vec![0; part.q_indices.len()];
        h.mod_up_polynomial_coeff(
            part_idx,
            &input,
            &mut polynomial_output,
            poly_length,
            &mut polynomial_scratch,
        );

        for coefficient in 0..poly_length {
            let scalar_input: Vec<_> = part
                .q_indices
                .clone()
                .map(|q_idx| input[q_idx * poly_length + coefficient])
                .collect();
            let mut scalar_output = vec![0; output_count];
            let mut scalar_scratch = vec![0; part.q_indices.len()];
            h.mod_up_scalar(
                part_idx,
                &scalar_input,
                &mut scalar_output,
                &mut scalar_scratch,
            );

            for output_modulus in 0..output_count {
                assert_eq!(
                    polynomial_output[output_modulus * poly_length + coefficient],
                    scalar_output[output_modulus],
                );
            }
        }
    }
}
