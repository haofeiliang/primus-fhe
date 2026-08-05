use itertools::izip;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::HybridRNS;

/// Approximately divides an NTT-domain `QP` polynomial by `P`.
///
/// The `Q` limbs remain in the NTT domain throughout the operation. Only the
/// `P` limbs are inverse-transformed for the cross-basis conversion. The
/// converted `P` polynomial is transformed one `Q` limb at a time and reused
/// as the subtraction operand in the NTT domain.
pub(super) fn approx_mod_down_ntt<T, M, Table>(
    hybrid_rns: &HybridRNS<T, M>,
    table: &Table,
    polynomial_mod_qp: &mut [T],
    poly_length: usize,
    converted_p_mod_q: &mut [T],
    scratch: &mut [T],
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: DcrtTable<ValueT = T>,
{
    let q_moduli_count = hybrid_rns.q_moduli_count();
    let q_len = q_moduli_count * poly_length;

    let (q_table, p_table) = table.ntt_tables().split_at(q_moduli_count);
    let (polynomial_mod_q, polynomial_mod_p) = polynomial_mod_qp.split_at_mut(q_len);

    p_table
        .iter()
        .zip(polynomial_mod_p.chunks_exact_mut(poly_length))
        .for_each(|(ntt_table, p_limb)| ntt_table.inverse_transform_slice(p_limb));

    hybrid_rns.approx_convert_p_to_q(polynomial_mod_p, converted_p_mod_q, poly_length, scratch);

    izip!(
        q_table,
        polynomial_mod_q.chunks_exact_mut(poly_length),
        converted_p_mod_q.chunks_exact_mut(poly_length),
        hybrid_rns.q_base().moduli(),
        hybrid_rns.inv_p_mod_q(),
    )
    .for_each(
        |(ntt_table, q_limb, converted_p_q_limb, qi, &inv_p_mod_qi)| {
            ntt_table.transform_slice(converted_p_q_limb);
            qi.reduce_sub_slice_assign(q_limb, converted_p_q_limb);
            qi.reduce_mul_scalar_slice_assign(q_limb, inv_p_mod_qi);
        },
    );
}

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{DcrtTable, NttTable, UintDcrtTable};

    use super::*;

    #[test]
    fn mixed_domain_mod_down_matches_coefficient_reference() {
        const POLY_LENGTH: usize = 4;
        let q_values = [17_u64, 41, 73];
        let p_values = [89_u64, 97];
        let q_moduli = q_values.map(BarrettModulus::new);
        let p_moduli = p_values.map(BarrettModulus::new);
        let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_moduli).copied().collect();
        let hybrid_rns = HybridRNS::new(&q_moduli, &p_moduli, 2).unwrap();
        let table = UintDcrtTable::new(POLY_LENGTH.trailing_zeros(), &qp_moduli).unwrap();

        let coefficient_qp: Vec<_> = q_values
            .iter()
            .chain(&p_values)
            .flat_map(|&modulus| {
                (0..POLY_LENGTH)
                    .map(move |coefficient| (11 * coefficient as u64 + modulus / 3) % modulus)
            })
            .collect();
        let q_len = q_values.len() * POLY_LENGTH;

        let mut reference = coefficient_qp.clone();
        let mut reference_converted = vec![0; q_len];
        let mut reference_scratch = vec![0; hybrid_rns.mod_down_scratch_len(POLY_LENGTH)];
        hybrid_rns.approx_mod_down(
            &mut reference,
            POLY_LENGTH,
            &mut reference_converted,
            &mut reference_scratch,
        );

        let mut mixed_domain = coefficient_qp.clone();
        table.transform_slice(&mut mixed_domain);
        let mut converted = vec![0; q_len];
        let mut scratch = vec![0; hybrid_rns.mod_down_scratch_len(POLY_LENGTH)];
        approx_mod_down_ntt(
            &hybrid_rns,
            &table,
            &mut mixed_domain,
            POLY_LENGTH,
            &mut converted,
            &mut scratch,
        );

        table.ntt_tables()[..q_values.len()]
            .iter()
            .zip(mixed_domain[..q_len].chunks_exact_mut(POLY_LENGTH))
            .for_each(|(ntt_table, q_limb)| ntt_table.inverse_transform_slice(q_limb));

        assert_eq!(&mixed_domain[..q_len], &reference[..q_len]);
        assert_eq!(&mixed_domain[q_len..], &coefficient_qp[q_len..]);
    }
}
