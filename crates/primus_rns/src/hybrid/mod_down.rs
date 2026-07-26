use itertools::izip;
use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::HybridRNS;

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Approximately divides a coefficient-domain `QP` polynomial by `P` and
    /// leaves the result in its `Q` limbs.
    ///
    /// `polynomial_mod_qp` is overwritten in its `Q` limbs, while its `P` limbs
    /// are left unchanged. `converted_p_mod_q` must hold
    /// `q_moduli_count() * poly_length` elements. `scratch.len()` must be at
    /// least [`mod_down_scratch_len`](Self::mod_down_scratch_len). A
    /// single-prime `P` ignores scratch.
    pub fn approx_mod_down(
        &self,
        polynomial_mod_qp: &mut [T],
        poly_length: usize,
        converted_p_mod_q: &mut [T],
        scratch: &mut [T],
    ) {
        let q_len = self.q_moduli_count() * poly_length;
        let p_len = self.p_moduli_count() * poly_length;
        assert_eq!(polynomial_mod_qp.len(), q_len + p_len);
        assert_eq!(converted_p_mod_q.len(), q_len);

        let (polynomial_mod_q, input_mod_p) = polynomial_mod_qp.split_at_mut(q_len);
        self.mod_down_converter.fast_convert_array(
            input_mod_p,
            converted_p_mod_q,
            poly_length,
            scratch,
        );

        izip!(
            polynomial_mod_q.chunks_exact_mut(poly_length),
            converted_p_mod_q.chunks_exact(poly_length),
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(q_limb, converted_p_q_limb, qi, &inv_p_mod_qi)| {
            q_limb.iter_mut().zip(converted_p_q_limb).for_each(
                |(output_mod_qi, &converted_p_qi)| {
                    let input_mod_qi = *output_mod_qi;
                    *output_mod_qi =
                        qi.reduce_mul(qi.reduce_sub(input_mod_qi, converted_p_qi), inv_p_mod_qi);
                },
            );
        });
    }

    /// Approximately divides one `QP` residue vector by `P`.
    ///
    /// `scratch.len()` must be at least
    /// [`mod_down_scalar_scratch_len`](Self::mod_down_scalar_scratch_len).
    pub fn approx_mod_down_scalar(
        &self,
        input_mod_qp: &[T],
        output_mod_q: &mut [T],
        scratch: &mut [T],
    ) {
        let (input_mod_q, input_mod_p) = input_mod_qp.split_at(self.q_moduli_count());
        assert_eq!(input_mod_p.len(), self.p_moduli_count());

        self.mod_down_converter
            .fast_convert(input_mod_p, output_mod_q, scratch);
        izip!(
            output_mod_q,
            input_mod_q,
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(output_mod_qi, &input_mod_qi, qi, &inv_p_mod_qi)| {
            let converted_p_qi = *output_mod_qi;
            *output_mod_qi =
                qi.reduce_mul(qi.reduce_sub(input_mod_qi, converted_p_qi), inv_p_mod_qi);
        });
    }
}
