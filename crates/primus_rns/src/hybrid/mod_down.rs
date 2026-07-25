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
    /// `converted_p` must hold `q_moduli_count() * poly_length` elements and
    /// `scratch` must hold `p_moduli_count() * poly_length` elements. The `P`
    /// limbs of `polynomial_qp` are left unchanged.
    pub fn approx_mod_down(
        &self,
        polynomial_qp: &mut [T],
        poly_length: usize,
        converted_p: &mut [T],
        scratch: &mut [T],
    ) {
        let q_len = self.q_moduli_count() * poly_length;
        let p_len = self.p_moduli_count() * poly_length;
        assert_eq!(polynomial_qp.len(), q_len + p_len);
        assert_eq!(converted_p.len(), q_len);
        assert_eq!(scratch.len(), p_len);

        let (polynomial_q, polynomial_p) = polynomial_qp.split_at_mut(q_len);
        self.mod_down_converter
            .fast_convert_array(polynomial_p, converted_p, poly_length, scratch);

        izip!(
            polynomial_q.chunks_exact_mut(poly_length),
            converted_p.chunks_exact(poly_length),
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(q_limb, converted_p_limb, modulus, &inv_p)| {
            q_limb
                .iter_mut()
                .zip(converted_p_limb)
                .for_each(|(value, &p_value)| {
                    *value = modulus.reduce_mul(modulus.reduce_sub(*value, p_value), inv_p);
                });
        });
    }

    /// Approximately divides one `QP` residue vector by `P`.
    ///
    /// `scratch` must contain `p_moduli_count()` elements.
    pub fn approx_mod_down_scalar(
        &self,
        residues_qp: &[T],
        residues_q: &mut [T],
        scratch: &mut [T],
    ) {
        let (q_residues, p_residues) = residues_qp.split_at(self.q_moduli_count());
        assert_eq!(p_residues.len(), self.p_moduli_count());
        assert_eq!(residues_q.len(), self.q_moduli_count());
        assert_eq!(scratch.len(), self.p_moduli_count());

        self.mod_down_converter
            .fast_convert(p_residues, residues_q, scratch);
        izip!(
            residues_q,
            q_residues,
            self.q_base.moduli(),
            &self.inv_p_mod_q,
        )
        .for_each(|(result, &value, modulus, &inv_p)| {
            *result = modulus.reduce_mul(modulus.reduce_sub(value, *result), inv_p);
        });
    }
}
