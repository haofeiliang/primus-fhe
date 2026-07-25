use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::{AsInto, FheUint};
use primus_modulo::Modulo;
use primus_reduce::FieldContext;

use super::BaseConverter;

/// Reusable scratch space for exact batched RNS base conversion.
///
/// A context is tied to an input modulus count and polynomial length. Reusing
/// it across conversions with the same dimensions avoids allocations in
/// [`BaseConverter::exact_convert_array`].
pub struct ExactConversionContext<T: FheUint> {
    adjusted_residues: Vec<T>,
    correction_terms: Vec<f64>,
    input_moduli_count: usize,
    poly_length: usize,
}

impl<T: FheUint> ExactConversionContext<T> {
    /// Allocates scratch space for the given conversion dimensions.
    ///
    /// # Panics
    ///
    /// Panics if `input_moduli_count * poly_length` overflows `usize`.
    pub fn new(input_moduli_count: usize, poly_length: usize) -> Self {
        let adjusted_residues_len = input_moduli_count
            .checked_mul(poly_length)
            .expect("exact conversion context length overflow");

        Self {
            adjusted_residues: vec![T::ZERO; adjusted_residues_len],
            correction_terms: vec![0.0; poly_length],
            input_moduli_count,
            poly_length,
        }
    }
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Exactly converts an input-basis array to a single-modulus output basis.
    ///
    /// The output basis must contain exactly one modulus. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// Each input residue vector is interpreted through its centered
    /// representative in `[-Q/2, Q/2)`, where `Q` is the input-base product.
    /// `crt_poly_out.len()` must equal `poly_length`; it receives that centered
    /// representative reduced modulo the single output modulus.
    /// `context` must be constructed for `input_moduli_count()` and the same
    /// `poly_length`.
    ///
    /// This uses the floating-point correction term common in centered exact
    /// RNS base conversion. Input coefficients must be canonical residues in
    /// their corresponding input moduli.
    pub fn exact_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
        context: &mut ExactConversionContext<T>,
    ) {
        let input_moduli_count = self.input_moduli_count();
        let expected_input_len = input_moduli_count
            .checked_mul(poly_length)
            .expect("exact conversion input length overflow");
        assert_eq!(crt_poly_in.len(), expected_input_len);
        assert_eq!(crt_poly_out.len(), poly_length);
        assert_eq!(context.input_moduli_count, input_moduli_count);
        assert_eq!(context.poly_length, poly_length);

        assert_eq!(
            self.output_moduli_count(),
            1,
            "output base in exact_convert_array must be one."
        );

        let adjusted_residues = &mut context.adjusted_residues;
        let correction_terms = &mut context.correction_terms;
        correction_terms.fill(0.0);

        // Calculate a_i * (Q / q_i)^-1 mod q_i and accumulate
        // sum_i(adjusted_residue_i / q_i) for each coefficient.
        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(|(i, (poly_mod_qi, &inv_q_div_qi_mod_qi, &qi))| {
            let qi_val = unsafe { qi.value_unchecked() };
            let divisor: f64 = qi_val.as_into();
            if inv_q_div_qi_mod_qi.value().is_one() {
                izip!(
                    poly_mod_qi,
                    adjusted_residues
                        .iter_mut()
                        .skip(i)
                        .step_by(input_moduli_count),
                    correction_terms.iter_mut()
                )
                .for_each(|(&ai, adjusted_residue, correction)| {
                    *adjusted_residue = ai;
                    let adjusted_residue: f64 = ai.as_into();
                    *correction += adjusted_residue / divisor;
                });
            } else {
                izip!(
                    poly_mod_qi,
                    adjusted_residues
                        .iter_mut()
                        .skip(i)
                        .step_by(input_moduli_count),
                    correction_terms.iter_mut()
                )
                .for_each(|(&ai, adjusted_residue, correction)| {
                    *adjusted_residue = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi_val);
                    let adjusted_residue: f64 = (*adjusted_residue).as_into();
                    *correction += adjusted_residue / divisor;
                });
            }
        });

        let p = self.output_base.moduli()[0];
        let q_mod_p = self.input_base.moduli_product().0.modulo(p);
        let q_div_qi_mod_p = self.iter_base_change_matrix().next().unwrap();

        // Final multiplication
        izip!(
            crt_poly_out,
            adjusted_residues.chunks_exact(input_moduli_count),
            correction_terms.iter(),
        )
        .for_each(|(coeff_mod_p, ai_mul_inv_q_div_qi_mod_qi, &correction)| {
            let sum_mod_p = p.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p);
            let rounded_correction: T = (correction + 0.5).as_into();
            let correction_q_mod_p = p.reduce_mul(rounded_correction, q_mod_p);
            *coeff_mod_p = p.reduce_sub(sum_mod_p, correction_q_mod_p);
        });
    }
}
