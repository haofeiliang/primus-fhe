use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::{AsInto, FheUint};
use primus_modulo::Modulo;
use primus_reduce::FieldContext;

use super::BaseConverter;

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Exactly converts an input-basis array to a single-modulus output basis.
    ///
    /// The output basis must contain exactly one modulus. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// `crt_poly_out.len()` must equal `poly_length`; it receives one residue
    /// modulo the single output modulus for each coefficient.
    ///
    /// This uses the floating-point correction term common in exact RNS base
    /// conversion.
    pub fn exact_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
    ) {
        let input_moduli_count = self.input_moduli_count();
        debug_assert_eq!(crt_poly_in.len(), input_moduli_count * poly_length);
        debug_assert_eq!(crt_poly_out.len(), poly_length);

        assert_eq!(
            self.output_moduli_count(),
            1,
            "output base in exact_convert_array must be one."
        );

        let mut temp: Vec<T> = vec![T::ZERO; input_moduli_count * poly_length];
        let mut v: Vec<f64> = vec![0.0f64; input_moduli_count * poly_length];
        let mut aggregated_rounded_v: Vec<T> = vec![T::ZERO; poly_length];

        // Calculate [x_{i} * \hat{q_{i}}]_{q_{i}}
        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(
            |(i, (poly, &inv_punctured_product_mod_modulus, &modulus))| {
                let divisor: f64 = unsafe { modulus.value_unchecked().as_into() };
                if inv_punctured_product_mod_modulus.value().is_one() {
                    // No multiplication needed
                    izip!(
                        poly,
                        temp.iter_mut().skip(i).step_by(input_moduli_count),
                        v.iter_mut().skip(i).step_by(input_moduli_count)
                    )
                    .for_each(|(&x, ele, fele)| {
                        // Reduce modulo input_base element
                        *ele = x.modulo(modulus);
                        let dividend: f64 = (*ele).as_into();
                        *fele = dividend / divisor;
                    });
                } else {
                    // Multiplication needed
                    izip!(
                        poly,
                        temp.iter_mut().skip(i).step_by(input_moduli_count),
                        v.iter_mut().skip(i).step_by(input_moduli_count)
                    )
                    .for_each(|(&x, ele, fele)| {
                        // Multiply coefficient of in with input-base inverse punctured-product element

                        *ele = inv_punctured_product_mod_modulus
                            .factor_mul_modulo(x, unsafe { modulus.value_unchecked() });
                        let dividend: f64 = (*ele).as_into();
                        *fele = dividend / divisor;
                    });
                }
            },
        );

        // Aggregate v and round to the nearest integer.
        izip!(
            v.chunks_exact(input_moduli_count),
            aggregated_rounded_v.iter_mut()
        )
        .for_each(|(vi, ri)| {
            // Otherwise a memory space of the last execution will be used.
            let aggregated_v: f64 = vi.iter().sum();
            *ri = (aggregated_v + 0.5).as_into();
        });

        let p = self.output_base.moduli()[0];
        let q_mod_p = self.input_base.moduli_product().0.modulo(p);
        let base_change_matrix_first = self.iter_base_change_matrix().next().unwrap();

        // Final multiplication
        izip!(
            crt_poly_out,
            temp.chunks_exact(input_moduli_count),
            aggregated_rounded_v,
        )
        .for_each(|(coeff, b, v)| {
            // Compute the base conversion sum modulo output_base element
            let sum_mod_output_base = p.reduce_dot_product(b, base_change_matrix_first);
            // Minus v*[q]_{p} mod p
            let v_q_mod_p = p.reduce_mul(v, q_mod_p);
            *coeff = p.reduce_sub(sum_mod_output_base, v_q_mod_p);
        });
    }
}
