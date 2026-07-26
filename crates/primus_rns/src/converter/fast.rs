use itertools::{Either, izip};
use primus_factor::FactorMul;
use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::BaseConverter;

/// One prepared destination-modulus kernel for batched fast conversion.
///
/// General conversion borrows coefficient-major adjusted residues prepared
/// once for the entire input polynomial. Each limb then differs only in its
/// destination modulus and base-change matrix row.
pub(crate) enum FastConversionLimb<'a, T, M> {
    SingleInput {
        input: &'a [T],
        modulus: &'a M,
    },
    General {
        adjusted_residues: &'a [T],
        input_moduli_count: usize,
        base_change_matrix_row: &'a [T],
        modulus: &'a M,
    },
}

impl<T: FheUint, M: FieldContext<T>> FastConversionLimb<'_, T, M> {
    /// Writes this destination-modulus polynomial in coefficient order.
    #[inline]
    pub(crate) fn write_to(self, output: &mut [T]) {
        match self {
            Self::SingleInput { input, modulus } => {
                assert_eq!(output.len(), input.len());
                output
                    .iter_mut()
                    .zip(input)
                    .for_each(|(result, &ai)| *result = modulus.reduce(ai));
            }
            Self::General {
                adjusted_residues,
                input_moduli_count,
                base_change_matrix_row,
                modulus,
            } => {
                debug_assert_eq!(base_change_matrix_row.len(), input_moduli_count);
                let adjusted_residues = adjusted_residues.chunks_exact(input_moduli_count);
                assert_eq!(output.len(), adjusted_residues.len());
                output
                    .iter_mut()
                    .zip(adjusted_residues)
                    .for_each(|(result, adjusted_residues)| {
                        *result =
                            modulus.reduce_dot_product(adjusted_residues, base_change_matrix_row);
                    });
            }
        }
    }
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Returns the minimum scratch length required by
    /// [`fast_convert`](Self::fast_convert).
    #[inline]
    pub fn fast_convert_scratch_len(&self) -> usize {
        if self.uses_single_input_kernel() {
            0
        } else {
            self.input_moduli_count()
        }
    }

    /// Returns the minimum scratch length required by the batched
    /// fast-conversion APIs.
    ///
    /// # Panics
    ///
    /// Panics if the required length overflows `usize`.
    #[inline]
    pub fn fast_convert_array_scratch_len(&self, poly_length: usize) -> usize {
        self.fast_convert_scratch_len()
            .checked_mul(poly_length)
            .expect("fast conversion scratch length overflow")
    }

    /// Converts one residue vector from the input basis to the output basis.
    ///
    /// `residues_in.len()` must equal `input_moduli_count()`. Element `i` is
    /// interpreted modulo `input_base().moduli()[i]`.
    ///
    /// `residues_out.len()` must equal `output_moduli_count()`. Element `j`
    /// receives the converted residue modulo `output_base().moduli()[j]`.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_scratch_len`](Self::fast_convert_scratch_len). The
    /// general conversion kernel overwrites only the required prefix with the
    /// adjusted input residues. A single-modulus input basis ignores scratch.
    pub fn fast_convert(&self, residues_in: &[T], residues_out: &mut [T], scratch: &mut [T]) {
        assert_eq!(residues_in.len(), self.input_moduli_count());
        assert_eq!(residues_out.len(), self.output_moduli_count());

        if self.uses_single_input_kernel() {
            let ai = residues_in[0];
            residues_out
                .iter_mut()
                .zip(self.output_base.moduli())
                .for_each(|(result, modulus)| *result = modulus.reduce(ai));
            return;
        }

        let required_scratch_len = self.fast_convert_scratch_len();
        assert!(scratch.len() >= required_scratch_len);
        let scratch = &mut scratch[..required_scratch_len];

        izip!(
            residues_in,
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli_values(),
            scratch.iter_mut()
        )
        .for_each(|(&ai, &inv_q_div_qi_mod_qi, qi, result)| {
            *result = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi);
        });

        let ai_mul_inv_q_div_qi_mod_qi = &*scratch;

        izip!(
            residues_out,
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(ele, q_div_qi_mod_pj, pj)| {
            *ele = pj.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_pj);
        });
    }

    /// Fills the coefficient-major scratch buffer for batched fast conversion.
    ///
    /// `crt_poly_in.len()` must equal `input_moduli_count() * poly_length` and
    /// uses modulus-major input layout. `scratch.len()` must be the same, but
    /// the written layout is coefficient-major: chunk `j` of length
    /// `input_moduli_count()` stores all adjusted residues for coefficient `j`.
    fn fill_fast_convert_array_scratch(
        &self,
        crt_poly_in: &[T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let input_moduli_count = self.input_moduli_count();
        debug_assert!(!self.uses_single_input_kernel());
        debug_assert_eq!(crt_poly_in.len(), input_moduli_count * poly_length);
        debug_assert_eq!(scratch.len(), input_moduli_count * poly_length);

        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(|(i, (poly_mod_qi, &inv_q_div_qi_mod_qi, &qi))| {
            if inv_q_div_qi_mod_qi.value().is_one() {
                izip!(
                    poly_mod_qi,
                    scratch.iter_mut().skip(i).step_by(input_moduli_count)
                )
                .for_each(|(&ai, ele)| {
                    *ele = ai;
                });
            } else {
                let qi_val = unsafe { qi.value_unchecked() };
                izip!(
                    poly_mod_qi,
                    scratch.iter_mut().skip(i).step_by(input_moduli_count)
                )
                .for_each(|(&ai, ele)| {
                    *ele = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi_val);
                });
            }
        });
    }

    /// Prepares the coefficient-major adjusted residues for the general
    /// batched conversion kernel.
    #[inline]
    fn prepare_general_fast_convert_array<'a>(
        &self,
        crt_poly_in: &[T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> &'a [T] {
        debug_assert!(!self.uses_single_input_kernel());
        let required_scratch_len = self.fast_convert_array_scratch_len(poly_length);
        assert!(scratch.len() >= required_scratch_len);
        let scratch = &mut scratch[..required_scratch_len];
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);
        scratch
    }

    /// Prepares one conversion and returns its destination-modulus kernels.
    ///
    /// Adjusted input residues are computed once. The returned iterator then
    /// yields one independently writable polynomial limb at a time, allowing a
    /// caller to immediately consume that limb before producing the next one.
    #[inline]
    pub(crate) fn fast_convert_array_limbs<'a>(
        &'a self,
        crt_poly_in: &'a [T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl ExactSizeIterator<Item = FastConversionLimb<'a, T, M>> + 'a {
        let input_moduli_count = self.input_moduli_count();
        assert_eq!(
            crt_poly_in.len(),
            input_moduli_count
                .checked_mul(poly_length)
                .expect("RNS input length overflow")
        );

        if self.uses_single_input_kernel() {
            Either::Left(self.output_base.moduli().iter().map(move |modulus| {
                FastConversionLimb::SingleInput {
                    input: crt_poly_in,
                    modulus,
                }
            }))
        } else {
            let adjusted_residues =
                self.prepare_general_fast_convert_array(crt_poly_in, poly_length, scratch);
            Either::Right(
                self.output_base
                    .moduli()
                    .iter()
                    .zip(self.iter_base_change_matrix())
                    .map(
                        move |(modulus, base_change_matrix_row)| FastConversionLimb::General {
                            adjusted_residues,
                            input_moduli_count,
                            base_change_matrix_row,
                            modulus,
                        },
                    ),
            )
        }
    }

    /// Converts a modulus-major array of residue vectors between bases.
    ///
    /// `crt_poly_in.len()` must equal `input_moduli_count() * poly_length` and
    /// uses modulus-major layout: chunk `i` of length `poly_length` stores all
    /// coefficients modulo `input_base().moduli()[i]`.
    ///
    /// `crt_poly_out.len()` must equal `output_moduli_count() * poly_length`
    /// and is written in the same modulus-major layout for the output basis.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_array_scratch_len`](Self::fast_convert_array_scratch_len).
    /// The general conversion kernel overwrites only the required prefix in
    /// coefficient-major layout. A single-modulus input basis ignores scratch.
    pub fn fast_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let expected_out_len = self
            .output_moduli_count()
            .checked_mul(poly_length)
            .expect("RNS output length overflow");

        assert_eq!(crt_poly_out.len(), expected_out_len);
        crt_poly_out
            .chunks_exact_mut(poly_length)
            .zip(self.fast_convert_array_limbs(crt_poly_in, poly_length, scratch))
            .for_each(|(output, limb)| limb.write_to(output));
    }

    /// Converts an array and returns output residues as pairs.
    ///
    /// The output basis must contain exactly two moduli. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// `scratch.len()` must be at least
    /// [`fast_convert_array_scratch_len`](Self::fast_convert_array_scratch_len).
    /// A general conversion overwrites and borrows only the required prefix in
    /// coefficient-major layout. A single-input conversion borrows the input
    /// directly and ignores scratch.
    ///
    /// The iterator yields exactly `poly_length` items, one `(mod p_0, mod p_1)`
    /// pair per coefficient.
    pub fn fast_convert_array_to_pair_iter<'a>(
        &'a self,
        crt_poly_in: &'a [T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl Iterator<Item = (T, T)> + 'a {
        assert_eq!(
            self.output_moduli_count(),
            2,
            "output base in fast_convert_array_to_pair must contain exactly two moduli"
        );

        let input_moduli_count = self.input_moduli_count();
        assert_eq!(
            crt_poly_in.len(),
            input_moduli_count
                .checked_mul(poly_length)
                .expect("RNS input length overflow")
        );
        let p0 = self.output_base.moduli()[0];
        let p1 = self.output_base.moduli()[1];
        if self.uses_single_input_kernel() {
            Either::Left(
                crt_poly_in
                    .iter()
                    .map(move |&ai| (p0.reduce(ai), p1.reduce(ai))),
            )
        } else {
            let scratch =
                self.prepare_general_fast_convert_array(crt_poly_in, poly_length, scratch);
            let mut rows = self.iter_base_change_matrix();
            let q_div_qi_mod_p0 = rows.next().expect("missing first output-base row");
            let q_div_qi_mod_p1 = rows.next().expect("missing second output-base row");

            Either::Right(scratch.chunks_exact(input_moduli_count).map(
                move |ai_mul_inv_q_div_qi_mod_qi| {
                    (
                        p0.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p0),
                        p1.reduce_dot_product(ai_mul_inv_q_div_qi_mod_qi, q_div_qi_mod_p1),
                    )
                },
            ))
        }
    }
}
