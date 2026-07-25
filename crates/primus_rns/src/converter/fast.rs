use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::FheUint;
use primus_modulo::Modulo;
use primus_reduce::FieldContext;

use super::BaseConverter;

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Converts one residue vector from the input basis to the output basis.
    ///
    /// `residues_in.len()` must equal `input_moduli_count()`. Element `i` is
    /// interpreted modulo `input_base().moduli()[i]`.
    ///
    /// `residues_out.len()` must equal `output_moduli_count()`. Element `j`
    /// receives the converted residue modulo `output_base().moduli()[j]`.
    ///
    /// `scratch.len()` must equal `input_moduli_count()`. It stores the
    /// adjusted input residues and is overwritten by the conversion.
    pub fn fast_convert(&self, residues_in: &[T], residues_out: &mut [T], scratch: &mut [T]) {
        debug_assert_eq!(residues_in.len(), self.input_moduli_count());
        debug_assert_eq!(scratch.len(), self.input_moduli_count());
        debug_assert_eq!(residues_out.len(), self.output_moduli_count());

        izip!(
            residues_in,
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli(),
            scratch.iter_mut()
        )
        .for_each(|(&value, &inv, modulus, result)| {
            *result = inv.factor_mul_modulo(value, unsafe { modulus.value_unchecked() });
        });

        let buf = &*scratch;

        izip!(
            residues_out,
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(ele, base_change_row, modulus)| {
            *ele = modulus.reduce_dot_product(buf, base_change_row);
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
        debug_assert_eq!(crt_poly_in.len(), input_moduli_count * poly_length);
        debug_assert_eq!(scratch.len(), input_moduli_count * poly_length);

        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(
            |(i, (poly, &inv_punctured_product_mod_modulus, &modulus))| {
                if inv_punctured_product_mod_modulus.value().is_one() {
                    izip!(poly, scratch.iter_mut().skip(i).step_by(input_moduli_count)).for_each(
                        |(&x, ele)| {
                            *ele = x.modulo(modulus);
                        },
                    );
                } else {
                    let modulus = unsafe { modulus.value_unchecked() };
                    izip!(poly, scratch.iter_mut().skip(i).step_by(input_moduli_count)).for_each(
                        |(&x, ele)| {
                            *ele = inv_punctured_product_mod_modulus.factor_mul_modulo(x, modulus);
                        },
                    );
                }
            },
        );
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
    /// `scratch.len()` must equal `input_moduli_count() * poly_length`. It is
    /// overwritten in coefficient-major layout before the output chunks are
    /// computed.
    pub fn fast_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let input_moduli_count = self.input_moduli_count();
        let expected_out_len = self
            .output_moduli_count()
            .checked_mul(poly_length)
            .expect("RNS output length overflow");

        assert_eq!(crt_poly_out.len(), expected_out_len);
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);

        izip!(
            crt_poly_out.chunks_exact_mut(poly_length),
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(poly, inv_punctured_product_mod_modulus, modulus)| {
            izip!(poly, scratch.chunks_exact(input_moduli_count)).for_each(|(ele, product)| {
                *ele = modulus.reduce_dot_product(product, inv_punctured_product_mod_modulus);
            });
        });
    }

    /// Converts an array into a caller-provided sequence of output polynomials.
    ///
    /// This is the scatter-output counterpart of [`fast_convert_array`](Self::fast_convert_array).
    /// It lets composite RNS operations write converted limbs directly into a
    /// non-contiguous destination without allocating an intermediate array.
    pub(crate) fn fast_convert_array_to_polynomials<'a, I>(
        &self,
        crt_poly_in: &[T],
        mut crt_poly_out: I,
        poly_length: usize,
        scratch: &mut [T],
    ) where
        T: 'a,
        I: Iterator<Item = &'a mut [T]>,
    {
        let (minimum_outputs, maximum_outputs) = crt_poly_out.size_hint();
        assert_eq!(maximum_outputs, Some(minimum_outputs));
        assert_eq!(minimum_outputs, self.output_moduli_count());
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);

        izip!(
            crt_poly_out.by_ref(),
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(poly, base_change_row, modulus)| {
            assert_eq!(poly.len(), poly_length);
            izip!(poly, scratch.chunks_exact(self.input_moduli_count())).for_each(
                |(coefficient, adjusted_residues)| {
                    *coefficient = modulus.reduce_dot_product(adjusted_residues, base_change_row);
                },
            );
        });
    }

    /// Converts an array and returns output residues as pairs.
    ///
    /// The output basis must contain exactly two moduli. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// `scratch.len()` must equal `input_moduli_count() * poly_length`. It is
    /// overwritten in coefficient-major layout and is borrowed by the returned
    /// iterator.
    ///
    /// The iterator yields exactly `poly_length` items, one `(mod p_0, mod p_1)`
    /// pair per coefficient.
    pub fn fast_convert_array_to_pair_iter<'a>(
        &'a self,
        crt_poly_in: &[T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl Iterator<Item = (T, T)> + 'a {
        assert_eq!(
            self.output_moduli_count(),
            2,
            "output base in fast_convert_array_to_pair must contain exactly two moduli"
        );

        let input_moduli_count = self.input_moduli_count();
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);

        let mut rows = self.iter_base_change_matrix();
        let row_0 = rows.next().expect("missing first output-base row");
        let row_1 = rows.next().expect("missing second output-base row");
        let modulus_0 = self.output_base.moduli()[0];
        let modulus_1 = self.output_base.moduli()[1];

        scratch
            .chunks_exact(input_moduli_count)
            .map(move |product| {
                (
                    modulus_0.reduce_dot_product(product, row_0),
                    modulus_1.reduce_dot_product(product, row_1),
                )
            })
    }
}
