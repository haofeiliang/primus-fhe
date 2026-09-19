use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::FieldContext;

use crate::{
    context::NttNtruTernaryCmuxContext,
    ntru::{Ntru, gadget_product::accumulate_ntt_gadget_product},
};

use super::NttNgsw;

impl<S, T> NttNgsw<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Rotates `input` by an encrypted ternary multiple of `exponent`.
    ///
    /// `self` and `negative` encrypt mutually exclusive bits `s⁺` and `s⁻`.
    /// For `s = s⁺ - s⁻`, the ideal output is `X^(exponent * s) * input`.
    /// This uses one external product:
    /// `output = input + (self - X^-exponent * negative) ⊠ ((X^exponent - 1) * input)`.
    /// Decomposition error and noise need not match two successive binary CMUXes;
    /// both control encryptions contribute noise even for `s=0`.
    ///
    /// # Correctness
    ///
    /// Both controls, input, output, basis, modulus and table must satisfy
    /// [`Self::external_product_to`] with `context.poly_length()`; each control
    /// has `context.decompose_length()` levels matching `basis`.
    /// Control bits must be mutually exclusive (unchecked), under the input's
    /// NTRU key. Independent control encryptions are required for the usual
    /// noise estimate.
    ///
    /// `exponent` is already quantized into `0..2N`. Its negative is derived
    /// modulo `2N`, not by separately quantizing a negated LWE coefficient.
    /// Output is overwritten with canonical coefficient-domain values without
    /// allocation or reset. A public zero exponent copies `input` exactly.
    ///
    /// # Panics
    /// Zero-exponent copying panics if input and output lengths differ.
    /// For nonzero exponents, a table/context polynomial-length mismatch panics
    /// when preparing the monomial factor, before output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, operands, basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_ternary_monomial_to<M, Table, A, B, C>(
        &self,
        negative: &NttNgsw<A>,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruTernaryCmuxContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        let control_length = context.combined_control.as_ref().len();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.decompose_length(), context.decompose_length());
        debug_assert_eq!(self.as_ref().len(), control_length);
        debug_assert_eq!(negative.as_ref().len(), control_length);
        debug_assert_eq!(input.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);
        if exponent == 0 {
            output.as_mut().copy_from_slice(input.as_ref());
            return;
        }

        let inverse_exponent = 2 * poly_length - exponent;
        // Control combination and decomposition run sequentially, so the
        // monomial factor can reuse the external-product digit buffer.
        let mut product = context.external_product.as_mut();
        self.sub_mul_monomial_to(
            negative,
            inverse_exponent,
            &mut context.combined_control,
            modulus,
            ntt,
            product.decomposed_ntt,
        );

        // Output first holds (X^a-1)C, so the external product accumulates in
        // its own buffer until decomposition has consumed the difference.
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        product.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            context.combined_control.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut product,
        );
        product.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
