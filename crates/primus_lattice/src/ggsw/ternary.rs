use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::FieldContext;

use crate::{context::NttGlweTernaryCmuxContext, glwe::Glwe};

use super::NttGgsw;

impl<S, T> NttGgsw<S>
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
    /// Approximate decomposition and noise need not match two successive binary
    /// CMUX operations. Both control encryptions contribute noise, even for `s=0`.
    ///
    /// # Correctness
    ///
    /// Both controls, input, output, basis, modulus, and table must satisfy
    /// [`Self::external_product_to`] with `context.size()`. Controls encrypt bits
    /// under the same key and basis, and at most one bit is one; this is unchecked.
    /// Independent control encryption is required for the usual noise estimate.
    /// `exponent` is already quantized and must be in `0..2N`. Its negative is
    /// derived modulo `2N`, not by separately quantizing a negated LWE coefficient.
    ///
    /// Output is overwritten with canonical coefficient-domain values, without
    /// allocation or caller-side initialization/reset. A public zero exponent
    /// copies `input` exactly without evaluating either control.
    ///
    /// # Panics
    ///
    /// Zero-exponent copying panics if input and output lengths differ.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, operands, basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_ternary_monomial_to<M, Table, A, B, C>(
        &self,
        negative: &NttGgsw<A>,
        input: &Glwe<B>,
        exponent: usize,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweTernaryCmuxContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = context.size();
        let poly_length = size.glwe_size().poly_length();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(self.as_ref().len(), size.ggsw_len());
        debug_assert_eq!(negative.as_ref().len(), size.ggsw_len());
        debug_assert_eq!(input.as_ref().len(), size.glwe_size().glwe_len());
        debug_assert_eq!(output.as_ref().len(), size.glwe_size().glwe_len());

        if exponent == 0 {
            output.as_mut().copy_from_slice(input.as_ref());
            return;
        }

        let inverse_exponent = 2 * poly_length - exponent;
        self.sub_mul_monomial_to(
            negative,
            inverse_exponent,
            &mut context.combined_control,
            modulus,
            ntt,
            &mut context.control_factor_ntt,
        );

        input.mul_monomial_sub_one_to(exponent, output, poly_length, modulus);
        let mut product = context.external_product.as_mut();
        product.ntt_accumulator.set_zero();
        context.combined_control.accumulate_external_product(
            output,
            basis,
            modulus,
            ntt,
            &mut product,
        );
        product.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
