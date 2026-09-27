//! Fuse the first encrypted rotation with lifting a public polynomial.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{
    context::{FourierNtruCmuxContext, NttNtruCmuxContext},
    ntru::Ntru,
};

use super::{FourierNlev, NttNlev};

impl<S, T> NttNlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Lifts a public polynomial while applying the first encrypted rotation.
    ///
    /// `self` encrypts one; `positive` and optional `negative` encrypt bits
    /// `s⁺` and `s⁻` as NLEV, not NGSW. With `R = X^exponent`, this computes
    /// `input ⊙ (self + (R-1)*positive + (R^-1-1)*negative)`.
    /// Only `input` is approximately decomposed. Monomial factors multiply
    /// gadget rows exactly, so small factors are not lost to decomposition.
    /// A zero exponent still lifts `input` with `self`.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_to`]'s representation, modulus, table,
    /// basis, input and output contracts. All controls use that same key and
    /// basis, with `context.decompose_length()` levels. Bits are mutually
    /// exclusive; omit `negative` for a binary secret. `exponent` is in `0..2N`,
    /// already quantized; its inverse is derived modulo `2N`.
    /// If decomposition reconstructs `input - epsilon`, the ideal phase is
    /// `(input - epsilon) * X^(exponent * (s⁺-s⁻))`, plus control noise.
    /// The input must therefore have sufficient scale for this basis.
    /// Output and scratch are overwritten without allocation or reset.
    ///
    /// # Panics
    /// Panics if output has the wrong polynomial length. For nonzero exponents,
    /// panics if initializer/combined scratch lengths differ or if table/context
    /// lengths differ during monomial preparation. Scratch may be partly written.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, public input, arithmetic, and scratch explicit"
    )]
    pub fn lift_monomial_to<M, Table, A, B, C>(
        &self,
        positive: &NttNlev<A>,
        negative: Option<&NttNlev<A>>,
        input: &Polynomial<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruCmuxContext<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.decompose_length(), context.decompose_length());
        debug_assert_eq!(positive.as_ref().len(), self.as_ref().len());
        if exponent == 0 {
            self.external_product_to(
                input,
                output,
                basis,
                modulus,
                ntt,
                &mut context.external_product,
            );
            return;
        }

        let mut combined = NttNlev(context.combined_control.as_mut_slice());
        combined.as_mut().copy_from_slice(self.as_ref());
        // Sequential use lets monomial preparation borrow the digit buffer.
        let factor = context.external_product.as_mut().decomposed_ntt;
        ntt.transform_coeff_one_monomial(exponent, factor);
        for value in factor.iter_mut() {
            *value = modulus.reduce_sub(*value, T::ONE);
        }
        combined.add_mul_ntt_polynomial_assign(positive, &NttPolynomial(&*factor), modulus);
        if let Some(negative) = negative {
            debug_assert_eq!(negative.as_ref().len(), self.as_ref().len());
            // In bit-reversed negacyclic order, evaluation points i and N-1-i
            // are inverses. Reversing NTT(X^e-1) therefore gives NTT(X^-e-1).
            factor.reverse();
            combined.add_mul_ntt_polynomial_assign(negative, &NttPolynomial(&*factor), modulus);
        }
        combined.external_product_to(
            input,
            output,
            basis,
            modulus,
            ntt,
            &mut context.external_product,
        );
    }
}

impl<S> FourierNlev<S>
where
    S: Data<Elem = Complex64>,
{
    /// Lifts a public polynomial while applying the first encrypted rotation.
    ///
    /// `self` is `NLEV[1]`; `positive` and optional `negative` are NLEV bit
    /// encryptions. Computes `input ⊙ (self + (R-1)*positive + (R^-1-1)*negative)`
    /// with `R = X^exponent`. Only `input` is decomposed; row multiplication
    /// uses an integer-scale monomial transform. Zero still performs the lift.
    ///
    /// # Correctness
    /// Inherits [`Self::external_product_to`]'s native basis, normalized torus
    /// scale, input/output layout and FFT contracts. All controls use the same
    /// key, basis, exact FFT table instance and `context.decompose_length()`
    /// levels. Bits are mutually exclusive; omit `negative` for binary.
    /// `exponent` is already quantized into `0..2N`.
    /// The ideal phase is the basis reconstruction of `input` times
    /// `X^(exponent * (s⁺-s⁻))`, plus control noise and Fourier rounding.
    /// Effective input information below the decomposition resolution can be
    /// lost. Output and scratch are overwritten without allocation or reset.
    ///
    /// # Panics
    /// For nonzero exponents, panics if initializer/combined scratch lengths
    /// differ or FFT/scratch lengths differ during the monomial transform.
    /// Scratch may be partly written; these checks precede output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, public input, transform, and scratch explicit"
    )]
    pub fn lift_monomial_to<T, Table, A, B, C>(
        &self,
        positive: &FourierNlev<A>,
        negative: Option<&FourierNlev<A>>,
        input: &Polynomial<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruCmuxContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.decompose_length(), context.decompose_length());
        debug_assert_eq!(positive.as_ref().len(), self.as_ref().len());
        if exponent == 0 {
            self.external_product_to(input, output, basis, fft, &mut context.external_product);
            return;
        }

        let mut combined = FourierNlev(context.combined_control.as_mut_slice());
        combined.as_mut().copy_from_slice(self.as_ref());
        let product = context.external_product.as_mut();
        product.decomposed_poly.fill(T::ZERO);
        let (index, coefficient) = if exponent < poly_length {
            (exponent, T::ONE)
        } else {
            (exponent - poly_length, T::MAX)
        };
        product.decomposed_poly[index] = coefficient;
        fft.forward_as_integer(product.decomposed_poly, product.decomposed_fourier);
        for value in product.decomposed_fourier.iter_mut() {
            value.re -= 1.0;
        }
        add_fourier_product(
            combined.as_mut(),
            positive.as_ref(),
            product.decomposed_fourier,
        );
        if let Some(negative) = negative {
            debug_assert_eq!(negative.as_ref().len(), self.as_ref().len());
            // At roots of unity, conjugation gives R^-1-1 at the same scale.
            for value in product.decomposed_fourier.iter_mut() {
                *value = value.conj();
            }
            add_fourier_product(
                combined.as_mut(),
                negative.as_ref(),
                product.decomposed_fourier,
            );
        }
        combined.external_product_to(input, output, basis, fft, &mut context.external_product);
    }
}

fn add_fourier_product(output: &mut [Complex64], control: &[Complex64], factor: &[Complex64]) {
    for (output, control) in output
        .chunks_exact_mut(factor.len())
        .zip(control.chunks_exact(factor.len()))
    {
        for ((output, &control), &factor) in output.iter_mut().zip(control).zip(factor) {
            *output += control * factor;
        }
    }
}
