//! Fused sums of public-polynomial/NLEV external products.
//!
//! Each pair is decomposed independently. Only the transform-domain products
//! are added; the single inverse transform must follow the entire sum.
//! Batch counts and destination lengths are checked before writing. Pair lengths
//! are checked during the single pass so iterators need neither cloning nor storage.

use core::borrow::Borrow;

use primus_data::Data;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

use crate::ntru::{Ntru, NttNtru, accumulate_ntt_gadget_product};
use crate::workspace::NttNtruExternalProductWorkspace;

use super::NttNlev;

impl<S, T> NttNlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes `output = sum_j polynomials[j] odot gadgets[j]`.
    ///
    /// Accumulates every product in the transform domain, then converts once to
    /// coefficient form. Output is overwritten; an empty sum writes zero. The
    /// workspace is reused without allocation or a caller-side reset.
    ///
    /// # Correctness
    /// Each pair inherits [`Self::external_product_to`]'s representation, basis,
    /// table and workspace contracts. Gadgets and polynomials have equal counts
    /// and matching order; all use the same basis. Inputs may be borrowed objects
    /// or semantic iterators over packed storage. Polynomial items convert to
    /// shared views via `Into`; pass `output.as_mut_view()` for an owned output.
    /// Callers constructing chunk iterators must exclude incomplete trailing objects.
    ///
    /// # Panics
    /// Panics on unequal reported iterator counts or incorrect object lengths.
    /// Counts, output length and gadget-length overflow are checked before writes.
    /// Each pair is checked as consumed; an invalid pair or panicking iterator may
    /// leave output holding a partial NTT-domain sum. It is not a coefficient result.
    /// Reusing the workspace in a valid call needs no reset.
    pub fn external_product_sum_to<'a, M, Table, I, J>(
        gadgets: I,
        polynomials: J,
        mut output: Ntru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Polynomial<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let gadgets = gadgets.into_iter();
        let polynomials = polynomials.into_iter();
        assert_eq!(
            gadgets.len(),
            polynomials.len(),
            "external-product sum requires one gadget per polynomial"
        );
        let poly_length = workspace.poly_length().get();
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "external-product output length mismatch"
        );
        if gadgets.len() == 0 {
            output.set_zero();
            return;
        }
        let gadget_len = basis
            .level_count()
            .get()
            .checked_mul(poly_length)
            .expect("external-product gadget length overflow");
        // Share coefficient/NTT storage and invert in place after all terms.
        let mut transformed = NttNtru(output.as_mut());
        let mut workspace = workspace.as_mut_with_accumulator(&mut transformed);
        workspace.ntt_accumulator.set_zero();
        for (gadget, polynomial) in gadgets.zip(polynomials) {
            let gadget: &Self = gadget.borrow();
            let polynomial = polynomial.into();
            assert_eq!(
                polynomial.as_ref().len(),
                poly_length,
                "external-product polynomial length mismatch"
            );
            assert_eq!(
                gadget.as_ref().len(),
                gadget_len,
                "external-product gadget length mismatch"
            );
            accumulate_ntt_gadget_product(
                gadget.as_ref(),
                polynomial.as_ref(),
                basis,
                modulus,
                ntt,
                &mut workspace,
            );
        }
        ntt.inverse_transform_slice(workspace.ntt_accumulator.as_mut());
    }
}
