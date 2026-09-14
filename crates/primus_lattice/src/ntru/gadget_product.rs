//! Shared NLev and NGSW decomposition, transform, and accumulation kernels.

use crate::context::{
    FourierNtruExternalProductContextRefMut, NttNtruExternalProductContextRefMut,
};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial};
use primus_reduce::FieldContext;

/// Adds the gadget product of `gadget` and `input` to the existing Fourier accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
///
/// # Correctness
///
/// Input contains `N = context.poly_length()` canonical coefficients. The
/// gadget has `basis.decompose_length()` complete levels in decomposition
/// order, each of length `N / 2` in the FFT table's normalized torus
/// representation. The basis uses the native modulus, and FFT/context
/// polynomial lengths and packing agree. The selected accumulator has `N / 2`
/// complex values and is disjoint from the input and decomposition scratch.
/// These conditions are caller obligations, with selected debug diagnostics.
pub(crate) fn accumulate_fourier_gadget_product<T, Table>(
    gadget: &[Complex64],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut FourierNtruExternalProductContextRefMut<'_, T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let poly_length = context.poly_length();
    let fourier_length = fft.fourier_length();

    debug_assert_eq!(fft.poly_length(), poly_length);
    debug_assert_eq!(fourier_length, poly_length / 2);
    debug_assert_eq!(basis.modulus(), None);
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.decompose_length() * fourier_length);

    basis.init_carry_slice(input, context.carries);

    for (decomposer, key_level) in basis
        .decomposer_iter()
        .zip(gadget.chunks_exact(fourier_length))
    {
        decomposer.decompose_slice_to(input, context.decomposed_poly, context.carries);
        fft.forward_as_integer(context.decomposed_poly, context.decomposed_fourier);
        FourierPolynomial(context.fourier_accumulator.as_mut()).add_mul_assign(
            &FourierPolynomial(&*context.decomposed_fourier),
            &FourierPolynomial(key_level),
        );
    }
}

/// Adds the gadget product of `gadget` and `input` to the existing NTT accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
///
/// # Correctness
///
/// Input contains `N = context.poly_length()` canonical coefficients. The
/// gadget has `basis.decompose_length()` complete levels in decomposition
/// order, each of length `N` in the NTT table's evaluation order.
/// Gadget values are canonical. Basis, table, and arithmetic modulus agree,
/// and the table polynomial length equals `N`. The selected accumulator has
/// `N` values and is disjoint from the input and decomposition scratch.
/// These conditions are caller obligations, with selected debug diagnostics.
pub(crate) fn accumulate_ntt_gadget_product<T, M, Table>(
    gadget: &[T],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    context: &mut NttNtruExternalProductContextRefMut<'_, T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let poly_length = context.poly_length();

    debug_assert_eq!(ntt.poly_length(), poly_length);
    debug_assert_eq!(ntt.modulus(), modulus.value());
    debug_assert_eq!(basis.modulus(), Some(modulus.value()));
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.decompose_length() * poly_length);

    basis.init_value_carry_slice_to(input, context.adjusted_poly, context.carries);

    for (decomposer, key_level) in basis
        .decomposer_iter()
        .zip(gadget.chunks_exact(poly_length))
    {
        decomposer.decompose_slice_to(
            context.adjusted_poly,
            context.decomposed_ntt,
            context.carries,
        );
        ntt.transform_slice(context.decomposed_ntt);
        NttPolynomial(context.ntt_accumulator.as_mut()).add_mul_assign(
            &NttPolynomial(key_level),
            &NttPolynomial(&*context.decomposed_ntt),
            modulus,
        );
    }
}
