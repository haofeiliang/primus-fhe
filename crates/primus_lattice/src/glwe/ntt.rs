use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, NttPolynomialIterMut};

use super::Glwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`NttPolynomial`] with same poly length, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
#[derive(Clone)]
pub struct NttGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttGlwe);

impl_iters!(NttGlwe);
impl_iter_sub_structure!(NttGlwe, NttPolynomial, ntt_poly);

impl_basic_operation_single_modulus!(NttGlwe);
impl_neg_single_modulus!(NttGlwe);
impl_mul_scalar_single_modulus!(NttGlwe);
impl_mul_factor_single_modulus!(NttGlwe);
impl_plaintext_single_modulus!(NttGlwe, NttPolynomial);
impl_ntt_polynomial_mul!(NttGlwe);

impl_intt!(NttGlwe, Glwe);

impl<S, T> NttGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `poly_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// The body is the final NTT polynomial and therefore has exactly
    /// `poly_length` evaluations.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_mut_slices(&mut self, poly_length: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        self.as_mut().split_at_mut(glwe_len - poly_length)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    ///
    /// # Correctness
    ///
    /// Storage and polynomial length must satisfy the layout required by [`Self::a_b_slices`].
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length. Also panics if it is zero.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        poly_length: usize,
    ) -> (NttPolynomialIterMut<'_, T>, NttPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(poly_length);
        (
            NttPolynomialIterMut::new(mask, poly_length),
            NttPolynomial(body),
        )
    }
}

impl<S, T> NttGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `poly_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// The body is the final NTT polynomial and therefore has exactly
    /// `poly_length` evaluations.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_slices(&self, poly_length: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        self.0.split_at(glwe_len - poly_length)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    ///
    /// # Correctness
    ///
    /// Storage and polynomial length must satisfy the layout required by [`Self::a_b_slices`].
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length. Also panics if it is zero.
    #[inline]
    pub fn a_b(&self, poly_length: usize) -> (NttPolynomialIter<'_, T>, NttPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(poly_length);
        (
            NttPolynomialIter::new(mask, poly_length),
            NttPolynomial(body),
        )
    }
}
