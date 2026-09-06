use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::{ArrayBase, DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};
use primus_reduce::FieldContext;

use super::CrtRlwe;

/// An owned DCRT-domain RLWE sample backed by a [`Vec<T>`].
pub type DcrtRlweOwned<T> = DcrtRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`DcrtPolynomial`] with same poly length and moduli count.
#[derive(Clone)]
pub struct DcrtRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRlwe);

impl_iters!(DcrtRlwe);
impl_iter_sub_structure!(DcrtRlwe, DcrtPolynomial, dcrt_poly);

impl_basic_operation_multiple_modulus!(DcrtRlwe);

impl_crt_intt!(DcrtRlwe, CrtRlwe);

impl<S, T> DcrtRlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`DcrtRlwe<S>`] with another `dcrt_poly` [`DcrtPolynomial<A>`],
    /// store the output into `output` [`DcrtRlwe<B>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        output: &mut DcrtRlwe<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let dcrt_poly_len = dcrt_poly.dcrt_poly_length();

        self.iter_dcrt_poly(dcrt_poly_len)
            .zip(output.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|(a, mut b)| {
                a.mul_to(dcrt_poly, &mut b, poly_length, moduli);
            });
    }
}
