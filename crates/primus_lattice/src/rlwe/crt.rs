use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
#[allow(unused_imports)]
use primus_poly::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut, DcrtPolynomial};
use primus_reduce::FieldContext;

use super::DcrtRlwe;

/// An owned CRT-domain RLWE sample backed by a [`Vec<T>`].
pub type CrtRlweOwned<T> = CrtRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`CrtPolynomial`] with same poly length and moduli count.
#[derive(Clone)]
pub struct CrtRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtRlwe);

impl_iters!(CrtRlwe);
impl_iter_sub_structure!(CrtRlwe, CrtPolynomial, crt_poly);
impl_rlwe_accessors!(CrtRlwe, CrtPolynomial);

impl_basic_operation_multiple_modulus!(CrtRlwe);
impl_neg_multiple_modulus!(CrtRlwe);
impl_mul_scalar_multiple_modulus!(CrtRlwe);
impl_mul_factor_multiple_modulus!(CrtRlwe);
impl_add_mul_monomial_multiple_modulus!(CrtRlwe);

impl_crt_ntt!(CrtRlwe, DcrtRlwe);

impl<S, T> CrtRlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`CrtRlwe<S>`] with another `dcrt_polynomial` [`DcrtPolynomial<A>`],
    /// store the output into `output` [`DcrtRlwe<B>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        output: &mut DcrtRlwe<B>,
        moduli: &[M],
        table: &DcrtTable<Table>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = table.poly_length();
        let crt_poly_len = table.crt_poly_length();

        output.0.copy_from_slice(self.as_ref());

        output
            .iter_dcrt_poly_mut(crt_poly_len)
            .for_each(|mut poly| {
                table.transform_slice(poly.0);
                poly.mul_assign(dcrt_poly, poly_length, moduli);
            });
    }
}
