use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, NttPolynomialIterMut};

use super::Rlwe;

/// An owned NTT-domain RLWE sample backed by a [`Vec<T>`].
pub type NttRlweOwned<T> = NttRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`NttPolynomial`] with same poly length.
#[derive(Clone)]
pub struct NttRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttRlwe);

impl_iters!(NttRlwe);
impl_iter_sub_structure!(NttRlwe, NttPolynomial, ntt_poly);
impl_rlwe_accessors!(NttRlwe, NttPolynomial);

impl_basic_operation_single_modulus!(NttRlwe);
impl_neg_single_modulus!(NttRlwe);
impl_mul_scalar_single_modulus!(NttRlwe);
impl_ntt_polynomial_mul!(NttRlwe);

impl_intt!(NttRlwe, Rlwe);

impl<S, T> NttRlwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`NttRlwe<S>`] with reference of [`NttPolynomial<A>`].
    #[inline]
    #[must_use]
    pub fn from_ref<A>(a: &NttPolynomial<A>, b: &NttPolynomial<A>) -> Self
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(a.poly_length(), b.poly_length());
        Self(S::from_vec([a.as_ref(), b.as_ref()].concat()))
    }
}
