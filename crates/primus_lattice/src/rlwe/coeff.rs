use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::FieldContext;

use super::NttRlwe;

/// An owned RLWE sample backed by a [`Vec<T>`].
pub type RlweOwned<T> = Rlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`Polynomial`] with same poly length.
#[derive(Clone)]
pub struct Rlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Rlwe);

impl_iters!(Rlwe);
impl_iter_sub_structure!(Rlwe, Polynomial, poly);
impl_rlwe_accessors!(Rlwe, Polynomial);

impl_basic_operation_single_modulus!(Rlwe);
impl_neg_single_modulus!(Rlwe);
impl_mul_scalar_single_modulus!(Rlwe);
impl_mul_factor_single_modulus!(Rlwe);
impl_monomial_single_modulus!(Rlwe);
impl_plaintext_single_modulus!(Rlwe, Polynomial);

impl_ntt!(Rlwe, NttRlwe);

impl<S, T> Rlwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Rlwe<S>`] with reference of [`Polynomial<A>`].
    #[inline]
    #[must_use]
    pub fn from_ref<A>(a: &Polynomial<A>, b: &Polynomial<A>) -> Self
    where
        A: Data<Elem = T>,
    {
        debug_assert_eq!(a.poly_length(), b.poly_length());
        Self(S::from_vec([a.as_ref(), b.as_ref()].concat()))
    }
}

impl<T: FheUint> Rlwe<Vec<T>> {
    /// Generate a [`Rlwe<Vec<T>>`] sample which encrypts `0`.
    pub fn generate_random_zero_sample<R, Table, M, A>(
        secret_key: &NttPolynomial<A>,
        gaussian: &DiscreteGaussian<T>,
        ntt_table: &Table,
        modulus: M,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        M: FieldContext<T>,
    {
        let poly_length = secret_key.poly_length();

        let mut data = Rlwe::zero(poly_length * 2);

        let (a, b) = data.a_b_mut_slices();

        Polynomial(&mut *a).random_assign(modulus, rng);

        b.copy_from_slice(a);
        ntt_table.transform_slice(b);
        NttPolynomial(&mut *b).mul_assign(secret_key, modulus);
        ntt_table.inverse_transform_slice(b);

        Polynomial(b).add_random_gaussian_assign(gaussian, modulus, rng);

        data
    }
}

impl<S, T> Rlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`Rlwe<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the output into `output` [`NttRlwe<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        output: &mut NttRlwe<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = ntt_table.poly_length();

        output.0.copy_from_slice(self.as_ref());

        output.0.chunks_exact_mut(poly_length).for_each(|poly| {
            ntt_table.transform_slice(poly);
            NttPolynomial(poly).mul_assign(ntt_poly, modulus);
        });
    }
}
