use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, Polynomial};
use primus_reduce::{FieldContext, RingContext};

use crate::lwe::Lwe;

use super::NttNtru;

/// A cryptographic structure for NTRU.
///
/// ## Structure of the `data`
///
/// |------h------|
///
/// where `h` is [`Polynomial`].
#[derive(Clone)]
pub struct Ntru<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Ntru<S>);
impl_bytes_conversion!(Ntru<S>);
impl_zero!(Ntru<S>);
impl_iters!(Ntru);
impl_basic_operation_single_modulus!(Ntru<S>);

impl<S, T> Ntru<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Ntru<S>`] with reference of [`Polynomial<A>`].
    #[inline]
    pub fn from_ref<A>(h: &Polynomial<A>) -> Self
    where
        A: Data<Elem = T>,
    {
        Self(S::from_vec(h.as_ref().to_vec()))
    }
}

impl<S, T> Ntru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts the constant-term NTRU phase as an LWE ciphertext.
    ///
    /// For an NTRU ciphertext `c` encrypted under `f`, this writes
    /// `a[0] = -c[0]`, `a[i] = c[N - i]` for `i > 0`, and `b = 0`. Hence the
    /// LWE phase `b - <a, f>` equals the constant coefficient of `f * c` in
    /// `Z_q[X] / (X^N + 1)`.
    ///
    /// # Panics
    ///
    /// Panics if `output` does not have LWE dimension `N`.
    #[inline]
    pub fn extract_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let coefficients = self.as_ref();
        assert_eq!(output.dimension(), coefficients.len());
        self.extract_compact_lwe_to(output, modulus);
    }

    /// Extracts the constant-term phase while omitting a zero-padded suffix.
    ///
    /// If the NTRU secret is `[s_lwe..., 0...]`, an output of dimension
    /// `s_lwe.len()` has the same phase as full extraction without allocating
    /// or processing the omitted mask coefficients.
    ///
    /// # Panics
    ///
    /// Panics if the output dimension is zero or exceeds the NTRU polynomial
    /// length.
    #[inline]
    pub fn extract_compact_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let coefficients = self.as_ref();
        let (a, b) = output.a_b_mut();
        assert!((1..=coefficients.len()).contains(&a.len()));

        *b = T::ZERO;
        a[0] = modulus.reduce_neg(coefficients[0]);
        a[1..]
            .iter_mut()
            .zip(coefficients[1..].iter().rev())
            .for_each(|(output, &coefficient)| *output = coefficient);
    }

    /// Multiplies this ciphertext by `X^exponent` and writes the result.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    #[inline]
    pub fn mul_monomial_to<M, A>(&self, exponent: usize, output: &mut Ntru<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        Polynomial(self.as_ref()).mul_monomial_to(
            exponent,
            &mut Polynomial(output.as_mut()),
            modulus,
        );
    }

    /// Computes `output = self * (X^exponent - 1)`.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    #[inline]
    pub fn mul_monomial_sub_one_to<M, A>(&self, exponent: usize, output: &mut Ntru<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        Polynomial(self.as_ref()).mul_monomial_sub_one_to(
            exponent,
            &mut Polynomial(output.as_mut()),
            modulus,
        );
    }

    /// Transforms `self` to ntt form and stores in `result`.
    #[inline]
    pub fn write_ntt_form<Table, A>(&self, result: &mut NttNtru<A>, ntt_table: &Table)
    where
        A: DataMut<Elem = T>,
        Table: NttTable<ValueT = T>,
    {
        let p = result.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p)
    }

    /// Performs a multiplication on the `self` [`Ntru<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the result into `result` [`NttNtru<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttNtru<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let p = result.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p);
        NttPolynomial(p).mul_assign(ntt_poly, modulus);
    }
}

impl<S, T> Ntru<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Multiplies each coefficient by `scalar` modulo `modulus` in place.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: FieldContext<T>,
    {
        ArrayBase(self.as_mut()).mul_scalar_assign(scalar, modulus);
    }

    /// Multiplies each coefficient by a Shoup `factor` modulo `modulus` in place.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        ArrayBase(self.as_mut()).mul_factor_assign(factor, modulus);
    }

    /// Transforms `self` to ntt form.
    #[inline]
    pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> NttNtru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.transform_slice(self.as_mut());
        NttNtru::new(self.0)
    }
}
