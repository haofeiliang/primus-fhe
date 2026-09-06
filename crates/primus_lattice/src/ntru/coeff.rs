use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::{FieldContext, RingContext};

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

impl_ciphertext_core!(Ntru);

impl_iters!(Ntru);

impl_basic_operation_single_modulus!(Ntru);
impl_neg_single_modulus!(Ntru);
impl_mul_scalar_single_modulus!(Ntru);
impl_mul_factor_single_modulus!(Ntru);

impl<S, T> Ntru<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Ntru<S>`] with reference of [`Polynomial<A>`].
    #[inline]
    #[must_use]
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
    /// Multiplies this ciphertext by `X^exponent` and writes the output.
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

    /// Transforms `self` to ntt form and stores in `output`.
    #[inline]
    pub fn write_ntt_form<Table, A>(&self, output: &mut NttNtru<A>, ntt_table: &Table)
    where
        A: DataMut<Elem = T>,
        Table: NttTable<ValueT = T>,
    {
        let p = output.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p)
    }

    /// Performs a multiplication on the `self` [`Ntru<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the output into `output` [`NttNtru<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        output: &mut NttNtru<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let p = output.as_mut();
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
    /// Transforms `self` to ntt form.
    #[inline]
    pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> NttNtru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.transform_slice(self.as_mut());
        NttNtru::new(self.0)
    }

    /// Multiplies this polynomial ciphertext by `X^exponent` without allocation.
    ///
    /// The polynomial length `N` must be a supported power of two, and `exponent`
    /// must be in `[0, 2N)`. Canonical input residues produce canonical output.
    #[inline]
    pub fn mul_monomial_assign<M>(&mut self, exponent: usize, modulus: M)
    where
        M: Copy + primus_reduce::ReduceNegSlice<T>,
    {
        Polynomial(self.as_mut()).mul_monomial_assign(exponent, modulus);
    }

    /// Accumulates `self += rhs * X^exponent` in `Z_q[X]/(X^N + 1)`.
    ///
    /// Both ciphertexts must contain a polynomial of the same nonzero power-of-two
    /// length `N`, use compatible keys, and contain canonical residues. `exponent`
    /// must be in `[0, 2N)`. Results are canonical; no temporary storage is allocated.
    #[inline]
    pub fn add_mul_monomial_assign<M, A>(&mut self, rhs: &Ntru<A>, exponent: usize, modulus: M)
    where
        M: Copy + primus_reduce::ReduceAddSlice<T> + primus_reduce::ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        Polynomial(self.as_mut()).add_mul_monomial_assign(
            &Polynomial(rhs.as_ref()),
            exponent,
            modulus,
        );
    }
}
