use itertools::izip;
use num_traits::Zero;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{ByteCount, FheUint, Size};
use primus_reduce::{ReduceAdd, ReduceMul, ReduceMulAddSlice, ReduceSub};

use crate::ArrayBase;

mod add;
mod inv;
mod mul;
mod neg;
mod random;
mod sub;

/// Raw modulus-major NTT storage for a CRT polynomial.
///
/// A complete RNS polynomial contains one contiguous `N`-evaluation block per
/// modulus, in the base's order and the originating NTT table's order. This
/// wrapper stores neither `N`, the base nor the transform identity: empty,
/// arbitrary-length and packed storage are allowed. [`Self::len`] counts all
/// stored evaluations; the owning boundary establishes the complete layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcrtPolynomial<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_iters!(DcrtPolynomial, dcrt_poly);

impl_views!(DcrtPolynomial);

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`DcrtPolynomial<S>`] from modulus-major NTT storage.
    #[must_use]
    #[inline]
    pub fn new(polys: S) -> Self {
        Self(polys)
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a [`DcrtPolynomial<S>`] with `len` zero NTT evaluations.
    #[must_use]
    #[inline]
    pub fn zero(len: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; len]))
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Extracts a mutable slice of the entire vector.
    ///
    /// Equivalent to `&mut s[..]`.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }

    /// Returns complete mutable modulus blocks of `poly_length` NTT values.
    ///
    /// Any incomplete trailing block is omitted. Callers must establish the
    /// total length and modulus count/order before using these blocks.
    ///
    /// # Panics
    /// Panics if `poly_length` is zero.
    #[inline]
    pub fn iter_each_modulus_mut(
        &mut self,
        poly_length: usize,
    ) -> std::slice::ChunksExactMut<'_, T> {
        self.0.chunks_exact_mut(poly_length)
    }

    /// Sets `self` to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Copy the coefficients from another slice.
    #[inline]
    pub fn copy_from<A>(&mut self, src: &DcrtPolynomial<A>)
    where
        A: Data<Elem = T>,
    {
        self.0.copy_from_slice(src.0.as_slice());
    }

    /// Performs `self += b * c` according to `moduli`.
    #[inline]
    pub fn add_mul_assign<M, A, B>(
        &mut self,
        b: &DcrtPolynomial<A>,
        c: &DcrtPolynomial<B>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            b.iter_each_modulus(poly_length),
            c.iter_each_modulus(poly_length),
            moduli
        )
        .for_each(|(acc, a, b, &modulus)| modulus.reduce_add_mul_slice_assign(acc, a, b))
    }

    /// Inverse butterfly: `(self, result) = (self + rhs, (self_orig - rhs) * w)`
    #[inline]
    pub fn butterfly_mul_to<M, A, B, C>(
        &mut self,
        rhs: &DcrtPolynomial<A>,
        w: &DcrtPolynomial<B>,
        output: &mut DcrtPolynomial<C>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T> + ReduceMul<T, Output = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        izip!(
            self.iter_each_modulus_mut(poly_length),
            rhs.iter_each_modulus(poly_length),
            w.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(a, s, w, b, &modulus)| {
            ArrayBase(a).butterfly_mul_element_wise_to(
                &ArrayBase(s),
                &ArrayBase(w),
                &mut ArrayBase(b),
                modulus,
            );
        })
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts a slice containing the entire vector.
    ///
    /// Equivalent to `&s[..]`.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    /// Returns complete modulus blocks of `poly_length` NTT values.
    ///
    /// Any incomplete trailing block is omitted. Callers must establish the
    /// total length and modulus count/order before using these blocks.
    ///
    /// # Panics
    /// Panics if `poly_length` is zero.
    #[inline]
    pub fn iter_each_modulus(&self, poly_length: usize) -> std::slice::ChunksExact<'_, T> {
        self.0.chunks_exact(poly_length)
    }

    /// Returns `true` if `self` is equal to `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(Zero::is_zero)
    }

    /// Returns the number of elements in the backing storage.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the backing storage contains no NTT evaluations.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<S, T> Size for DcrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * <T as ByteCount>::BYTES
    }
}

impl<S, T> AsRef<[T]> for DcrtPolynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.0.as_slice()
    }
}

impl<S, T> AsMut<[T]> for DcrtPolynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice()
    }
}
