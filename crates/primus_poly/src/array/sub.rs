use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::ReduceSubSlice;

use super::ArrayBase;

impl<S, T> ArrayBase<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_element_wise<M, A>(mut self, rhs: &ArrayBase<A>, modulus: M) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        self.sub_element_wise_assign(rhs, modulus);
        self
    }

    /// Performs `self -= rhs` according to `modulus`.
    #[inline]
    pub fn sub_element_wise_assign<M, A>(&mut self, rhs: &ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_sub_slice_assign(self.as_mut(), rhs.as_ref());
    }
}

impl<S, T> ArrayBase<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs `result = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_element_wise_to<M, A, B>(
        &self,
        rhs: &ArrayBase<A>,
        output: &mut ArrayBase<B>,
        modulus: M,
    ) where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }

    /// Performs `rhs = self - rhs` according to `modulus`.
    #[inline]
    pub fn sub_element_wise_rev_assign<M, A>(&self, rhs: &mut ArrayBase<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_rev_assign(self.as_ref(), rhs.as_mut());
    }
}
