use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::{FheUint, Size};
use primus_reduce::prelude::*;
use serde::{Deserialize, Serialize};

use super::Lwe;

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
///
/// This structure encrypts several messages like a rlwe but truncated `b`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiMsgLwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(MultiMsgLwe<S>);

impl<S, T> MultiMsgLwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`MultiMsgLwe<S, T>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        let converted_data: &[T] = bytemuck::cast_slice(data);

        Self(S::from_slice(converted_data))
    }

    /// Generates a [`MultiMsgLwe<S, T>`] with all values are `0`.
    #[inline]
    pub fn zero(dimension: usize, msg_count: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; dimension + msg_count]))
    }
}

impl<S, T> MultiMsgLwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`MultiMsgLwe<S, T>`] from bytes `data`.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        let converted_data: &[T] = bytemuck::cast_slice(data);

        self.0.copy_from_slice(converted_data);
    }

    /// Returns mutable references to `a` and `b` of this [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn a_b_mut(&mut self, dimension: usize) -> (&mut [T], &mut [T]) {
        self.0.split_at_mut(dimension)
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }

    /// Perform component-wise modular addition of two [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn add<M, A>(mut self, rhs: &MultiMsgLwe<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise modular addition
    /// on the `self` [`MultiMsgLwe<S, T>`] with another `rhs` [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &MultiMsgLwe<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }

    /// Perform component-wise modular subtraction of two [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn sub<M, A>(mut self, rhs: &MultiMsgLwe<A>, modulus: M) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise modular subtraction
    /// on the `self` [`MultiMsgLwe<S, T>`] with another `rhs` [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn sub_assign<M, A>(&mut self, rhs: &MultiMsgLwe<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_sub_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }

    /// Performs an in-place modular scalar multiplication
    /// on the `self` [`MultiMsgLwe<S, T>`] with scalar `T`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.0.as_mut_slice(), scalar);
    }

    /// Performs an in-place modular scalar multiplication
    /// on the `rhs` [`MultiMsgLwe<S, T>`] with `scalar` `T`,
    /// then add to `self`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &MultiMsgLwe<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice(), scalar);
    }
}

impl<S, T> MultiMsgLwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Converts [`MultiMsgLwe<S, T>`] into bytes.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let data: &[u8] = bytemuck::cast_slice(self.0.as_slice());

        data.to_vec()
    }

    /// Converts [`MultiMsgLwe<S, T>`] into bytes, stored in `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        let src: &[u8] = bytemuck::cast_slice(self.0.as_slice());

        assert_eq!(data.len(), src.len());

        data.copy_from_slice(src);
    }

    /// Returns references to `a` and `b` of this [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn a_b(&self, dimension: usize) -> (&[T], &[T]) {
        self.0.split_at(dimension)
    }

    /// Writes the component-wise modular sum `output = self + rhs`.
    ///
    /// All ciphertexts must have the same layout and length. Coefficients must
    /// satisfy the input range required by `modulus`.
    #[inline]
    pub fn add_to<M, A, B>(&self, rhs: &MultiMsgLwe<A>, output: &mut MultiMsgLwe<B>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_add_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }

    /// Writes the component-wise modular difference `output = self - rhs`.
    ///
    /// All ciphertexts must have the same layout and length. Coefficients must
    /// satisfy the input range required by `modulus`.
    #[inline]
    pub fn sub_to<M, A, B>(&self, rhs: &MultiMsgLwe<A>, output: &mut MultiMsgLwe<B>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }
}

impl<T: FheUint> MultiMsgLwe<Vec<T>> {
    /// Sample extract [`Lwe<Vec<T>>`].
    #[inline]
    pub fn extract_rlwe_mode<M>(&self, dimension: usize, index: usize, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mut data = self.0[..dimension + 1].to_vec();
        if index == 0 {
            Lwe::new(data)
        } else {
            data[..dimension].rotate_right(index);
            modulus.reduce_neg_slice_assign(&mut data[..index]);
            data[dimension] = self.0[dimension + index];
            Lwe::new(data)
        }
    }

    /// Sample extract all [`Lwe<T>`].
    ///
    /// # Panics
    ///
    /// Panics if `msg_count` is zero or exceeds the LWE dimension.
    #[inline]
    pub fn extract_all<M>(&self, msg_count: usize, modulus: M) -> Vec<Lwe<Vec<T>>>
    where
        M: Copy + ReduceNegAssign<T>,
    {
        assert!(
            (1..=self.0.len() / 2).contains(&msg_count),
            "message count must be positive and not exceed the LWE dimension"
        );

        let dimension = self.0.len() - msg_count;
        let mut output = Vec::with_capacity(msg_count);

        let mut data = self.0[..dimension + 1].to_vec();
        self.0[dimension + 1..].iter().for_each(|&b| {
            let lwe = Lwe::new(data.clone());
            output.push(lwe);

            data[..dimension].rotate_right(1);
            modulus.reduce_neg_assign(&mut data[0]);
            data[dimension] = b;
        });
        output.push(Lwe::new(data));

        output
    }
}

impl<S, T> Size for MultiMsgLwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * T::BYTES
    }
}
