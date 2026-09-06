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

impl_common!(MultiMsgLwe);
impl_bytes_io!(MultiMsgLwe);

impl_basic_operation_single_modulus!(MultiMsgLwe);
impl_neg_single_modulus!(MultiMsgLwe);
impl_mul_scalar_single_modulus!(MultiMsgLwe);
impl_mul_factor_single_modulus!(MultiMsgLwe);

impl<S, T> MultiMsgLwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates a [`MultiMsgLwe<S, T>`] with all values are `0`.
    #[must_use]
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
}

impl<S, T> MultiMsgLwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns references to `a` and `b` of this [`MultiMsgLwe<S, T>`].
    #[inline]
    pub fn a_b(&self, dimension: usize) -> (&[T], &[T]) {
        self.0.split_at(dimension)
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
