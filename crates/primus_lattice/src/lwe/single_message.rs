use std::mem::MaybeUninit;

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_distr::DiscreteGaussian;
use primus_integer::{FheUint, Size};
use primus_reduce::{Modulus, prelude::*};
use rand::distr::{Distribution, Uniform};
use serde::{Deserialize, Serialize};

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Lwe);
impl_bytes_io!(Lwe);

impl_basic_operation_single_modulus!(Lwe);
impl_neg_single_modulus!(Lwe);
impl_mul_scalar_single_modulus!(Lwe);
impl_mul_factor_single_modulus!(Lwe);

impl<S, T> Lwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates a [`Lwe<S, T>`] with all values are `0`.
    #[must_use]
    #[inline]
    pub fn zero(dimension: usize) -> Self {
        Self(S::from_vec(vec![T::ZERO; dimension + 1]))
    }
}

impl<T> Lwe<Vec<T>>
where
    T: FheUint,
{
    /// Generate a [`Lwe<S, T>`] sample which encrypts `0`.
    #[inline]
    pub fn generate_random_zero_sample<M, R>(
        secret_key: &[T],
        modulus: M,
        uniform: Uniform<T>,
        gaussian: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Self
    where
        M: Copy + Modulus<ValueT = T> + ReduceDotProduct<T> + ReduceAdd<T, Output = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let len = secret_key.len();

        let mut data: Vec<MaybeUninit<T>> = Vec::with_capacity(len + 1);
        unsafe {
            data.set_len(len + 1);
        }
        data[0..len]
            .iter_mut()
            .zip(uniform.sample_iter(&mut *rng))
            .for_each(|(x, y)| {
                x.write(y);
            });
        data[len].write(gaussian.sample(rng));

        let mut data = unsafe { std::mem::transmute::<Vec<MaybeUninit<T>>, Vec<T>>(data) };

        let b = modulus.reduce_dot_product(&data[0..len], secret_key);
        data[len] = modulus.reduce_add(b, data[len]);

        Lwe(data)
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Returns a mutable reference to the `a` of this [`Lwe<S, T>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut [T] {
        self.0.as_mut_slice().split_last_mut().unwrap().1
    }

    /// Returns a mutable reference to the `b` of this [`Lwe<S, T>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut T {
        self.0.as_mut_slice().last_mut().unwrap()
    }

    /// Returns mutable references to `a` and `b` of this [`Lwe<S, T>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut [T], &mut T) {
        let (b, a) = self.0.as_mut_slice().split_last_mut().unwrap();
        (a, b)
    }

    /// Sets all values to `0`.
    #[inline]
    pub fn set_zero(&mut self) {
        self.0.fill(T::ZERO);
    }
}

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns a reference to the `a` of this [`Lwe<S, T>`].
    #[inline]
    pub fn a(&self) -> &[T] {
        self.0.as_slice().split_last().unwrap().1
    }

    /// Returns the `b` of this [`Lwe<S, T>`].
    #[inline]
    pub fn b(&self) -> T {
        *self.0.as_slice().last().unwrap()
    }

    /// Returns a reference to `a` and the value of `b` of this LWE sample.
    pub fn a_b(&self) -> (&[T], T) {
        let (b, a) = self.0.as_slice().split_last().unwrap();
        (a, *b)
    }

    /// Returns the dimension of this [`Lwe<S, T>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.0.len() - 1
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Consumes this ciphertext and negates it, reusing its backing storage.
    ///
    /// Coefficients must satisfy the input range required by `modulus`.
    #[must_use]
    #[inline]
    pub fn neg<M>(mut self, modulus: M) -> Self
    where
        M: Copy + ReduceNegSlice<T>,
    {
        self.neg_assign(modulus);
        self
    }
}

impl<S, T> Size for Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn byte_count(&self) -> usize {
        self.0.len() * T::BYTES
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Adds an already encoded canonical plaintext to `b`, preserving the mask.
    /// The plaintext must use the ciphertext modulus and scale; no encoding occurs.
    #[inline]
    pub fn add_plaintext_assign<M>(&mut self, plaintext: T, modulus: M)
    where
        M: ReduceAddAssign<T>,
    {
        modulus.reduce_add_assign(self.b_mut(), plaintext);
    }

    /// Subtracts an already encoded canonical plaintext from `b`, preserving the mask.
    /// The plaintext must use the ciphertext modulus and scale; no encoding occurs.
    #[inline]
    pub fn sub_plaintext_assign<M>(&mut self, plaintext: T, modulus: M)
    where
        M: ReduceSubAssign<T>,
    {
        modulus.reduce_sub_assign(self.b_mut(), plaintext);
    }

    /// Overwrites the ciphertext with a zero mask and an already encoded body.
    /// The plaintext must be canonical in the ciphertext modulus and scale.
    /// This performs no encoding, random sampling or allocation.
    #[inline]
    pub fn set_trivial(&mut self, plaintext: T) {
        let (a, b) = self.a_b_mut();
        a.fill(T::ZERO);
        *b = plaintext;
    }
}
