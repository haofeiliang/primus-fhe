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

impl_common!(Lwe<S>);

impl<S, T> Lwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Lwe<S, T>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        let converted_data: &[T] = bytemuck::cast_slice(data);

        Self(DataOwned::from_slice(converted_data))
    }
}

impl<S, T> Lwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Creates a new [`Lwe<S, T>`] from bytes `data`.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        let converted_data: &[T] = bytemuck::cast_slice(data);

        self.0.copy_from_slice(converted_data);
    }
}

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Converts [`Lwe<S, T>`] into bytes.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let data: &[u8] = bytemuck::cast_slice(self.0.as_slice());
        data.to_vec()
    }

    /// Converts [`Lwe<S, T>`] into bytes, stored in `data`.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        let src: &[u8] = bytemuck::cast_slice(self.0.as_slice());

        assert_eq!(data.len(), src.len());

        data.copy_from_slice(src);
    }
}

impl<S, T> Lwe<S>
where
    S: DataOwned<Elem = T>,
    T: FheUint,
{
    /// Generates a [`Lwe<S, T>`] with all values are `0`.
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
    /// Performs component-wise modular addition of two [`Lwe<S, T>`].
    #[inline]
    pub fn add<M, A>(mut self, rhs: &Lwe<A>, modulus: M) -> Self
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        self.add_assign(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise modular addition
    /// on the `self` [`Lwe<S, T>`] with another `rhs` [`Lwe<S, T>`].
    #[inline]
    pub fn add_assign<M, A>(&mut self, rhs: &Lwe<A>, modulus: M)
    where
        M: Copy + ReduceAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }

    /// Performs component-wise modular subtraction of two [`Lwe<S, T>`].
    #[inline]
    pub fn sub<M, A>(mut self, rhs: &Lwe<A>, modulus: M) -> Self
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        self.sub_assign(rhs, modulus);
        self
    }

    /// Performs an in-place component-wise modular subtraction
    /// on the `self` [`Lwe<S, T>`] with another `rhs` [`Lwe<S, T>`].
    #[inline]
    pub fn sub_assign<M, A>(&mut self, rhs: &Lwe<A>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_sub_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice());
    }

    /// Performs an in-place modular scalar multiplication
    /// on the `self` [`Lwe<S, T>`] with scalar `T`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.0.as_mut_slice(), scalar);
    }

    /// Performs an in-place modular scalar multiplication
    /// on the `rhs` [`Lwe<S, T>`] with `scalar` `T`,
    /// then add to `self`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &Lwe<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: Data<Elem = T>,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.0.as_mut_slice(), rhs.0.as_slice(), scalar);
    }

    /// Performs an negation on the `self` [`Lwe<S, T>`].
    #[inline]
    pub fn neg_assign<M>(&mut self, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
    {
        modulus.reduce_neg_slice_assign(self.0.as_mut_slice());
    }
}

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Writes the component-wise modular sum `output = self + rhs`.
    ///
    /// All ciphertexts must have the same layout and length. Coefficients must
    /// satisfy the input range required by `modulus`.
    #[inline]
    pub fn add_to<M, A, B>(&self, rhs: &Lwe<A>, output: &mut Lwe<B>, modulus: M)
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
    pub fn sub_to<M, A, B>(&self, rhs: &Lwe<A>, output: &mut Lwe<B>, modulus: M)
    where
        M: Copy + ReduceSubSlice<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
    }

    /// Performs a modular negation on the `self` [`Lwe<S, T>`].
    #[inline]
    pub fn neg<M, A>(&self, modulus: M) -> Lwe<A>
    where
        M: Copy + ReduceNegSlice<T>,
        A: DataOwned<Elem = T>,
    {
        let len = self.0.len();

        let mut data = vec![T::ZERO; len];
        modulus.reduce_neg_slice_to(self.0.as_slice(), &mut data);

        Lwe::new(A::from_vec(data))
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
