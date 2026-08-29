//! Value-side mirror of `primus_reduce::slice_ops`.
//!
//! Each trait is implemented on `[T]` and delegates to the corresponding
//! modulus-receiver trait, mirroring the scalar `XxxModulo` / `ReduceXxx`
//! pairing in [`crate::ops`].
//!
//! Implementations may use `debug_assert*!` to diagnose shape mismatches.
//! Release callers must uphold the length and value-range requirements
//! documented on each method. APIs that document panics, such as
//! [`DotProductModulo::dot_product_modulo`], check those conditions in every
//! build profile.

use primus_reduce::prelude::*;

/// Value-side mirror of [`ReduceOnceSlice`].
pub trait OnceModuloSlice<M> {
    /// For each `v` in `self`: `v -= modulus` if `v >= modulus`.
    ///
    /// # Correctness
    ///
    /// - Each `self[i] < 2 * modulus`
    /// - Each result is `< modulus`
    fn once_modulo_slice_assign(&mut self, modulus: M);

    /// Writes the once-reduced value into `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - Each `self[i] < 2 * modulus`
    /// - Each result is `< modulus`
    fn once_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> OnceModuloSlice<M> for [T]
where
    M: ReduceOnceSlice<T>,
{
    #[inline(always)]
    fn once_modulo_slice_assign(&mut self, modulus: M) {
        modulus.reduce_once_slice_assign(self);
    }

    #[inline(always)]
    fn once_modulo_slice_to(&self, output: &mut Self, modulus: M) {
        modulus.reduce_once_slice_to(self, output);
    }
}

/// Value-side mirror of [`ReduceNegSlice`].
pub trait NegModuloSlice<M> {
    /// Calculates `v = -v (mod modulus)` for each element in-place.
    ///
    /// # Correctness
    ///
    /// - Each `self[i] < modulus`
    fn neg_modulo_slice_assign(&mut self, modulus: M);

    /// Writes `-self[i] (mod modulus)` into `output[i]` for each element.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - Each `self[i] < modulus`
    fn neg_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> NegModuloSlice<M> for [T]
where
    M: ReduceNegSlice<T>,
{
    #[inline(always)]
    fn neg_modulo_slice_assign(&mut self, modulus: M) {
        modulus.reduce_neg_slice_assign(self);
    }

    #[inline(always)]
    fn neg_modulo_slice_to(&self, output: &mut Self, modulus: M) {
        modulus.reduce_neg_slice_to(self, output);
    }
}

/// Value-side mirror of [`ReduceAddSlice`].
pub trait AddModuloSlice<M> {
    /// Calculates `self[i] = (self[i] + b[i]) (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    fn add_modulo_slice_assign(&mut self, b: &Self, modulus: M);

    /// Writes `self[i] + b[i] (mod modulus)` into `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == output.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    fn add_modulo_slice_to(&self, b: &Self, output: &mut Self, modulus: M);
}

impl<T, M> AddModuloSlice<M> for [T]
where
    M: ReduceAddSlice<T>,
{
    #[inline(always)]
    fn add_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.reduce_add_slice_assign(self, b);
    }

    #[inline(always)]
    fn add_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.reduce_add_slice_to(self, b, output);
    }
}

/// Value-side mirror of [`ReduceDoubleSlice`].
pub trait DoubleModuloSlice<M> {
    /// `self[i] = 2 * self[i] (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - Each `self[i] < modulus`
    fn double_modulo_slice_assign(&mut self, modulus: M);

    /// `output[i] = 2 * self[i] (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - Each `self[i] < modulus`
    fn double_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> DoubleModuloSlice<M> for [T]
where
    M: ReduceDoubleSlice<T>,
{
    #[inline(always)]
    fn double_modulo_slice_assign(&mut self, modulus: M) {
        modulus.reduce_double_slice_assign(self);
    }

    #[inline(always)]
    fn double_modulo_slice_to(&self, output: &mut [T], modulus: M) {
        modulus.reduce_double_slice_to(self, output);
    }
}

/// Value-side mirror of [`ReduceSubSlice`].
pub trait SubModuloSlice<M> {
    /// Calculates `self[i] = (self[i] - b[i]) (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    fn sub_modulo_slice_assign(&mut self, b: &Self, modulus: M);

    /// Writes `self[i] - b[i] (mod modulus)` into `output[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == output.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    fn sub_modulo_slice_to(&self, b: &Self, output: &mut Self, modulus: M);

    /// Calculates `b[i] = (self[i] - b[i]) (mod modulus)` element-wise
    /// — reverse direction. The second slice is mutated instead of the first.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    fn sub_modulo_slice_rev_assign(&self, b: &mut Self, modulus: M);
}

impl<T, M> SubModuloSlice<M> for [T]
where
    M: ReduceSubSlice<T>,
{
    #[inline(always)]
    fn sub_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.reduce_sub_slice_assign(self, b);
    }

    #[inline(always)]
    fn sub_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.reduce_sub_slice_to(self, b, output);
    }

    #[inline(always)]
    fn sub_modulo_slice_rev_assign(&self, b: &mut [T], modulus: M) {
        modulus.reduce_sub_slice_rev_assign(self, b);
    }
}

/// Value-side mirror of [`ReduceMulSlice`].
pub trait MulModuloSlice<M, T> {
    /// `self[i] = self[i] * b[i] (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] * b[i] < modulus²`
    fn mul_modulo_slice_assign(&mut self, b: &[T], modulus: M);

    /// `output[i] = self[i] * b[i] (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == output.len()`
    /// - Each `self[i] * b[i] < modulus²`
    fn mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M);

    /// `self[i] = self[i] * scalar (mod modulus)` element-wise.
    ///
    /// # Correctness
    ///
    /// - `scalar < modulus`
    /// - Each `self[i] < modulus`
    fn mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M);

    /// `output[i] = self[i] * scalar (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - `scalar < modulus` and each `self[i] < modulus`
    fn mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M);
}

impl<T, M> MulModuloSlice<M, T> for [T]
where
    M: ReduceMulSlice<T>,
{
    #[inline(always)]
    fn mul_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.reduce_mul_slice_assign(self, b);
    }

    #[inline(always)]
    fn mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.reduce_mul_slice_to(self, b, output);
    }

    #[inline(always)]
    fn mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M) {
        modulus.reduce_mul_scalar_slice_assign(self, scalar);
    }

    #[inline(always)]
    fn mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M) {
        modulus.reduce_mul_scalar_slice_to(self, scalar, output);
    }
}

/// Value-side mirror of [`ReduceMulAddSlice`].
///
/// The receiver `self` plays the role of the accumulator or first
/// multiplicand depending on the method (see method docs).
pub trait MulAddModuloSlice<M, T> {
    /// `self[i] += a[i] * b[i] (mod modulus)` — FMAC accumulate.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len() == b.len()`
    /// - Each `self[i] < modulus`, `a[i] < modulus`, and `b[i] < modulus`
    fn add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// `self[i] -= a[i] * b[i] (mod modulus)` — fused multiply-subtract.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len() == b.len()`
    /// - Each `self[i] < modulus`, `a[i] < modulus`, and `b[i] < modulus`
    fn sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// `self[i] += a[i] * scalar (mod modulus)` — scalar FMAC accumulate.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len()`
    /// - `scalar < modulus`, each `self[i] < modulus`, and each `a[i] < modulus`
    fn add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M);

    /// `output[i] = self[i] * b[i] + c[i] (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == c.len() == output.len()`
    /// - Each `self[i] < modulus`, `b[i] < modulus`, and `c[i] < modulus`
    fn mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M);

    /// `output[i] = self[i] * scalar + c[i] (mod modulus)`.
    ///
    /// Note: `self` is the slice playing the role of `a` in the
    /// modulus-side `reduce_mul_scalar_add_slice_to(a, scalar, c, out)`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == c.len() == output.len()`
    /// - `scalar < modulus`, each `self[i] < modulus`, and each `c[i] < modulus`
    fn mul_scalar_add_modulo_slice_to(&self, scalar: T, c: &[T], output: &mut [T], modulus: M);
}

impl<T, M> MulAddModuloSlice<M, T> for [T]
where
    M: ReduceMulAddSlice<T>,
{
    #[inline(always)]
    fn add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.reduce_add_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.reduce_sub_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M) {
        modulus.reduce_add_mul_scalar_slice_assign(self, a, scalar);
    }

    #[inline(always)]
    fn mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M) {
        modulus.reduce_mul_add_slice_to(self, b, c, output);
    }

    #[inline(always)]
    fn mul_scalar_add_modulo_slice_to(&self, scalar: T, c: &[T], output: &mut [T], modulus: M) {
        modulus.reduce_mul_scalar_add_slice_to(self, scalar, c, output);
    }
}

/// Value-side mirror of [`ReduceInvSlice`].
pub trait InvModuloSlice<M> {
    /// `output[i] = self[i]^(-1) (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - Each `self[i] < modulus`
    /// - Each `self[i]` and `modulus` must be coprime
    ///
    /// # Panics
    ///
    /// Panics if any element has no inverse modulo `modulus`.
    fn inv_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> InvModuloSlice<M> for [T]
where
    M: ReduceInvSlice<T>,
{
    #[inline(always)]
    fn inv_modulo_slice_to(&self, output: &mut [T], modulus: M) {
        modulus.reduce_inv_slice_to(self, output);
    }
}

/// Value-side mirror of [`TryReduceInvSlice`].
pub trait TryInvModuloSlice<M, T>
where
    Self: AsRef<[T]>,
{
    /// Try to compute `output[i] = self[i]^(-1) (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self.as_ref().len() == output.len()`
    /// - Every value in `self` is less than `modulus`
    ///
    /// # Errors
    ///
    /// Returns an inverse-related [`ReduceError`](primus_reduce::ReduceError)
    /// if one or more values have no inverse. `output` may be modified when an
    /// error is returned.
    fn try_inv_modulo_slice_to(
        &self,
        output: &mut [T],
        modulus: M,
    ) -> Result<(), primus_reduce::ReduceError<T>>;
}

impl<T, M> TryInvModuloSlice<M, T> for [T]
where
    M: TryReduceInvSlice<T>,
{
    #[inline(always)]
    fn try_inv_modulo_slice_to(
        &self,
        output: &mut [T],
        modulus: M,
    ) -> Result<(), primus_reduce::ReduceError<T>> {
        modulus.try_reduce_inv_slice_to(self, output)
    }
}

/// Modular dot product of two slices.
pub trait DotProductModulo<M, T> {
    /// Calculates `∑ self[i] * b[i] (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    ///
    /// # Panics
    ///
    /// Panics if `self.len() != b.len()`.
    #[must_use]
    fn dot_product_modulo(&self, b: &[T], modulus: M) -> T;
}

impl<M, T> DotProductModulo<M, T> for [T]
where
    M: ReduceDotProduct<T>,
{
    #[inline(always)]
    fn dot_product_modulo(&self, b: &[T], modulus: M) -> T {
        modulus.reduce_dot_product(self, b)
    }
}

/// Modular dot product of two iterators.
pub trait DotProductModuloIter<M, T>
where
    Self: IntoIterator<Item = T>,
{
    /// Calculates `∑ a_i * b_i (mod modulus)` using standard `zip` semantics.
    ///
    /// # Correctness
    ///
    /// - Each `a_i < modulus` and `b_i < modulus`
    ///
    /// # Behavior
    ///
    /// If the iterators have different lengths, iteration stops at the shorter
    /// one.
    #[must_use]
    fn dot_product_modulo_iter<B>(self, b: B, modulus: M) -> T
    where
        B: IntoIterator<Item = T>;
}

impl<M, T, A> DotProductModuloIter<M, T> for A
where
    A: IntoIterator<Item = T>,
    M: ReduceDotProduct<T>,
{
    #[inline(always)]
    fn dot_product_modulo_iter<B>(self, b: B, modulus: M) -> T
    where
        B: IntoIterator<Item = T>,
    {
        modulus.reduce_dot_product_iter(self, b)
    }
}
