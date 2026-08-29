//! Value-side mirror of `primus_reduce::lazy_slice_ops`.
//!
//! Results remain congruent modulo `modulus` and lie in `[0, 2 * modulus)`.
//! Callers must perform a final reduction, for example via
//! [`crate::slice_ops::OnceModuloSlice`], when a canonical representative is
//! required.
//! Implementations may diagnose shape mismatches only with `debug_assert*!`;
//! release callers must uphold each method's documented length requirements.

use primus_reduce::prelude::*;

/// Value-side mirror of [`LazyReduceMulSlice`].
pub trait LazyMulModuloSlice<M, T> {
    /// Replaces each value with a lazy representative of `self[i] * b[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_modulo_slice_assign(&mut self, b: &[T], modulus: M);

    /// Writes lazy representatives of `self[i] * b[i]` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == output.len()`
    /// - Each `self[i] * b[i] < modulus²`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M);

    /// Replaces each value with a lazy representative of `self[i] * scalar`.
    ///
    /// # Correctness
    ///
    /// - `scalar < modulus`
    /// - Each `self[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M);

    /// Writes lazy representatives of `self[i] * scalar` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - `scalar < modulus` and each `self[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M);
}

impl<T, M> LazyMulModuloSlice<M, T> for [T]
where
    M: LazyReduceMulSlice<T>,
{
    #[inline(always)]
    fn lazy_mul_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.lazy_reduce_mul_slice_assign(self, b);
    }

    #[inline(always)]
    fn lazy_mul_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_slice_to(self, b, output);
    }

    #[inline(always)]
    fn lazy_mul_scalar_modulo_slice_assign(&mut self, scalar: T, modulus: M) {
        modulus.lazy_reduce_mul_scalar_slice_assign(self, scalar);
    }

    #[inline(always)]
    fn lazy_mul_scalar_modulo_slice_to(&self, scalar: T, output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_scalar_slice_to(self, scalar, output);
    }
}

/// Value-side mirror of [`LazyReduceMulAddSlice`].
pub trait LazyMulAddModuloSlice<M, T> {
    /// Replaces each value with a lazy representative of `self[i] + a[i] * b[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len() == b.len()`
    /// - Each `self[i] < modulus`, `a[i] < modulus`, and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// Replaces each value with a lazy representative of `self[i] - a[i] * b[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len() == b.len()`
    /// - Each `self[i] < modulus`, `a[i] < modulus`, and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M);

    /// Replaces each value with a lazy representative of `self[i] + a[i] * scalar`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == a.len()`
    /// - `scalar < modulus`, each `self[i] < modulus`, and each `a[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M);

    /// Writes lazy representatives of `self[i] * b[i] + c[i]` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == c.len() == output.len()`
    /// - Each `self[i] < modulus`, `b[i] < modulus`, and `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M);

    /// Writes lazy representatives of `self[i] * scalar + c[i]` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == c.len() == output.len()`
    /// - `scalar < modulus`, each `self[i] < modulus`, and each `c[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_mul_scalar_add_modulo_slice_to(&self, scalar: T, c: &[T], output: &mut [T], modulus: M);
}

impl<T, M> LazyMulAddModuloSlice<M, T> for [T]
where
    M: LazyReduceMulAddSlice<T>,
{
    #[inline(always)]
    fn lazy_add_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.lazy_reduce_add_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn lazy_sub_mul_modulo_slice_assign(&mut self, a: &[T], b: &[T], modulus: M) {
        modulus.lazy_reduce_sub_mul_slice_assign(self, a, b);
    }

    #[inline(always)]
    fn lazy_add_mul_scalar_modulo_slice_assign(&mut self, a: &[T], scalar: T, modulus: M) {
        modulus.lazy_reduce_add_mul_scalar_slice_assign(self, a, scalar);
    }

    #[inline(always)]
    fn lazy_mul_add_modulo_slice_to(&self, b: &[T], c: &[T], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_mul_add_slice_to(self, b, c, output);
    }

    #[inline(always)]
    fn lazy_mul_scalar_add_modulo_slice_to(
        &self,
        scalar: T,
        c: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        modulus.lazy_reduce_mul_scalar_add_slice_to(self, scalar, c, output);
    }
}

/// Value-side mirror of [`LazyReduceSubSlice`].
pub trait LazySubModuloSlice<M> {
    /// Replaces each value with a lazy representative of `self[i] - b[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_sub_modulo_slice_assign(&mut self, b: &Self, modulus: M);

    /// Writes lazy representatives of `self[i] - b[i]` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len() == output.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_sub_modulo_slice_to(&self, b: &Self, output: &mut Self, modulus: M);

    /// Replaces `b[i]` with a lazy representative of `self[i] - b[i]`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == b.len()`
    /// - Each `self[i] < modulus` and `b[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_sub_modulo_slice_rev_assign(&self, b: &mut Self, modulus: M);
}

impl<T, M> LazySubModuloSlice<M> for [T]
where
    M: LazyReduceSubSlice<T>,
{
    #[inline(always)]
    fn lazy_sub_modulo_slice_assign(&mut self, b: &[T], modulus: M) {
        modulus.lazy_reduce_sub_slice_assign(self, b);
    }

    #[inline(always)]
    fn lazy_sub_modulo_slice_to(&self, b: &[T], output: &mut [T], modulus: M) {
        modulus.lazy_reduce_sub_slice_to(self, b, output);
    }

    #[inline(always)]
    fn lazy_sub_modulo_slice_rev_assign(&self, b: &mut [T], modulus: M) {
        modulus.lazy_reduce_sub_slice_rev_assign(self, b);
    }
}

/// Value-side mirror of [`LazyReduceNegSlice`].
pub trait LazyNegModuloSlice<M> {
    /// Replaces each value with a lazy representative of its negation.
    ///
    /// # Correctness
    ///
    /// - Each `self[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_neg_modulo_slice_assign(&mut self, modulus: M);

    /// Writes lazy representatives of `-self[i]` to `output`.
    ///
    /// # Correctness
    ///
    /// - `self.len() == output.len()`
    /// - Each `self[i] < modulus`
    /// - Each result is in `[0, 2 * modulus)`
    fn lazy_neg_modulo_slice_to(&self, output: &mut Self, modulus: M);
}

impl<T, M> LazyNegModuloSlice<M> for [T]
where
    M: LazyReduceNegSlice<T>,
{
    #[inline(always)]
    fn lazy_neg_modulo_slice_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_neg_slice_assign(self);
    }

    #[inline(always)]
    fn lazy_neg_modulo_slice_to(&self, output: &mut [T], modulus: M) {
        modulus.lazy_reduce_neg_slice_to(self, output);
    }
}
