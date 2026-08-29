use primus_reduce::prelude::*;

/// The lazy modulo operation.
pub trait LazyModulo<M> {
    /// Output type.
    type Output;

    /// Calculates a representative congruent to `self` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// The supported input range is defined by the concrete [`LazyReduce`]
    /// implementation of `modulus`.
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`. It may be non-canonical and must be
    /// reduced once when a value in `[0, modulus)` is required.
    ///
    /// If the modulus type does not natively support lazy reduction,
    /// implementations should fall back to [`Modulo`](crate::ops::Modulo).
    #[must_use]
    fn lazy_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> LazyModulo<M> for T
where
    M: LazyReduce<T>,
{
    type Output = <M as LazyReduce<T>>::Output;

    #[inline(always)]
    fn lazy_modulo(self, modulus: M) -> Self::Output {
        modulus.lazy_reduce(self)
    }
}

/// The lazy modulo assignment operation.
pub trait LazyModuloAssign<M> {
    /// Replaces `self` with a representative congruent to it modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// The supported input range is defined by the concrete
    /// [`LazyReduceAssign`] implementation of `modulus`.
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`ModuloAssign`](crate::ops::ModuloAssign).
    fn lazy_modulo_assign(&mut self, modulus: M);
}

impl<T, M> LazyModuloAssign<M> for T
where
    M: LazyReduceAssign<T>,
{
    #[inline(always)]
    fn lazy_modulo_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_assign(self)
    }
}

/// The lazy modular multiplication.
pub trait LazyMulModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `self * b` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self * b < modulus²`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`MulModulo`](crate::ops::MulModulo).
    #[must_use]
    fn lazy_mul_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> LazyMulModulo<M> for T
where
    M: LazyReduceMul<T>,
{
    type Output = <M as LazyReduceMul<T>>::Output;

    #[inline(always)]
    fn lazy_mul_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.lazy_reduce_mul(self, b)
    }
}

/// The lazy modular multiplication assignment.
pub trait LazyMulModuloAssign<M>: Sized {
    /// Replaces `self` with a lazy representative of `self * b` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self * b < modulus²`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`MulModuloAssign`](crate::ops::MulModuloAssign).
    fn lazy_mul_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> LazyMulModuloAssign<M> for T
where
    M: LazyReduceMulAssign<T>,
{
    #[inline(always)]
    fn lazy_mul_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.lazy_reduce_mul_assign(self, b)
    }
}

/// The lazy modular multiply-add.
pub trait LazyMulAddModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `self * b + c` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`MulAddModulo`](crate::ops::MulAddModulo).
    #[must_use]
    fn lazy_mul_add_modulo(self, b: Self, c: Self, modulus: M) -> Self::Output;
}

impl<T, M> LazyMulAddModulo<M> for T
where
    M: LazyReduceMulAdd<T>,
{
    type Output = <M as LazyReduceMulAdd<T>>::Output;

    #[inline(always)]
    fn lazy_mul_add_modulo(self, b: T, c: T, modulus: M) -> Self::Output {
        modulus.lazy_reduce_mul_add(self, b, c)
    }
}

/// The lazy modular multiply-add assignment.
pub trait LazyMulAddModuloAssign<M>: Sized {
    /// Replaces `self` with a lazy representative of `self * b + c` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`MulAddModuloAssign`](crate::ops::MulAddModuloAssign).
    fn lazy_mul_add_modulo_assign(&mut self, b: Self, c: Self, modulus: M);
}

impl<T, M> LazyMulAddModuloAssign<M> for T
where
    M: LazyReduceMulAddAssign<T>,
{
    #[inline(always)]
    fn lazy_mul_add_modulo_assign(&mut self, b: T, c: T, modulus: M) {
        modulus.lazy_reduce_mul_add_assign(self, b, c)
    }
}

/// The lazy modular subtraction.
pub trait LazySubModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `self - b` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`SubModulo`](crate::ops::SubModulo).
    #[must_use]
    fn lazy_sub_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> LazySubModulo<M> for T
where
    M: LazyReduceSub<T>,
{
    type Output = <M as LazyReduceSub<T>>::Output;

    #[inline(always)]
    fn lazy_sub_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.lazy_reduce_sub(self, b)
    }
}

/// The lazy modular subtraction assignment.
pub trait LazySubModuloAssign<M>: Sized {
    /// Replaces `self` with a lazy representative of `self - b` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`SubModuloAssign`](crate::ops::SubModuloAssign).
    fn lazy_sub_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> LazySubModuloAssign<M> for T
where
    M: LazyReduceSubAssign<T>,
{
    #[inline(always)]
    fn lazy_sub_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.lazy_reduce_sub_assign(self, b)
    }
}

/// The lazy modular negation.
pub trait LazyNegModulo<M> {
    /// Output type.
    type Output;

    /// Calculates a lazy representative of `-self` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`NegModulo`](crate::ops::NegModulo).
    #[must_use]
    fn lazy_neg_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> LazyNegModulo<M> for T
where
    M: LazyReduceNeg<T>,
{
    type Output = <M as LazyReduceNeg<T>>::Output;

    #[inline(always)]
    fn lazy_neg_modulo(self, modulus: M) -> Self::Output {
        modulus.lazy_reduce_neg(self)
    }
}

/// The lazy modular negation assignment.
pub trait LazyNegModuloAssign<M> {
    /// Replaces `self` with a lazy representative of `-self` modulo `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    ///
    /// # Guarantees
    ///
    /// The result is in `[0, 2 * modulus)`.
    ///
    /// Implementations without a specialized lazy kernel may fall back to
    /// [`NegModuloAssign`](crate::ops::NegModuloAssign).
    fn lazy_neg_modulo_assign(&mut self, modulus: M);
}

impl<T, M> LazyNegModuloAssign<M> for T
where
    M: LazyReduceNegAssign<T>,
{
    #[inline(always)]
    fn lazy_neg_modulo_assign(&mut self, modulus: M) {
        modulus.lazy_reduce_neg_assign(self)
    }
}
