use primus_integer::UnsignedInteger;
use primus_reduce::ReduceError;
use primus_reduce::prelude::*;

/// The modulo operation.
pub trait Modulo<M> {
    /// Output type.
    type Output;

    /// Calculates `self (mod modulus)`.
    fn modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> Modulo<M> for T
where
    M: Reduce<T>,
{
    type Output = <M as Reduce<T>>::Output;

    #[inline(always)]
    fn modulo(self, modulus: M) -> Self::Output {
        modulus.reduce(self)
    }
}

/// The modulo assignment operation.
pub trait ModuloAssign<M> {
    /// Calculates `self = self (mod modulus)`.
    fn modulo_assign(&mut self, modulus: M);
}

impl<T, M> ModuloAssign<M> for T
where
    M: ReduceAssign<T>,
{
    #[inline(always)]
    fn modulo_assign(&mut self, modulus: M) {
        modulus.reduce_assign(self)
    }
}

/// A single-correction modular reduction.
pub trait ModuloOnce<M> {
    /// Output type.
    type Output;

    /// Calculates `self - modulus` if `self >= modulus`.
    fn modulo_once(self, modulus: M) -> Self::Output;
}

impl<T, M> ModuloOnce<M> for T
where
    M: ReduceOnce<T>,
{
    type Output = <M as ReduceOnce<T>>::Output;

    #[inline(always)]
    fn modulo_once(self, modulus: M) -> Self::Output {
        modulus.reduce_once(self)
    }
}

/// In-place single-correction modular reduction.
pub trait ModuloOnceAssign<M> {
    /// Calculates `self -= modulus` if `self >= modulus`.
    fn modulo_once_assign(&mut self, modulus: M);
}

impl<T, M> ModuloOnceAssign<M> for T
where
    M: ReduceOnceAssign<T>,
{
    #[inline(always)]
    fn modulo_once_assign(&mut self, modulus: M) {
        modulus.reduce_once_assign(self)
    }
}

/// The modular addition.
pub trait AddModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates `self + b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn add_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> AddModulo<M> for T
where
    M: ReduceAdd<T>,
{
    type Output = <M as ReduceAdd<T>>::Output;

    #[inline(always)]
    fn add_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.reduce_add(self, b)
    }
}

/// The modular addition assignment.
pub trait AddModuloAssign<M>: Sized {
    /// Calculates `self += b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn add_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> AddModuloAssign<M> for T
where
    M: ReduceAddAssign<T>,
{
    #[inline(always)]
    fn add_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.reduce_add_assign(self, b)
    }
}

/// The modular double.
pub trait DoubleModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `2*self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn double_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> DoubleModulo<M> for T
where
    M: ReduceDouble<T>,
{
    type Output = <M as ReduceDouble<T>>::Output;

    #[inline(always)]
    fn double_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_double(self)
    }
}

/// The modular double assignment.
pub trait DoubleModuloAssign<M> {
    /// Calculates `self = 2*self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn double_modulo_assign(&mut self, modulus: M);
}

impl<T, M> DoubleModuloAssign<M> for T
where
    M: ReduceDoubleAssign<T>,
{
    #[inline(always)]
    fn double_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_double_assign(self)
    }
}

/// The modular subtraction.
pub trait SubModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates `self - b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn sub_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> SubModulo<M> for T
where
    M: ReduceSub<T>,
{
    type Output = <M as ReduceSub<T>>::Output;

    #[inline(always)]
    fn sub_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.reduce_sub(self, b)
    }
}

/// The modular subtraction assignment.
pub trait SubModuloAssign<M>: Sized {
    /// Calculates `self -= b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    fn sub_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> SubModuloAssign<M> for T
where
    M: ReduceSubAssign<T>,
{
    #[inline(always)]
    fn sub_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.reduce_sub_assign(self, b)
    }
}

/// The modular negation.
pub trait NegModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `-self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> NegModulo<M> for T
where
    M: ReduceNeg<T>,
{
    type Output = <M as ReduceNeg<T>>::Output;

    #[inline(always)]
    fn neg_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_neg(self)
    }
}

/// The modular negation assignment.
pub trait NegModuloAssign<M> {
    /// Calculates `-self (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn neg_modulo_assign(&mut self, modulus: M);
}

impl<T, M> NegModuloAssign<M> for T
where
    M: ReduceNegAssign<T>,
{
    #[inline(always)]
    fn neg_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_neg_assign(self)
    }
}

/// The modular multiplication.
pub trait MulModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates `self * b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*b < modulus²`
    fn mul_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> MulModulo<M> for T
where
    M: ReduceMul<T>,
{
    type Output = <M as ReduceMul<T>>::Output;

    #[inline(always)]
    fn mul_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.reduce_mul(self, b)
    }
}

/// The modular multiplication assignment.
pub trait MulModuloAssign<M>: Sized {
    /// Calculates `self *= b (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self*b < modulus²`
    fn mul_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> MulModuloAssign<M> for T
where
    M: ReduceMulAssign<T>,
{
    #[inline(always)]
    fn mul_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.reduce_mul_assign(self, b)
    }
}

/// The modular square.
pub trait SquareModulo<M> {
    /// Output type.
    type Output;

    /// Calculates `self² (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn square_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> SquareModulo<M> for T
where
    M: ReduceSquare<T>,
{
    type Output = <M as ReduceSquare<T>>::Output;

    #[inline(always)]
    fn square_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_square(self)
    }
}

/// The modular square assignment.
pub trait SquareModuloAssign<M> {
    /// Calculates `self = self² (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    fn square_modulo_assign(&mut self, modulus: M);
}

impl<T, M> SquareModuloAssign<M> for T
where
    M: ReduceSquareAssign<T>,
{
    #[inline(always)]
    fn square_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_square_assign(self)
    }
}

/// The modular multiply-add.
pub trait MulAddModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates `(self * b) + c (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    fn mul_add_modulo(self, b: Self, c: Self, modulus: M) -> Self::Output;
}

impl<T, M> MulAddModulo<M> for T
where
    M: ReduceMulAdd<T>,
{
    type Output = <M as ReduceMulAdd<T>>::Output;

    #[inline(always)]
    fn mul_add_modulo(self, b: T, c: T, modulus: M) -> Self::Output {
        modulus.reduce_mul_add(self, b, c)
    }
}

/// The modular multiply-add assignment.
pub trait MulAddModuloAssign<M>: Sized {
    /// Calculates `(self * b) + c (mod modulus)`.
    ///
    /// # Correctness
    ///
    /// - `self < modulus`
    /// - `b < modulus`
    /// - `c < modulus`
    fn mul_add_modulo_assign(&mut self, b: Self, c: Self, modulus: M);
}

impl<T, M> MulAddModuloAssign<M> for T
where
    M: ReduceMulAddAssign<T>,
{
    #[inline(always)]
    fn mul_add_modulo_assign(&mut self, b: T, c: T, modulus: M) {
        modulus.reduce_mul_add_assign(self, b, c)
    }
}

/// Modular multiplicative inversion.
pub trait InvModulo<M> {
    /// Output type.
    type Output;

    /// Calculate the multiplicative inverse of `self (mod modulus)`.
    fn inv_modulo(self, modulus: M) -> Self::Output;
}

impl<T, M> InvModulo<M> for T
where
    M: ReduceInv<T>,
{
    type Output = <M as ReduceInv<T>>::Output;

    #[inline(always)]
    fn inv_modulo(self, modulus: M) -> Self::Output {
        modulus.reduce_inv(self)
    }
}

/// In-place modular multiplicative inversion.
pub trait InvModuloAssign<M> {
    /// Calculates `self^(-1) (mod modulus)`.
    fn inv_modulo_assign(&mut self, modulus: M);
}

impl<T, M> InvModuloAssign<M> for T
where
    M: ReduceInvAssign<T>,
{
    #[inline(always)]
    fn inv_modulo_assign(&mut self, modulus: M) {
        modulus.reduce_inv_assign(self)
    }
}

/// Fallible modular multiplicative inversion.
pub trait TryInvModulo<M>
where
    Self: Sized,
{
    /// Output type.
    type Output;

    /// Attempts to calculate the multiplicative inverse of `self` modulo
    /// `modulus`.
    ///
    /// # Preconditions
    ///
    /// - `self < modulus`
    ///
    /// # Errors
    ///
    /// If there does not exist such an inverse, a [`ReduceError`] will be returned.
    fn try_inv_modulo(self, modulus: M) -> Result<Self::Output, ReduceError<Self>>;
}

impl<T, M> TryInvModulo<M> for T
where
    M: TryReduceInv<T>,
{
    type Output = <M as TryReduceInv<T>>::Output;

    #[inline(always)]
    fn try_inv_modulo(self, modulus: M) -> Result<Self::Output, ReduceError<Self>> {
        modulus.try_reduce_inv(self)
    }
}

/// The modular division.
pub trait DivModulo<M>: Sized {
    /// Output type.
    type Output;

    /// Calculates `self / b (mod modulus)`.
    fn div_modulo(self, b: Self, modulus: M) -> Self::Output;
}

impl<T, M> DivModulo<M> for T
where
    M: ReduceDiv<T>,
{
    type Output = <M as ReduceDiv<T>>::Output;

    #[inline(always)]
    fn div_modulo(self, b: T, modulus: M) -> Self::Output {
        modulus.reduce_div(self, b)
    }
}

/// The modular division assignment.
pub trait DivModuloAssign<M>: Sized {
    /// Calculates `self /= b (mod modulus)`.
    fn div_modulo_assign(&mut self, b: Self, modulus: M);
}

impl<T, M> DivModuloAssign<M> for T
where
    M: ReduceDivAssign<T>,
{
    #[inline(always)]
    fn div_modulo_assign(&mut self, b: T, modulus: M) {
        modulus.reduce_div_assign(self, b)
    }
}

/// The modular exponentiation.
pub trait ExpModulo<M> {
    /// Calculates `self^exp (mod modulus)`.
    fn exp_modulo<Exponent: UnsignedInteger>(self, exp: Exponent, modulus: M) -> Self;
}

impl<T, M> ExpModulo<M> for T
where
    M: ReduceExp<T>,
{
    #[inline(always)]
    fn exp_modulo<Exponent: UnsignedInteger>(self, exp: Exponent, modulus: M) -> Self {
        modulus.reduce_exp(self, exp)
    }
}

/// The modular power-of-two exponentiation.
pub trait ExpPowerOf2Modulo<M> {
    /// Calculates `self^(2^exp_log) (mod modulus)`.
    fn exp_power_of_2_modulo(self, exp_log: u32, modulus: M) -> Self;
}

impl<T, M> ExpPowerOf2Modulo<M> for T
where
    M: ReduceExpPowerOf2<T>,
{
    #[inline(always)]
    fn exp_power_of_2_modulo(self, exp_log: u32, modulus: M) -> Self {
        modulus.reduce_exp_power_of_2(self, exp_log)
    }
}
