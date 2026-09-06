use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;

#[allow(unused_imports)]
use crate::glwe::{Glwe, GlweIter, GlweIterMut};

use super::NttGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::Glwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct Glev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Glev<S>);
impl_bytes_conversion!(Glev<S>);
impl_zero!(Glev<S>);
impl_iters!(Glev);
impl_iter_sub_structure!(Glev<S>, Glwe);
impl_basic_operation_single_modulus!(Glev<S>);
impl_ntt!(Glev<S>, NttGlev);

impl<S, T> Glev<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Multiplies every coefficient of every gadget level by `scalar` in place.
    ///
    /// Coefficients and `scalar` must satisfy the input ranges required by `modulus`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: primus_reduce::ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
    }
}
