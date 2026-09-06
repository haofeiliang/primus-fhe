use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

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
/// where `c1` to `cd` are [`Glwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct Glev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Glev);

impl_iters!(Glev);
impl_iter_sub_structure!(Glev, Glwe);

impl_basic_operation_single_modulus!(Glev);
impl_mul_scalar_single_modulus!(Glev);
impl_mul_factor_single_modulus!(Glev);
impl_add_mul_monomial_single_modulus!(Glev);

impl_ntt!(Glev, NttGlev);
