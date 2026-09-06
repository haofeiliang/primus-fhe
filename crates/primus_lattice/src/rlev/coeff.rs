use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlwe::{Rlwe, RlweIter, RlweIterMut};

use super::NttRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::Rlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct Rlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Rlev);

impl_iters!(Rlev);
impl_iter_sub_structure!(Rlev, Rlwe);

impl_basic_operation_single_modulus!(Rlev);
impl_mul_scalar_single_modulus!(Rlev);
impl_mul_factor_single_modulus!(Rlev);
impl_add_mul_monomial_single_modulus!(Rlev);

impl_ntt!(Rlev, NttRlev);
