use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlwe::{CrtRlwe, CrtRlweIter, CrtRlweIterMut};

use super::DcrtRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::CrtRlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct CrtRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtRlev);

impl_iters!(CrtRlev);
impl_iter_sub_structure!(CrtRlev, CrtRlwe);

impl_basic_operation_multiple_modulus!(CrtRlev);
impl_mul_scalar_multiple_modulus!(CrtRlev);
impl_mul_factor_multiple_modulus!(CrtRlev);
impl_add_mul_monomial_multiple_modulus!(CrtRlev);

impl_crt_ntt!(CrtRlev, DcrtRlev);
