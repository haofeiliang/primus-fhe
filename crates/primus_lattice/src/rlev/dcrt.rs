use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlwe::{DcrtRlwe, DcrtRlweIter, DcrtRlweIterMut};

use super::CrtRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::DcrtRlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct DcrtRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRlev);

impl_iters!(DcrtRlev);
impl_iter_sub_structure!(DcrtRlev, DcrtRlwe);

impl_basic_operation_multiple_modulus!(DcrtRlev);
impl_mul_scalar_multiple_modulus!(DcrtRlev);
impl_mul_factor_multiple_modulus!(DcrtRlev);

impl_crt_intt!(DcrtRlev, CrtRlev);
