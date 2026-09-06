use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlev::{DcrtRlev, DcrtRlevIter, DcrtRlevIterMut};

use super::CrtRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`DcrtRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct DcrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRgsw);

impl_iters!(DcrtRgsw);
impl_iter_sub_structure!(DcrtRgsw, DcrtRlev);

impl_basic_operation_multiple_modulus!(DcrtRgsw);
impl_mul_scalar_multiple_modulus!(DcrtRgsw);
impl_mul_factor_multiple_modulus!(DcrtRgsw);
impl_dcrt_polynomial_mul!(DcrtRgsw);

impl_crt_intt!(DcrtRgsw, CrtRgsw);
