use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlev::{CrtRlev, CrtRlevIter, CrtRlevIterMut};

use super::DcrtRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`CrtRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct CrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtRgsw);

impl_iters!(CrtRgsw);
impl_iter_sub_structure!(CrtRgsw, CrtRlev);

impl_basic_operation_multiple_modulus!(CrtRgsw);
impl_mul_scalar_multiple_modulus!(CrtRgsw);
impl_mul_factor_multiple_modulus!(CrtRgsw);
impl_add_mul_monomial_multiple_modulus!(CrtRgsw);

impl_crt_ntt!(CrtRgsw, DcrtRgsw);
