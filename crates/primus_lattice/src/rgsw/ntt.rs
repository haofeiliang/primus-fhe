use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlev::{NttRlev, NttRlevIter, NttRlevIterMut};

use super::Rgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`NttRlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct NttRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttRgsw);

impl_iters!(NttRgsw);
impl_iter_sub_structure!(NttRgsw, NttRlev);

impl_basic_operation_single_modulus!(NttRgsw);
impl_mul_scalar_single_modulus!(NttRgsw);
impl_mul_factor_single_modulus!(NttRgsw);

impl_intt!(NttRgsw, Rgsw);
