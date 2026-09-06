use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlev::{Rlev, RlevIter, RlevIterMut};

use super::NttRgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`Rlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct Rgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Rgsw);

impl_iters!(Rgsw);
impl_iter_sub_structure!(Rgsw, Rlev);

impl_basic_operation_single_modulus!(Rgsw);

impl_ntt!(Rgsw, NttRgsw);
