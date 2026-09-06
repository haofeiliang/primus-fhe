use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::glev::{Glev, GlevIter, GlevIterMut};

use super::NttGgsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`Glev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct Ggsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Ggsw);

impl_iters!(Ggsw);
impl_iter_sub_structure!(Ggsw, Glev);

impl_basic_operation_single_modulus!(Ggsw);
impl_mul_scalar_single_modulus!(Ggsw);
impl_mul_factor_single_modulus!(Ggsw);

impl_ntt!(Ggsw, NttGgsw);
