use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

#[allow(unused_imports)]
use crate::glwe::{CrtGlwe, CrtGlweIter, CrtGlweIterMut};

use super::DcrtGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::CrtGlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct CrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGlev);

impl_iters!(CrtGlev);
impl_iter_sub_structure!(CrtGlev, CrtGlwe);

impl_basic_operation_multiple_modulus!(CrtGlev);

impl_crt_ntt!(CrtGlev, DcrtGlev);
