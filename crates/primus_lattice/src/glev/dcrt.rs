use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

#[allow(unused_imports)]
use crate::glwe::{DcrtGlwe, DcrtGlweIter, DcrtGlweIterMut};

use super::CrtGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::DcrtGlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct DcrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtGlev);

impl_iters!(DcrtGlev);
impl_iter_sub_structure!(DcrtGlev, DcrtGlwe);

impl_basic_operation_multiple_modulus!(DcrtGlev);

impl_crt_intt!(DcrtGlev, CrtGlev);
