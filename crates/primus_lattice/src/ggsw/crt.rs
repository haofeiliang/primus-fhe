use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::ArrayBase;
use primus_reduce::FieldContext;

#[allow(unused_imports)]
use crate::glev::{CrtGlev, CrtGlevIter, CrtGlevIterMut};

use super::DcrtGgsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::glev::CrtGlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct CrtGgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGgsw);

impl_iters!(CrtGgsw);
impl_iter_sub_structure!(CrtGgsw, CrtGlev);

impl_basic_operation_multiple_modulus!(CrtGgsw);

impl_crt_ntt!(CrtGgsw, DcrtGgsw);
