use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::glev::{DcrtGlev, DcrtGlevIter, DcrtGlevIterMut};

use super::CrtGgsw;

/// Represents a ciphertext in the General-GSW homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--ck--|--c[k+1]--|
///
/// where `c1` to `c[k+1]` are [`crate::glev::DcrtGlev`] with same parameter, `k` is the dimension.
#[derive(Clone)]
pub struct DcrtGgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtGgsw);

impl_iters!(DcrtGgsw);
impl_iter_sub_structure!(DcrtGgsw, DcrtGlev);

impl_basic_operation_multiple_modulus!(DcrtGgsw);

impl_crt_intt!(DcrtGgsw, CrtGgsw);
