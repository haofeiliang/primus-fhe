use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;

#[allow(unused_imports)]
use crate::ntru::{NttNtru, NttNtruIter, NttNtruIterMut};

use super::Ngsw;

/// An NTT-domain [`Ngsw`] ciphertext.
///
/// The data is a flat list of NTT-domain NTRU polynomials, one per gadget
/// decomposition level.
#[derive(Clone)]
pub struct NttNgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttNgsw<S>);
impl_bytes_conversion!(NttNgsw<S>);
impl_zero!(NttNgsw<S>);
impl_iters!(NttNgsw);
impl_iter_sub_structure!(NttNgsw<S>, NttNtru);
impl_basic_operation_single_modulus!(NttNgsw<S>);
impl_intt!(NttNgsw<S>, Ngsw);
