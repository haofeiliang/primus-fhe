use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;

#[allow(unused_imports)]
use crate::ntru::{NttNtru, NttNtruIter, NttNtruIterMut};

use super::Nlev;

/// An NTT-domain [`Nlev`] ciphertext.
///
/// The data is a flat list of NTT-domain NTRU polynomials, one per gadget
/// decomposition level.
#[derive(Clone)]
pub struct NttNlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttNlev<S>);
impl_bytes_conversion!(NttNlev<S>);
impl_zero!(NttNlev<S>);
impl_iters!(NttNlev);
impl_iter_sub_structure!(NttNlev<S>, NttNtru);
impl_basic_operation_single_modulus!(NttNlev<S>);
impl_intt!(NttNlev<S>, Nlev);
