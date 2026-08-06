use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;

#[allow(unused_imports)]
use crate::ntru::{Ntru, NtruIter, NtruIterMut};

use super::NttNlev;

/// A gadget-decomposed NTRU ciphertext in the coefficient domain.
///
/// For gadget scalars `v_0, ..., v_{L-1}`, an encryption of `beta` is
/// `(NTRU_f[v_i * beta])_{i in [L]}`.
///
/// ## Layout
///
/// ```text
/// |--ntru_level_0--| ... |--ntru_level_{L-1}--|
/// ```
///
/// Each level contains one coefficient-domain [`Ntru`] polynomial.
#[derive(Clone)]
pub struct Nlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Nlev<S>);
impl_bytes_conversion!(Nlev<S>);
impl_zero!(Nlev<S>);
impl_iters!(Nlev);
impl_iter_sub_structure!(Nlev<S>, Ntru);
impl_basic_operation_single_modulus!(Nlev<S>);
impl_ntt!(Nlev<S>, NttNlev);
