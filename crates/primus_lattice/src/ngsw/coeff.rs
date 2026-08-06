use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::ArrayBase;

#[allow(unused_imports)]
use crate::ntru::{Ntru, NtruIter, NtruIterMut};

use super::NttNgsw;

/// A GSW-style NTRU ciphertext in the coefficient domain.
///
/// For gadget scalars `v_0, ..., v_{L-1}`, an encryption of `beta` is
/// `NLEV_f[f * beta]`, whose level `i` is
/// `NTRU_f[v_i * f * beta] = g_i / f + v_i * beta`.
///
/// Although this has the same flat layout as an NLev ciphertext, it is a
/// distinct type because the encrypted phase and valid products differ.
///
/// ## Layout
///
/// ```text
/// |--ntru_level_0--| ... |--ntru_level_{L-1}--|
/// ```
#[derive(Clone)]
pub struct Ngsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Ngsw<S>);
impl_bytes_conversion!(Ngsw<S>);
impl_zero!(Ngsw<S>);
impl_iters!(Ngsw);
impl_iter_sub_structure!(Ngsw<S>, Ntru);
impl_basic_operation_single_modulus!(Ngsw<S>);
impl_ntt!(Ngsw<S>, NttNgsw);
