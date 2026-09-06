use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

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

impl_ciphertext_core!(NttNlev);

impl_iters!(NttNlev);
impl_iter_sub_structure!(NttNlev, NttNtru);

impl_basic_operation_single_modulus!(NttNlev);
impl_mul_scalar_single_modulus!(NttNlev);
impl_mul_factor_single_modulus!(NttNlev);
impl_ntt_polynomial_mul!(NttNlev);

impl_intt!(NttNlev, Nlev);
