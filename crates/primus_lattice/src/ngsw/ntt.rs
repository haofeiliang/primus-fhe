use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

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

impl_ciphertext_core!(NttNgsw);

impl_iters!(NttNgsw);
impl_iter_sub_structure!(NttNgsw, NttNtru);

impl_basic_operation_single_modulus!(NttNgsw);
impl_neg_single_modulus!(NttNgsw);
impl_mul_scalar_single_modulus!(NttNgsw);
impl_mul_factor_single_modulus!(NttNgsw);
impl_ntt_polynomial_mul!(NttNgsw);

impl_intt!(NttNgsw, Ngsw);
