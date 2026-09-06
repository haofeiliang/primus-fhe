use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

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
/// where `c1` to `cd` are [`CrtGlwe`] with same parameter, `d` is the decompose length.
///
/// Arithmetic preserves every gadget level and its layout. Operands must use
/// matching ciphertext dimensions, gadget bases, level order, ordered RNS bases,
/// and key semantics. Scalar and factor multiplication applies the same RNS
/// scalar to every level and ciphertext component.
#[derive(Clone)]
pub struct CrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGlev);

impl_iters!(CrtGlev);
impl_iter_sub_structure!(CrtGlev, CrtGlwe);

impl_basic_operation_multiple_modulus!(CrtGlev);
impl_neg_multiple_modulus!(CrtGlev);
impl_mul_scalar_multiple_modulus!(CrtGlev);
impl_mul_factor_multiple_modulus!(CrtGlev);
impl_monomial_multiple_modulus!(CrtGlev);

impl_crt_ntt!(CrtGlev, DcrtGlev);
