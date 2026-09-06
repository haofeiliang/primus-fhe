use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlwe::{DcrtRlwe, DcrtRlweIter, DcrtRlweIterMut};

use super::CrtRlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts at different levels of one gadget basis,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::DcrtRlwe`] with same parameter, `d` is the decompose length.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct DcrtRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRlev);

impl_iters!(DcrtRlev);
impl_iter_sub_structure!(DcrtRlev, DcrtRlwe);

impl_basic_operation_multiple_modulus!(DcrtRlev);
impl_neg_multiple_modulus!(DcrtRlev);
impl_mul_scalar_multiple_modulus!(DcrtRlev);
impl_mul_factor_multiple_modulus!(DcrtRlev);
impl_dcrt_polynomial_mul!(DcrtRlev);

impl_crt_intt!(DcrtRlev, CrtRlev);
