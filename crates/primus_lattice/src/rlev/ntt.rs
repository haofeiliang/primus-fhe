use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlwe::{NttRlwe, NttRlweIter, NttRlweIterMut};

use super::Rlev;

/// A representation of Ring Learning with Errors (RLWE) ciphertexts at different levels of one gadget basis,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::rlwe::NttRlwe`] with same parameter, `d` is the decompose length.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct NttRlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttRlev);

impl_iters!(NttRlev);
impl_iter_sub_structure!(NttRlev, NttRlwe);

impl_basic_operation_single_modulus!(NttRlev);
impl_neg_single_modulus!(NttRlev);
impl_mul_scalar_single_modulus!(NttRlev);
impl_mul_factor_single_modulus!(NttRlev);
impl_ntt_polynomial_mul!(NttRlev);

impl_intt!(NttRlev, Rlev);
