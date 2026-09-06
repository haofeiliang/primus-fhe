use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlev::{NttRlev, NttRlevIter, NttRlevIterMut};

use super::Rgsw;

/// Represents a ciphertext in the Ring-GSW (Ring Learning With Errors) homomorphic encryption scheme.
///
/// ## Structure of the `data`
///
/// `|--c1--|--c2--|`
///
/// Both rows are RLev ciphertexts with identical parameters. The underlying
/// GLWE dimension is exactly one.
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
pub struct NttRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttRgsw);

impl_iters!(NttRgsw);
impl_iter_sub_structure!(NttRgsw, NttRlev);

impl_basic_operation_single_modulus!(NttRgsw);
impl_neg_single_modulus!(NttRgsw);
impl_mul_scalar_single_modulus!(NttRgsw);
impl_mul_factor_single_modulus!(NttRgsw);
impl_gadget_diagonal_single_modulus!(NttRgsw, NttPolynomial, 1);
impl_ntt_polynomial_mul!(NttRgsw);

impl_intt!(NttRgsw, Rgsw);
