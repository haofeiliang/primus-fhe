use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;

#[allow(unused_imports)]
use crate::rlev::{Rlev, RlevIter, RlevIterMut};

use super::NttRgsw;

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
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct Rgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Rgsw);

impl_iters!(Rgsw);
impl_iter_sub_structure!(Rgsw, Rlev);

impl_basic_operation_single_modulus!(Rgsw);
impl_neg_single_modulus!(Rgsw);
impl_mul_scalar_single_modulus!(Rgsw);
impl_mul_factor_single_modulus!(Rgsw);
impl_monomial_single_modulus!(Rgsw);
impl_gadget_diagonal_single_modulus!(Rgsw, Polynomial, 1);

impl_ntt!(Rgsw, NttRgsw);
