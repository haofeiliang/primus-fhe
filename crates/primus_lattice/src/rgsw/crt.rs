use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlev::{CrtRlev, CrtRlevIter, CrtRlevIterMut};

use super::DcrtRgsw;

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
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct CrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtRgsw);

impl_iters!(CrtRgsw);
impl_iter_sub_structure!(CrtRgsw, CrtRlev);

impl_basic_operation_multiple_modulus!(CrtRgsw);
impl_neg_multiple_modulus!(CrtRgsw);
impl_mul_scalar_multiple_modulus!(CrtRgsw);
impl_mul_factor_multiple_modulus!(CrtRgsw);
impl_monomial_multiple_modulus!(CrtRgsw);
impl_gadget_diagonal_multiple_modulus!(CrtRgsw, CrtPolynomial, 1);

impl_crt_ntt!(CrtRgsw, DcrtRgsw);
