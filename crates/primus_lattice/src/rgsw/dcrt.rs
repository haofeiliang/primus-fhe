use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;

#[allow(unused_imports)]
use crate::rlev::{DcrtRlev, DcrtRlevIter, DcrtRlevIterMut};

use super::CrtRgsw;

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
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct DcrtRgsw<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRgsw);

impl_iters!(DcrtRgsw);
impl_iter_sub_structure!(DcrtRgsw, DcrtRlev);

impl_basic_operation_multiple_modulus!(DcrtRgsw);
impl_neg_multiple_modulus!(DcrtRgsw);
impl_mul_scalar_multiple_modulus!(DcrtRgsw);
impl_mul_factor_multiple_modulus!(DcrtRgsw);
impl_gadget_diagonal_multiple_modulus!(DcrtRgsw, DcrtPolynomial, 1);
impl_dcrt_polynomial_mul!(DcrtRgsw);

impl_crt_intt!(DcrtRgsw, CrtRgsw);
