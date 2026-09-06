use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
#[cfg(doc)]
use primus_poly::DcrtPolynomial;
use primus_poly::{DcrtPolynomialIter, DcrtPolynomialIterMut};

use super::CrtRlwe;

/// An owned DCRT-domain RLWE sample backed by a [`Vec<T>`].
pub type DcrtRlweOwned<T> = DcrtRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`primus_poly::DcrtPolynomial`] with same poly length and moduli count.
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
#[derive(Clone)]
pub struct DcrtRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtRlwe);

impl_iters!(DcrtRlwe);
impl_iter_sub_structure!(DcrtRlwe, DcrtPolynomial, dcrt_poly);
impl_rlwe_accessors!(DcrtRlwe, DcrtPolynomial);

impl_basic_operation_multiple_modulus!(DcrtRlwe);
impl_neg_multiple_modulus!(DcrtRlwe);
impl_mul_scalar_multiple_modulus!(DcrtRlwe);
impl_mul_factor_multiple_modulus!(DcrtRlwe);
impl_plaintext_multiple_modulus!(DcrtRlwe, DcrtPolynomial);
impl_dcrt_polynomial_mul!(DcrtRlwe);

impl_crt_intt!(DcrtRlwe, CrtRlwe);
