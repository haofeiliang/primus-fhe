use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
#[allow(unused_imports)]
use primus_poly::{BigUintPolynomial, BigUintPolynomialIter, BigUintPolynomialIterMut};
#[cfg(feature = "rns")]
use primus_reduce::FieldContext;
#[cfg(feature = "rns")]
use primus_rns::RNSBase;

#[cfg(feature = "rns")]
use super::CrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::BigUintPolynomial`] with same poly length, `k` is the dimension.
///
/// Coefficients are stored consecutively, each as a fixed-width sequence
/// of little-endian limbs. All coefficients use the same limb width.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
#[derive(Clone)]
pub struct BigUintGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(BigUintGlwe);

impl_iters!(BigUintGlwe);
impl_iter_sub_structure!(BigUintGlwe, BigUintPolynomial, big_uint_poly);

#[cfg(feature = "rns")]
impl<S, T> BigUintGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Composes the CRT representation in `crt_glwe` into this BigUint GLWE.
    ///
    /// # Correctness
    ///
    /// Let `N = poly_length`, `m = rns_base.moduli_count()`, and
    /// `w = rns_base.big_uint_value_len()`. Require `N > 0` and
    /// `crt_poly_len = N * m`. Each BigUint polynomial contains `N * w`
    /// limbs, grouped by coefficient in little-endian limb order; each CRT
    /// polynomial contains `m` length-`N` blocks in the base's modulus order.
    /// Both ciphertexts must contain the same number of complete polynomials.
    /// The destination is overwritten; complete ciphertext lengths and base order are caller obligations. CRT input residues must be canonical.
    /// `compose_buffer` must contain exactly `m` elements and is initialized
    /// by recomposition. Each composed coefficient is the representative in `[0, Q)`,
    /// where `Q` is the product of the RNS moduli.
    ///
    /// # Panics
    ///
    /// Panics when a zero-length polynomial chunk is used. For each processed
    /// polynomial, the RNS backend also checks its CRT and BigUint buffer
    /// lengths and the compose-buffer length.
    #[inline]
    pub fn compose_assign<A, M>(
        &mut self,
        crt_glwe: &CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        rns_base: &RNSBase<T, M>,
        compose_buffer: &mut [T],
    ) where
        A: Data<Elem = T>,
        M: FieldContext<T>,
    {
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = poly_length * big_uint_value_len;

        self.iter_big_uint_poly_mut(big_uint_poly_len)
            .zip(crt_glwe.iter_crt_poly(crt_poly_len))
            .for_each(|(mut big_uint_poly, crt_poly)| {
                rns_base.compose_polynomial_to(
                    &crt_poly,
                    &mut big_uint_poly,
                    poly_length,
                    compose_buffer,
                );
            });
    }
}

#[cfg(feature = "rns")]
impl<S, T> BigUintGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Reduces each BigUint coefficient into the ordered CRT base.
    ///
    /// # Correctness
    ///
    /// Let `N = poly_length`, `m = rns_base.moduli_count()`, and
    /// `w = rns_base.big_uint_value_len()`. Require `N > 0` and
    /// `crt_poly_len = N * m`. Each BigUint polynomial contains `N * w`
    /// limbs, grouped by coefficient in little-endian limb order; each CRT
    /// polynomial contains `m` length-`N` blocks in the base's modulus order.
    /// Both ciphertexts must contain the same number of complete polynomials.
    /// The destination is overwritten; complete ciphertext lengths and base order are caller obligations.
    ///
    /// # Panics
    ///
    /// Panics when a zero-length polynomial chunk is used. For each processed
    /// polynomial, the RNS backend also checks its CRT and BigUint buffer
    /// lengths.
    #[inline]
    pub fn decompose_to<A, M>(
        &self,
        output: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        rns_base: &RNSBase<T, M>,
    ) where
        A: DataMut<Elem = T>,
        M: FieldContext<T>,
    {
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = poly_length * big_uint_value_len;

        self.iter_big_uint_poly(big_uint_poly_len)
            .zip(output.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(big_uint_poly, mut crt_poly)| {
                rns_base.decompose_polynomial_to(&big_uint_poly, &mut crt_poly, poly_length);
            });
    }
}
