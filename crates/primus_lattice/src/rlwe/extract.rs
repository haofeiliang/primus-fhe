//! Sample extraction from coefficient-domain RLWE ciphertexts.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::{ReduceNeg, ReduceNegSlice};

use super::Rlwe;
use crate::lwe::{Lwe, MultiMsgLwe};

impl<T: FheUint> Rlwe<Vec<T>> {
    /// Extracts the constant coefficient, consuming and reusing the allocation.
    ///
    /// # Correctness
    ///
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    #[must_use]
    #[inline]
    pub fn into_lwe<M>(self, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        Lwe::new(self.into_multi_msg_lwe(1, modulus).0)
    }

    /// Packs the first `count` coefficients, consuming and reusing the allocation.
    /// The mask is converted to constant-term LWE extraction order.
    ///
    /// # Correctness
    ///
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    ///
    /// # Panics
    ///
    /// Panics if `count` exceeds the polynomial length.
    #[must_use]
    pub fn into_multi_msg_lwe<M>(self, count: usize, modulus: M) -> MultiMsgLwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mut data = self.0;
        let poly_len = data.len() / 2;

        assert!(
            count <= poly_len,
            "message count must not exceed polynomial length"
        );

        data.truncate(poly_len + count);

        data[1..poly_len].reverse();
        modulus.reduce_neg_slice_assign(&mut data[1..poly_len]);

        MultiMsgLwe::new(data)
    }
}

impl<S, T> Rlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Allocates an LWE sample for the constant coefficient.
    ///
    /// # Correctness
    ///
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    #[must_use]
    #[inline]
    pub fn extract_lwe<M>(&self, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        self.extract_lwe_at(0, modulus)
    }

    /// Allocates an LWE sample for coefficient `index`.
    /// Storage must contain two complete nonempty polynomials of equal length.
    ///
    /// # Correctness
    ///
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    ///
    /// # Panics
    ///
    /// Panics if `index` is outside the polynomial.
    #[must_use]
    #[inline]
    pub fn extract_lwe_at<M>(&self, index: usize, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        let (mask, body) = self.a_b_slices();
        assert!(index < mask.len(), "RLWE extraction index is out of range");
        let split = index + 1;
        let mut data = Vec::with_capacity(mask.len() + 1);
        data.extend(mask[..split].iter().rev().copied());
        data.extend(
            mask[split..]
                .iter()
                .rev()
                .map(|&value| modulus.reduce_neg(value)),
        );
        data.push(body[index]);
        Lwe::new(data)
    }

    /// Allocates a packed LWE containing the first `count` body coefficients.
    /// The mask is stored in constant-term LWE extraction order.
    ///
    /// # Correctness
    ///
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    ///
    /// # Panics
    ///
    /// Panics if `count` exceeds the polynomial length.
    #[must_use]
    #[inline]
    pub fn extract_multi_msg_lwe<M>(&self, count: usize, modulus: M) -> MultiMsgLwe<Vec<T>>
    where
        M: Copy + ReduceNeg<T, Output = T>,
    {
        let poly_len = self.0.len() / 2;
        let src = self.0.as_slice();

        assert!(
            count <= poly_len,
            "message count must not exceed polynomial length"
        );

        let mut data = Vec::with_capacity(poly_len + count);
        data.push(src[0]);
        data.extend(
            src[1..poly_len]
                .iter()
                .rev()
                .map(|&value| modulus.reduce_neg(value)),
        );
        data.extend_from_slice(&src[poly_len..poly_len + count]);

        MultiMsgLwe::new(data)
    }

    /// Extracts the constant coefficient into an existing LWE buffer.
    ///
    /// # Correctness
    ///
    /// Storage must contain two polynomials of the same nonzero length `N`.
    /// The output dimension must be `N`.
    /// The output phase equals the selected coefficient
    /// of `b - a*s`. Canonical inputs produce canonical outputs without allocation.
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    #[inline]
    pub fn extract_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let (mask, _) = self.a_b_slices();
        crate::glwe::Glwe(self.as_ref()).extract_lwe_to(output, mask.len(), modulus);
    }

    /// Extracts coefficient `index` into an existing LWE buffer.
    ///
    /// # Correctness
    ///
    /// Storage must contain two polynomials of the same nonzero length `N`.
    /// The output dimension must be `N`.
    /// `index` must belong to `[0, N)`. The output phase equals the selected coefficient
    /// of `b - a*s`. Canonical inputs produce canonical outputs without allocation.
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    #[inline]
    pub fn extract_lwe_at_to<M, A>(&self, index: usize, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let (mask, _) = self.a_b_slices();
        crate::glwe::Glwe(self.as_ref()).extract_lwe_at_to(index, output, mask.len(), modulus);
    }

    /// Extracts the constant coefficient into an existing LWE buffer.
    ///
    /// # Correctness
    ///
    /// Storage must contain two polynomials of the same nonzero length `N`.
    /// The output dimension must be in `1..=N`; the RLWE secret must have
    /// a zero suffix beyond that dimension.
    /// The output phase equals the selected coefficient
    /// of `b - a*s`. Canonical inputs produce canonical outputs without allocation.
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    /// Only a zero suffix of that secret may be omitted.
    #[inline]
    pub fn extract_compact_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let (mask, _) = self.a_b_slices();
        crate::glwe::Glwe(self.as_ref()).extract_compact_lwe_to(output, mask.len(), modulus);
    }

    /// Extracts coefficient `index` into an existing LWE buffer.
    ///
    /// # Correctness
    ///
    /// Storage must contain two polynomials of the same nonzero length `N`.
    /// The output dimension must be in `1..=N`; the RLWE secret must have
    /// a zero suffix beyond that dimension.
    /// `index` must belong to `[0, N)`. The output phase equals the selected coefficient
    /// of `b - a*s`. Canonical inputs produce canonical outputs without allocation.
    /// Input storage must contain exactly two nonempty length-`N` polynomials
    /// in coefficient form, with canonical values under `modulus`. The
    /// extracted LWE key is the coefficient vector of the RLWE secret.
    /// Only a zero suffix of that secret may be omitted.
    #[inline]
    pub fn extract_compact_lwe_at_to<M, A>(&self, index: usize, output: &mut Lwe<A>, modulus: M)
    where
        M: primus_reduce::RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let (mask, _) = self.a_b_slices();
        crate::glwe::Glwe(self.as_ref()).extract_compact_lwe_at_to(
            index,
            output,
            mask.len(),
            modulus,
        );
    }
}
