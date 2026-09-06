use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceNegSlice;

use crate::{
    GlweSize,
    lwe::{Lwe, MultiMsgLwe},
};

/// A coefficient-domain GLWE ciphertext whose body stores only its first
/// coefficients.
///
/// The layout is `|--a_1--| ... |--a_k--|--b[..message_count]--|`. Each mask
/// polynomial has the full polynomial length, while the truncated body keeps
/// one coefficient per packed message.
#[derive(Clone)]
pub struct TruncatedGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(TruncatedGlwe);

impl_basic_operation_single_modulus!(TruncatedGlwe);
impl_mul_scalar_single_modulus!(TruncatedGlwe);
impl_mul_factor_single_modulus!(TruncatedGlwe);

impl<T> TruncatedGlwe<Vec<T>>
where
    T: FheUint,
{
    /// Extracts the first encrypted coefficient as an LWE ciphertext.
    #[inline]
    pub fn extract_lwe_locally<M>(self, size: GlweSize, modulus: M) -> Lwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let mask_len = size.mask_len();
        let poly_length = size.poly_length();
        let mut data = self.0;

        data.truncate(mask_len + 1);
        for mask in data[..mask_len].chunks_exact_mut(poly_length) {
            mask[1..].reverse();
            modulus.reduce_neg_slice_assign(&mut mask[1..]);
        }

        Lwe::new(data)
    }

    /// Extracts the retained coefficients as a packed multi-message LWE
    /// ciphertext.
    ///
    /// Requires GLWE dimension one (RLWE), since [`MultiMsgLwe`] rotates its
    /// entire mask as one polynomial when extracting subsequent messages.
    ///
    /// # Panics
    ///
    /// Panics if `size.dimension() != 1` or `count` exceeds the number of
    /// retained body coefficients.
    pub fn extract_first_few_lwe_locally<M>(
        self,
        count: usize,
        size: GlweSize,
        modulus: M,
    ) -> MultiMsgLwe<Vec<T>>
    where
        M: Copy + ReduceNegSlice<T>,
    {
        assert_eq!(
            size.dimension(),
            1,
            "packed multi-message LWE extraction requires GLWE dimension 1"
        );
        let mask_len = size.mask_len();
        let poly_length = size.poly_length();
        let message_count = self.message_count(size);
        let mut data = self.0;

        assert!(count <= message_count);
        data.truncate(mask_len + count);
        for mask in data[..mask_len].chunks_exact_mut(poly_length) {
            mask[1..].reverse();
            modulus.reduce_neg_slice_assign(&mut mask[1..]);
        }

        MultiMsgLwe::new(data)
    }
}

impl<S, T> TruncatedGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Returns the mask and retained body coefficients.
    #[inline]
    pub fn a_b_slices(&self, size: GlweSize) -> (&[T], &[T]) {
        self.0.split_at(size.mask_len())
    }

    /// Returns the number of retained body coefficients.
    #[inline]
    pub fn message_count(&self, size: GlweSize) -> usize {
        self.as_ref()
            .len()
            .checked_sub(size.mask_len())
            .expect("truncated GLWE ciphertext is shorter than its mask")
    }
}
