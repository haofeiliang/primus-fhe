use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceInvSlice;

use super::NttPolynomial;

impl<S, T> NttPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs the point-wise inverse in the NTT domain.
    ///
    /// # Correctness
    ///
    /// `output.poly_length()` must equal `self.poly_length()`.
    ///
    /// # Panics
    ///
    /// Panics if any value has no inverse modulo `modulus`.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut NttPolynomial<A>, modulus: M)
    where
        M: Copy + ReduceInvSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_inv_slice_to(self.as_slice(), output.as_mut_slice());
    }
}
