use itertools::izip;
use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_reduce::ReduceInvSlice;

use super::DcrtPolynomial;

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Writes the point-wise inverse of each modulus component to `output`.
    ///
    /// # Correctness
    ///
    /// - `poly_length` is nonzero
    /// - Input and output storage have the same length and are both divisible
    ///   by `poly_length`
    /// - `moduli.len()` equals the number of modulus components
    ///
    /// # Panics
    ///
    /// Panics if any value has no inverse modulo its component modulus.
    #[inline]
    pub fn inv_to<M, A>(&self, output: &mut DcrtPolynomial<A>, poly_length: usize, moduli: &[M])
    where
        M: Copy + ReduceInvSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        debug_assert_eq!(self.dcrt_poly_length(), output.dcrt_poly_length());

        izip!(
            self.iter_each_modulus(poly_length),
            output.iter_each_modulus_mut(poly_length),
            moduli
        )
        .for_each(|(poly, out, &modulus)| modulus.reduce_inv_slice_to(poly, out));
    }
}
