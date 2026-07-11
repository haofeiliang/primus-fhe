use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Negates every value in this Fourier polynomial.
    #[inline]
    pub fn neg_assign(&mut self) {
        for value in self.0.iter_mut() {
            *value = -*value;
        }
    }

    /// Negates every value and returns this Fourier polynomial.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn neg(mut self) -> Self {
        self.neg_assign();
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Writes the pointwise negation of `self` to `output`.
    #[inline]
    pub fn neg_to<A>(&self, output: &mut FourierPolynomial<A>)
    where
        A: RawData<Elem = Complex64> + DataMut,
    {
        assert_eq!(self.0.len(), output.0.len());
        for (output, value) in output.0.iter_mut().zip(self.0.iter()) {
            *output = -*value;
        }
    }
}
