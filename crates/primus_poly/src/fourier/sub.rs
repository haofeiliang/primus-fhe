use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Subtracts `rhs` pointwise from this Fourier polynomial.
    #[inline]
    pub fn sub_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        assert_eq!(self.0.len(), rhs.0.len());
        for (value, rhs) in self.0.iter_mut().zip(rhs.0.iter()) {
            *value -= *rhs;
        }
    }

    /// Subtracts `rhs` pointwise and returns this Fourier polynomial.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn sub<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: Data<Elem = Complex64>,
    {
        self.sub_assign(rhs);
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Replaces `rhs` with the pointwise difference `self - rhs`.
    #[inline]
    pub fn sub_rev_assign<A>(&self, rhs: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        assert_eq!(self.0.len(), rhs.0.len());
        for (rhs, lhs) in rhs.0.iter_mut().zip(self.0.iter()) {
            *rhs = *lhs - *rhs;
        }
    }

    /// Writes the pointwise difference `self - rhs` to `output`.
    #[inline]
    pub fn sub_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        assert_eq!(self.0.len(), rhs.0.len());
        assert_eq!(self.0.len(), output.0.len());
        for ((output, lhs), rhs) in output.0.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *output = *lhs - *rhs;
        }
    }
}
