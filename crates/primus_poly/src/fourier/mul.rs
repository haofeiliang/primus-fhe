use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Multiplies this Fourier polynomial pointwise by `rhs`.
    #[inline]
    pub fn mul_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        debug_assert_eq!(self.0.len(), rhs.0.len());
        for (value, rhs) in self.0.iter_mut().zip(rhs.0.iter()) {
            *value *= *rhs;
        }
    }

    /// Multiplies pointwise by `rhs` and returns this Fourier polynomial.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn mul<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: Data<Elem = Complex64>,
    {
        self.mul_assign(rhs);
        self
    }

    /// Multiplies every Fourier value by the real scalar `scalar` in place.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: f64) {
        for value in self.0.iter_mut() {
            *value *= scalar;
        }
    }

    /// Multiplies every Fourier value by the real scalar `scalar` and returns
    /// this Fourier polynomial.
    #[inline]
    pub fn mul_scalar(mut self, scalar: f64) -> Self {
        self.mul_scalar_assign(scalar);
        self
    }

    /// Accumulates the pointwise product `lhs * rhs` into this polynomial.
    #[inline]
    pub fn add_mul_assign<A, B>(&mut self, lhs: &FourierPolynomial<A>, rhs: &FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: Data<Elem = Complex64>,
    {
        debug_assert_eq!(self.0.len(), lhs.0.len());
        debug_assert_eq!(self.0.len(), rhs.0.len());
        for ((value, lhs), rhs) in self.0.iter_mut().zip(lhs.0.iter()).zip(rhs.0.iter()) {
            *value += *lhs * *rhs;
        }
    }
}

impl<S> FourierPolynomial<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes the pointwise product `self * rhs` to `output`.
    #[inline]
    pub fn mul_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(self.0.len(), rhs.0.len());
        debug_assert_eq!(self.0.len(), output.0.len());
        for ((output, lhs), rhs) in output.0.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *output = *lhs * *rhs;
        }
    }

    /// Writes the real scalar product `self * scalar` to `output`.
    #[inline]
    pub fn mul_scalar_to<A>(&self, scalar: f64, output: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(self.0.len(), output.0.len());
        for (output, value) in output.0.iter_mut().zip(self.0.iter()) {
            *output = *value * scalar;
        }
    }
}
