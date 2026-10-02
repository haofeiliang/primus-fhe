use num_complex::Complex64;
use primus_data::{Data, DataMut};

use super::{FourierPolynomial, FourierPolynomialMut, FourierPolynomialRef};

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
        mul_assign_kernel(self.as_mut_view(), rhs.as_view());
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
        mul_scalar_assign_kernel(self.as_mut_view(), scalar);
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
        add_mul_assign_kernel(self.as_mut_view(), lhs.as_view(), rhs.as_view());
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
        mul_to_kernel(self.as_view(), rhs.as_view(), output.as_mut_view());
    }

    /// Writes the real scalar product `self * scalar` to `output`.
    #[inline]
    pub fn mul_scalar_to<A>(&self, scalar: f64, output: &mut FourierPolynomial<A>)
    where
        A: DataMut<Elem = Complex64>,
    {
        mul_scalar_to_kernel(self.as_view(), scalar, output.as_mut_view());
    }
}

#[inline]
fn mul_assign_kernel(mut acc: FourierPolynomialMut<'_>, rhs: FourierPolynomialRef<'_>) {
    debug_assert_eq!(acc.fourier_length(), rhs.fourier_length());
    for (value, rhs) in acc.iter_mut().zip(rhs.iter()) {
        *value *= *rhs;
    }
}

#[inline]
fn mul_scalar_assign_kernel(mut acc: FourierPolynomialMut<'_>, scalar: f64) {
    for value in acc.iter_mut() {
        *value *= scalar;
    }
}

// Preserve the order of complex multiplication followed by accumulation.
// Values are already in the Fourier domain and need no additional normalization.
#[inline]
fn add_mul_assign_kernel(
    mut acc: FourierPolynomialMut<'_>,
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
) {
    debug_assert_eq!(acc.fourier_length(), lhs.fourier_length());
    debug_assert_eq!(acc.fourier_length(), rhs.fourier_length());
    for ((value, lhs), rhs) in acc.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *value += *lhs * *rhs;
    }
}

#[inline]
fn mul_to_kernel(
    lhs: FourierPolynomialRef<'_>,
    rhs: FourierPolynomialRef<'_>,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(lhs.fourier_length(), rhs.fourier_length());
    debug_assert_eq!(lhs.fourier_length(), output.fourier_length());
    for ((output, lhs), rhs) in output.iter_mut().zip(lhs.iter()).zip(rhs.iter()) {
        *output = *lhs * *rhs;
    }
}

#[inline]
fn mul_scalar_to_kernel(
    input: FourierPolynomialRef<'_>,
    scalar: f64,
    mut output: FourierPolynomialMut<'_>,
) {
    debug_assert_eq!(input.fourier_length(), output.fourier_length());
    for (output, value) in output.iter_mut().zip(input.iter()) {
        *output = *value * scalar;
    }
}
