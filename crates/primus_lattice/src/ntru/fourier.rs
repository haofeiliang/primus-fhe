use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};
use primus_poly::FourierPolynomial;

#[allow(unused_imports)]
use super::Ntru;

/// A scalar NTRU ciphertext represented by independent complex evaluations.
///
/// One negacyclic polynomial of length `N` occupies `N / 2` complex values.
#[derive(Clone)]
pub struct FourierNtru<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierNtru);

impl_fourier_iters!(FourierNtru);

impl_fourier_basic_operation!(FourierNtru);

impl_fourier_conversion!(Ntru, FourierNtru);

impl<S> FourierNtru<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Multiplies this ciphertext by a Fourier-domain plaintext polynomial.
    #[inline]
    pub fn mul_fourier_polynomial_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        FourierPolynomial(self.as_mut()).mul_assign(rhs);
    }
}

impl<S> FourierNtru<S>
where
    S: Data<Elem = Complex64>,
{
    /// Writes the pointwise product of this ciphertext and a Fourier
    /// plaintext polynomial to `output`.
    #[inline]
    pub fn mul_fourier_polynomial_to<A, B>(
        &self,
        rhs: &FourierPolynomial<A>,
        output: &mut FourierNtru<B>,
    ) where
        A: Data<Elem = Complex64>,
        B: DataMut<Elem = Complex64>,
    {
        FourierPolynomial(self.as_ref()).mul_to(rhs, &mut FourierPolynomial(output.as_mut()));
    }
}
