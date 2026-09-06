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

impl_fourier_iters!(FourierNtru);
impl_fourier_core!(FourierNtru);
impl_fourier_forward!(Ntru, FourierNtru);
impl_fourier_backward!(FourierNtru, Ntru);

impl<S> FourierNtru<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Adds another Fourier NTRU ciphertext pointwise.
    #[inline]
    pub fn add_assign<A>(&mut self, rhs: &FourierNtru<A>)
    where
        A: Data<Elem = Complex64>,
    {
        FourierPolynomial(self.as_mut()).add_assign(&FourierPolynomial(rhs.as_ref()));
    }

    /// Subtracts another Fourier NTRU ciphertext pointwise.
    #[inline]
    pub fn sub_assign<A>(&mut self, rhs: &FourierNtru<A>)
    where
        A: Data<Elem = Complex64>,
    {
        FourierPolynomial(self.as_mut()).sub_assign(&FourierPolynomial(rhs.as_ref()));
    }

    /// Negates this Fourier NTRU ciphertext pointwise.
    #[inline]
    pub fn neg_assign(&mut self) {
        FourierPolynomial(self.as_mut()).neg_assign();
    }

    /// Multiplies this ciphertext by a real scalar.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: f64) {
        FourierPolynomial(self.as_mut()).mul_scalar_assign(scalar);
    }

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
