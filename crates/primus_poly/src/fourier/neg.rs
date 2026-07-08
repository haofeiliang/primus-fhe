use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataMut,
{
    /// Performs the unary `-` operation (pointwise complex negation).
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn neg(mut self) -> Self {
        self.neg_assign();
        self
    }

    /// Performs the unary `-` operation in place.
    #[inline]
    pub fn neg_assign(&mut self) {
        let len = 2 * self.fourier_length();
        let a = &mut self.0.as_mut_slice()[..len];
        #[cfg(target_arch = "x86_64")]
        {
            if *super::constants::HAS_AVX512F {
                unsafe {
                    super::simd::avx512::neg_assign(a, len);
                    return;
                }
            }
            if *super::constants::HAS_AVX2_FMA {
                unsafe {
                    super::simd::avx2::neg_assign(a, len);
                    return;
                }
            }
        }
        for x in a {
            *x = -*x;
        }
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// Performs `output = -self` (pointwise complex negation).
    #[inline]
    pub fn neg_to<A>(&self, output: &mut FourierPolynomial<A>)
    where
        A: RawData<Elem = f64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        for (&a, out) in self.iter().zip(output.iter_mut()) {
            *out = -a;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fourier::FourierPolynomialOwned;

    #[test]
    fn test_neg_assign() {
        // [re=1, re=-3, im=2, im=0] → length=2 logically
        let mut a = FourierPolynomialOwned::from_slice(&[1.0, -3.0, 2.0, 0.0]);
        a.neg_assign();
        assert_eq!(a.as_slice(), &[-1.0, 3.0, -2.0, 0.0]);
    }

    #[test]
    fn test_neg_to() {
        let a = FourierPolynomialOwned::from_slice(&[1.0, 0.0, -1.0, 2.0]);
        let mut output = FourierPolynomialOwned::zero(2);
        a.neg_to(&mut output);
        assert_eq!(output.as_slice(), &[-1.0, 0.0, 1.0, -2.0]);
    }
}
