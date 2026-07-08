use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataMut,
{
    /// `self += rhs` (pointwise addition in place).
    #[inline]
    pub fn add_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: RawData<Elem = f64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        let len = 2 * self.fourier_length();
        let a = &mut self.0.as_mut_slice()[..len];
        let b = &rhs.0.as_slice()[..len];
        #[cfg(target_arch = "x86_64")]
        {
            if *super::constants::HAS_AVX512F {
                unsafe {
                    super::simd::avx512::add_assign(a, b, len);
                    return;
                }
            }
            if *super::constants::HAS_AVX2_FMA {
                unsafe {
                    super::simd::avx2::add_assign(a, b, len);
                    return;
                }
            }
        }
        for (x, &y) in a.iter_mut().zip(b) {
            *x += y;
        }
    }

    /// `self + rhs` (owning).
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: RawData<Elem = f64> + Data,
    {
        self.add_assign(rhs);
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// `output = self + rhs`.
    #[inline]
    pub fn add_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: RawData<Elem = f64> + Data,
        B: RawData<Elem = f64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        for ((&a, &b), out) in self.iter().zip(rhs.iter()).zip(output.iter_mut()) {
            *out = a + b;
        }
    }
}
