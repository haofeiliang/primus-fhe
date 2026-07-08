use primus_data::{Data, DataMut, RawData};

use super::FourierPolynomial;

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + DataMut,
{
    /// `self *= rhs` (pointwise complex multiplication in place).
    #[inline]
    pub fn mul_assign<A>(&mut self, rhs: &FourierPolynomial<A>)
    where
        A: RawData<Elem = f64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        let m = self.fourier_length();
        let (re, im) = self.0.as_mut_slice().split_at_mut(m);
        let (r_re, r_im) = rhs.0.as_slice().split_at(m);
        for (((re, im), &rre), &rim) in re
            .iter_mut()
            .zip(im.iter_mut())
            .zip(r_re.iter())
            .zip(r_im.iter())
        {
            let a_re = *re;
            let a_im = *im;
            *re = a_re * rre - a_im * rim;
            *im = a_re * rim + a_im * rre;
        }
    }

    /// `self += lhs * rhs` (fused multiply-add) in place — hot path.
    #[inline]
    pub fn add_mul_assign<A, B>(&mut self, lhs: &FourierPolynomial<A>, rhs: &FourierPolynomial<B>)
    where
        A: RawData<Elem = f64> + Data,
        B: RawData<Elem = f64> + Data,
    {
        debug_assert_eq!(self.fourier_length(), lhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        let m = self.fourier_length();
        let (acc_re, acc_im) = self.0.as_mut_slice().split_at_mut(m);
        let (l_re, l_im) = lhs.0.as_slice().split_at(m);
        let (r_re, r_im) = rhs.0.as_slice().split_at(m);

        #[cfg(target_arch = "x86_64")]
        {
            if *super::constants::HAS_AVX512F {
                unsafe {
                    super::simd::avx512::add_mul_assign(acc_re, acc_im, l_re, l_im, r_re, r_im, m);
                    return;
                }
            }
            if *super::constants::HAS_AVX2_FMA {
                unsafe {
                    super::simd::avx2::add_mul_assign(acc_re, acc_im, l_re, l_im, r_re, r_im, m);
                    return;
                }
            }
        }
        // scalar fallback
        for i in 0..m {
            acc_re[i] += l_re[i] * r_re[i] - l_im[i] * r_im[i];
            acc_im[i] += l_re[i] * r_im[i] + l_im[i] * r_re[i];
        }
    }

    /// `self *= rhs` (owning).
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn mul<A>(mut self, rhs: &FourierPolynomial<A>) -> Self
    where
        A: RawData<Elem = f64> + Data,
    {
        self.mul_assign(rhs);
        self
    }
}

impl<S> FourierPolynomial<S>
where
    S: RawData<Elem = f64> + Data,
{
    /// `output = self * rhs` (pointwise complex multiplication).
    #[inline]
    pub fn mul_to<A, B>(&self, rhs: &FourierPolynomial<A>, output: &mut FourierPolynomial<B>)
    where
        A: RawData<Elem = f64> + Data,
        B: RawData<Elem = f64> + DataMut,
    {
        debug_assert_eq!(self.fourier_length(), rhs.fourier_length());
        debug_assert_eq!(self.fourier_length(), output.fourier_length());
        let m = self.fourier_length();
        let (a_re, a_im) = self.0.as_slice().split_at(m);
        let (b_re, b_im) = rhs.0.as_slice().split_at(m);
        let (out_re, out_im) = output.0.as_mut_slice().split_at_mut(m);

        #[cfg(target_arch = "x86_64")]
        {
            if *super::constants::HAS_AVX512F {
                unsafe {
                    super::simd::avx512::mul_to(a_re, a_im, b_re, b_im, out_re, out_im, m);
                    return;
                }
            }
            if *super::constants::HAS_AVX2_FMA {
                unsafe {
                    super::simd::avx2::mul_to(a_re, a_im, b_re, b_im, out_re, out_im, m);
                    return;
                }
            }
        }
        for i in 0..m {
            out_re[i] = a_re[i] * b_re[i] - a_im[i] * b_im[i];
            out_im[i] = a_re[i] * b_im[i] + a_im[i] * b_re[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fourier::FourierPolynomialOwned;

    fn make(data: &[f64]) -> FourierPolynomialOwned {
        FourierPolynomialOwned::from_slice(data)
    }

    #[test]
    fn test_mul_assign() {
        // a = [2, i]  →  [2, 0, 0, 1]
        let a = make(&[2.0, 0.0, 0.0, 1.0]);
        // b = [3, 1]  →  [3, 1, 0, 0]
        let b = make(&[3.0, 1.0, 0.0, 0.0]);
        let mut result = a;
        result.mul_assign(&b);
        // (2)*(3) = 6, (i)*(1) = i
        assert_eq!(result.as_slice(), &[6.0, 0.0, 0.0, 1.0]);
    }

    #[test]
    fn test_add_mul_assign() {
        // acc = [1, 1] → [1, 1, 0, 0]
        let mut acc = make(&[1.0, 1.0, 0.0, 0.0]);
        // lhs = [2, i] → [2, 0, 0, 1]
        let lhs = make(&[2.0, 0.0, 0.0, 1.0]);
        // rhs = [3, 1] → [3, 1, 0, 0]
        let rhs = make(&[3.0, 1.0, 0.0, 0.0]);
        // acc += lhs * rhs: [1+6, 1+i] = [7, 1+1i] → [7, 0, 1, 1]
        acc.add_mul_assign(&lhs, &rhs);
        assert_eq!(acc.as_slice(), &[7.0, 1.0, 0.0, 1.0]);
    }

    #[test]
    fn test_mul_to() {
        let a = make(&[2.0, 0.0, 0.0, 1.0]);
        let b = make(&[3.0, 1.0, 0.0, 0.0]);
        let mut output = FourierPolynomialOwned::zero(2);
        a.mul_to(&b, &mut output);
        assert_eq!(output.as_slice(), &[6.0, 0.0, 0.0, 1.0]);
    }
}
