use primus_data::{Data, DataMut, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{
    ReduceMul, ReduceMulAdd, ReduceMulAddSlice, ReduceMulSlice, ReduceNegSlice, ReduceSubAssign,
    RingContext,
};

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Performs `self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor<F>(mut self, factor: F, modulus: T) -> Self
    where
        F: FactorSliceOps<T>,
    {
        self.mul_factor_assign(factor, modulus);
        self
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &Polynomial<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
    }

    /// Performs `self *= factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        factor.factor_mul_slice_assign(self.as_mut(), modulus)
    }

    /// Performs `self += factor * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &Polynomial<A>, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + Data,
    {
        factor.add_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
    }

    /// Multiplies `self` by the monomial `X^r` in the ring `Z_modulus[X]/(X^N + 1)`, in place.
    pub fn mul_monomial_assign<M>(&mut self, r: usize, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let poly_length = self.poly_length();

        if r < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[0..r]);
            };

            rotate(self.as_mut_slice(), modulus)
        } else {
            debug_assert!(r < poly_length * 2);
            let r = r - poly_length;

            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[r..]);
            };

            rotate(self.as_mut_slice(), modulus)
        }
    }
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Multiplies `self` by `X^exponent` in `Z_q[X]/(X^N + 1)` and writes the result.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    #[inline]
    pub fn mul_monomial_to<M, A>(&self, exponent: usize, output: &mut Polynomial<A>, modulus: M)
    where
        M: RingContext<T>,
        A: RawData<Elem = T> + DataMut,
    {
        self.monomial_to::<false, M, A>(exponent, output, modulus);
    }

    /// Computes `output = self * (X^exponent - 1)` in `Z_q[X]/(X^N + 1)`.
    ///
    /// `exponent` must belong to `[0, 2N)`. Rotation and subtraction are
    /// fused into one coefficient pass.
    #[inline]
    pub fn mul_monomial_sub_one_to<M, A>(
        &self,
        exponent: usize,
        output: &mut Polynomial<A>,
        modulus: M,
    ) where
        M: RingContext<T>,
        A: RawData<Elem = T> + DataMut,
    {
        self.monomial_to::<true, M, A>(exponent, output, modulus);
    }

    #[inline]
    fn monomial_to<const SUBTRACT_SELF: bool, M, A>(
        &self,
        exponent: usize,
        output: &mut Polynomial<A>,
        modulus: M,
    ) where
        M: RingContext<T>,
        A: RawData<Elem = T> + DataMut,
    {
        let input = self.as_ref();
        let output = output.as_mut();
        let poly_length = input.len();

        debug_assert!(poly_length > 0 && poly_length.is_power_of_two());
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(output.len(), poly_length);

        let shift = exponent & (poly_length - 1);
        let negate_rotation = exponent >= poly_length;
        let tail_len = poly_length - shift;

        if SUBTRACT_SELF {
            if negate_rotation {
                for destination in 0..shift {
                    output[destination] =
                        modulus.reduce_sub(input[tail_len + destination], input[destination]);
                }
                for destination in shift..poly_length {
                    output[destination] = modulus.reduce_sub(
                        modulus.reduce_neg(input[destination - shift]),
                        input[destination],
                    );
                }
            } else {
                for destination in 0..shift {
                    output[destination] = modulus.reduce_sub(
                        modulus.reduce_neg(input[tail_len + destination]),
                        input[destination],
                    );
                }
                for destination in shift..poly_length {
                    output[destination] =
                        modulus.reduce_sub(input[destination - shift], input[destination]);
                }
            }
        } else {
            output[..shift].copy_from_slice(&input[tail_len..]);
            output[shift..].copy_from_slice(&input[..tail_len]);
            if negate_rotation {
                modulus.reduce_neg_slice_assign(&mut output[shift..]);
            } else {
                modulus.reduce_neg_slice_assign(&mut output[..shift]);
            }
        }
    }

    /// Performs a naive negacyclic multiplication and overwrites `output`.
    pub fn naive_mul_to<M, A, B>(&self, rhs: &Polynomial<A>, output: &mut Polynomial<B>, modulus: M)
    where
        M: Copy + ReduceSubAssign<T> + ReduceMul<T, Output = T> + ReduceMulAdd<T, Output = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let a: &[T] = self.as_ref();
        let b: &[T] = rhs.as_ref();
        let c: &mut [T] = output.as_mut();

        let coeff_count = a.len();
        debug_assert_eq!(coeff_count, b.len());
        debug_assert_eq!(coeff_count, c.len());

        if coeff_count == 0 {
            return;
        }

        for i in 0..coeff_count {
            c[i] = modulus.reduce_mul(a[0], b[i]);
            for j in 1..=i {
                c[i] = modulus.reduce_mul_add(a[j], b[i - j], c[i]);
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                modulus.reduce_sub_assign(&mut c[k], modulus.reduce_mul(a[j], b[i - j]));
            }
        }
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut Polynomial<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
    }

    /// Performs `result = self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut Polynomial<A>, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        factor.factor_mul_slice_to(self.as_ref(), output.as_mut(), modulus);
    }
}
