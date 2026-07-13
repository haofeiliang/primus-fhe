//! Element-wise arithmetic operations.
//!
//! Generates `add_element_wise`, `sub_element_wise`, and their `_assign` / `_to`
//! variants for both single-modulus and multiple-modulus representations.

macro_rules! impl_basic_operation_single_modulus {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Perform element-wise modular addition `self + rhs`.
            #[inline]
            pub fn add_element_wise<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).add_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Perform element-wise modular subtraction `self - rhs`.
            #[inline]
            pub fn sub_element_wise<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).sub_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            #[inline]
            pub fn add_element_wise_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).add_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`
            #[inline]
            pub fn sub_element_wise_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).sub_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Performs in-place element-wise modular addition:`result = self + rhs`,
            #[inline]
            pub fn add_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                modulus: M,
            ) where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                ArrayBase(self.as_ref()).add_element_wise_to(
                    &ArrayBase(rhs.as_ref()),
                    &mut ArrayBase(result.as_mut()),
                    modulus,
                )
            }

            /// Performs in-place element-wise modular addition:`result = self - rhs`,
            #[inline]
            pub fn sub_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                modulus: M,
            ) where
                M: primus_reduce::RingContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                ArrayBase(self.as_ref()).sub_element_wise_to(
                    &ArrayBase(rhs.as_ref()),
                    &mut ArrayBase(result.as_mut()),
                    modulus,
                )
            }
        }
    };
}

macro_rules! impl_basic_operation_multiple_modulus {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Perform element-wise modular addition `self + rhs`.
            #[inline]
            pub fn add_element_wise<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                self.add_element_wise_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Perform element-wise modular subtraction `self - rhs`.
            #[inline]
            pub fn sub_element_wise<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                self.sub_element_wise_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            #[inline]
            pub fn add_element_wise_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                izip!(
                    self.0.chunks_exact_mut(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                )
                .for_each(|(x, y)| {
                    izip!(
                        x.chunks_exact_mut(poly_length),
                        y.chunks_exact(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, &modulus)| {
                        ArrayBase(a).add_element_wise_assign(&ArrayBase(b), modulus);
                    });
                });
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`.
            #[inline]
            pub fn sub_element_wise_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                izip!(
                    self.0.chunks_exact_mut(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                )
                .for_each(|(x, y)| {
                    izip!(
                        x.chunks_exact_mut(poly_length),
                        y.chunks_exact(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, &modulus)| {
                        ArrayBase(a).sub_element_wise_assign(&ArrayBase(b), modulus);
                    });
                });
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Performs element-wise modular addition `result = self + rhs`.
            #[inline]
            pub fn add_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    result.0.chunks_exact_mut(crt_poly_length),
                )
                .for_each(|(x, y, z)| {
                    izip!(
                        x.chunks_exact(poly_length),
                        y.chunks_exact(poly_length),
                        z.chunks_exact_mut(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, c, &modulus)| {
                        ArrayBase(a).add_element_wise_to(&ArrayBase(b), &mut ArrayBase(c), modulus);
                    });
                });
            }

            /// Performs element-wise modular subtraction `result = self - rhs`.
            #[inline]
            pub fn sub_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    result.0.chunks_exact_mut(crt_poly_length),
                )
                .for_each(|(x, y, z)| {
                    izip!(
                        x.chunks_exact(poly_length),
                        y.chunks_exact(poly_length),
                        z.chunks_exact_mut(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, c, &modulus)| {
                        ArrayBase(a).sub_element_wise_to(&ArrayBase(b), &mut ArrayBase(c), modulus);
                    });
                });
            }
        }
    };
}
