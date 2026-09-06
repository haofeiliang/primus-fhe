//! Component-wise arithmetic over ordered RNS moduli.

#[cfg(feature = "rns")]
macro_rules! impl_basic_operation_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Perform element-wise modular addition `self + rhs`.
            #[inline]
            pub fn add<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: Data<Elem = T>,
            {
                self.add_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Perform element-wise modular subtraction `self - rhs`.
            #[inline]
            pub fn sub<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: Data<Elem = T>,
            {
                self.sub_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            #[inline]
            pub fn add_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: Data<Elem = T>,
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
            pub fn sub_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: Data<Elem = T>,
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

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Performs element-wise modular addition `output = self + rhs`.
            #[inline]
            pub fn add_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                output: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    output.0.chunks_exact_mut(crt_poly_length),
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

            /// Performs element-wise modular subtraction `output = self - rhs`.
            #[inline]
            pub fn sub_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                output: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    output.0.chunks_exact_mut(crt_poly_length),
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
