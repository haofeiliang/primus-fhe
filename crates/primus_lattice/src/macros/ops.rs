//! Single-modulus ciphertext arithmetic, grouped by supported operation.

macro_rules! impl_basic_operation_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Consumes `self` and adds `rhs`, reusing the backing storage.
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[must_use]
            #[inline]
            pub fn add<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_mut())
                    .add_element_wise_assign(&primus_poly::ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Consumes `self` and subtracts `rhs`, reusing the backing storage.
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[must_use]
            #[inline]
            pub fn sub<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_mut())
                    .sub_element_wise_assign(&primus_poly::ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn add_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_mut())
                    .add_element_wise_assign(&primus_poly::ArrayBase(rhs.as_ref()), modulus);
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn sub_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_mut())
                    .sub_element_wise_assign(&primus_poly::ArrayBase(rhs.as_ref()), modulus);
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Writes the element-wise modular sum `output = self + rhs`.
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn add_to<M, A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_ref()).add_element_wise_to(
                    &primus_poly::ArrayBase(rhs.as_ref()),
                    &mut primus_poly::ArrayBase(output.as_mut()),
                    modulus,
                )
            }

            /// Writes the element-wise modular difference `output = self - rhs`.
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn sub_to<M, A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                primus_poly::ArrayBase(self.as_ref()).sub_element_wise_to(
                    &primus_poly::ArrayBase(rhs.as_ref()),
                    &mut primus_poly::ArrayBase(output.as_mut()),
                    modulus,
                )
            }
        }
    };
}

// Single-modulus operations shared without imposing a polynomial layout.
macro_rules! impl_neg_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Negates every ciphertext component modulo `modulus` in place.
            ///
            /// Coefficients must satisfy the input range required by `modulus`.
            #[inline]
            pub fn neg_assign<M>(&mut self, modulus: M)
            where
                M: primus_reduce::ReduceNegSlice<T>,
            {
                modulus.reduce_neg_slice_assign(self.as_mut());
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = -self` into existing storage.
            ///
            /// Input and output must have the same layout and length.
            /// Coefficients must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn neg_to<M, A>(&self, output: &mut $cipher<A>, modulus: M)
            where
                M: primus_reduce::ReduceNegSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                modulus.reduce_neg_slice_to(self.as_ref(), output.as_mut());
            }
        }
    };
}

macro_rules! impl_mul_scalar_assign_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext component by `scalar` in place.
            ///
            /// Coefficients and `scalar` must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
            where
                M: primus_reduce::ReduceMulSlice<T>,
            {
                modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
            }
        }
    };
}

macro_rules! impl_mul_scalar_single_modulus {
    ($cipher:ident) => {
        impl_mul_scalar_assign_single_modulus!($cipher);
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self * scalar` into existing storage.
            ///
            /// Input and output must have the same layout and length.
            /// Coefficients and `scalar` must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut $cipher<A>, modulus: M)
            where
                M: primus_reduce::ReduceMulSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
            }
        }
    };
}

macro_rules! impl_add_mul_scalar_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Accumulates `self += rhs * scalar` without allocating.
            ///
            /// Both ciphertexts must have the same layout and length. Coefficients
            /// and `scalar` must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &$cipher<A>, scalar: T, modulus: M)
            where
                M: primus_reduce::ReduceMulAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
            }
        }
    };
}

macro_rules! impl_mul_factor_assign_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext component by a precomputed `factor` in place.
            ///
            /// The factor must be prepared for `modulus`; coefficients must satisfy
            /// its multiplication input range.
            #[inline]
            pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
            where
                F: primus_factor::FactorSliceOps<T>,
            {
                primus_poly::ArrayBase(self.as_mut()).mul_factor_assign(factor, modulus);
            }
        }
    };
}
