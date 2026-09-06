//! Coefficient-domain monomial products.

macro_rules! impl_monomial_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every complete polynomial by `X^exponent` in `Z_q[X]/(X^N + 1)`.
            ///
            /// `N = poly_length` must be a supported power of two and `exponent`
            /// must be in `[0, 2N)`. Storage must contain complete polynomials.
            /// Values must be canonical residues; the result remains canonical.
            /// This operation does not allocate temporary storage.
            #[inline]
            pub fn mul_monomial_assign<M>(
                &mut self,
                exponent: usize,
                poly_length: usize,
                modulus: M,
            ) where
                M: Copy + primus_reduce::ReduceNegSlice<T>,
            {
                for poly in self.as_mut().chunks_exact_mut(poly_length) {
                    primus_poly::Polynomial(poly).mul_monomial_assign(exponent, modulus);
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every complete polynomial by `X^exponent` in `Z_q[X]/(X^N + 1)`.
            ///
            /// `N = poly_length` must be a supported power of two and `exponent`
            /// must be in `[0, 2N)`. Storage must contain complete polynomials.
            /// Values must be canonical residues; the result remains canonical.
            /// This operation does not allocate temporary storage.
            /// Input and output must have equal lengths and matching layouts and bases.
            /// Every output coefficient is overwritten.
            #[inline]
            pub fn mul_monomial_to<M, A>(
                &self,
                exponent: usize,
                output: &mut $cipher<A>,
                poly_length: usize,
                modulus: M,
            ) where
                M: primus_reduce::RingContext<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(poly_length)
                    .zip(output.as_mut().chunks_exact_mut(poly_length))
                {
                    primus_poly::Polynomial(input).mul_monomial_to(
                        exponent,
                        &mut primus_poly::Polynomial(output),
                        modulus,
                    );
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Accumulates `self += rhs * X^exponent` on each complete polynomial.
            ///
            /// Uses `Z_q[X]/(X^N + 1)` with `N = poly_length` and
            /// `poly_length` must be a supported power of two, and `exponent`
            /// must be in `[0, 2N)`. Input and accumulator must have equal
            /// lengths, matching coefficient layouts and compatible key semantics.
            /// Gadget bases and level/row order must match. Values must be canonical
            /// residues; results remain canonical. No temporary ciphertext is allocated.
            #[inline]
            pub fn add_mul_monomial_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                exponent: usize,
                poly_length: usize,
                modulus: M,
            ) where
                M: Copy + primus_reduce::ReduceAddSlice<T> + primus_reduce::ReduceSubSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(poly_length)
                    .zip(rhs.as_ref().chunks_exact(poly_length))
                {
                    primus_poly::Polynomial(acc).add_mul_monomial_assign(
                        &primus_poly::Polynomial(rhs),
                        exponent,
                        modulus,
                    );
                }
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_monomial_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every complete polynomial by `X^exponent` in `Z_q[X]/(X^N + 1)`.
            ///
            /// `N = poly_length` must be a supported power of two and `exponent`
            /// must be in `[0, 2N)`. Storage must contain complete polynomials.
            /// Values must be canonical residues; the result remains canonical.
            /// This operation does not allocate temporary storage.
            /// Each component has one length-`poly_length` block per modulus, in
            /// `moduli` order; the basis is nonempty and
            /// `rns_poly_len = poly_length * moduli.len()`.
            #[inline]
            pub fn mul_monomial_assign<M>(
                &mut self,
                exponent: usize,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceNegSlice<T>,
            {
                for poly in self.as_mut().chunks_exact_mut(rns_poly_len) {
                    for (poly, &modulus) in poly.chunks_exact_mut(poly_length).zip(moduli) {
                        primus_poly::Polynomial(poly).mul_monomial_assign(exponent, modulus);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every complete polynomial by `X^exponent` in `Z_q[X]/(X^N + 1)`.
            ///
            /// `N = poly_length` must be a supported power of two and `exponent`
            /// must be in `[0, 2N)`. Storage must contain complete polynomials.
            /// Values must be canonical residues; the result remains canonical.
            /// This operation does not allocate temporary storage.
            /// Each component has one length-`poly_length` block per modulus, in
            /// `moduli` order; the basis is nonempty and
            /// `rns_poly_len = poly_length * moduli.len()`.
            /// Input and output must have equal lengths and matching layouts and bases.
            /// Every output coefficient is overwritten.
            #[inline]
            pub fn mul_monomial_to<M, A>(
                &self,
                exponent: usize,
                output: &mut $cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: primus_reduce::RingContext<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(rns_poly_len)
                    .zip(output.as_mut().chunks_exact_mut(rns_poly_len))
                {
                    for (input, output, &modulus) in itertools::izip!(
                        input.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        moduli
                    ) {
                        primus_poly::Polynomial(input).mul_monomial_to(
                            exponent,
                            &mut primus_poly::Polynomial(output),
                            modulus,
                        );
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Accumulates `self += rhs * X^exponent` on each complete polynomial.
            ///
            /// Uses `Z_q[X]/(X^N + 1)` with `N = poly_length` and
            /// `poly_length` must be a supported power of two, and `exponent`
            /// must be in `[0, 2N)`. Input and accumulator must have equal
            /// lengths, matching coefficient layouts and compatible key semantics.
            /// Gadget bases and level/row order must match. Values must be canonical
            /// residues; results remain canonical. No temporary ciphertext is allocated.
            /// Each component contains one length-`poly_length` block per modulus
            /// in `moduli` order. The modulus count must be nonzero and
            /// `rns_poly_len = poly_length * moduli.len()`. Storage must contain
            /// complete RNS components, and both ciphertexts must use the same basis.
            #[inline]
            pub fn add_mul_monomial_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                exponent: usize,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceAddSlice<T> + primus_reduce::ReduceSubSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(rns_poly_len)
                    .zip(rhs.as_ref().chunks_exact(rns_poly_len))
                {
                    for (acc, rhs, &modulus) in itertools::izip!(
                        acc.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        moduli
                    ) {
                        primus_poly::Polynomial(acc).add_mul_monomial_assign(
                            &primus_poly::Polynomial(rhs),
                            exponent,
                            modulus,
                        );
                    }
                }
            }
        }
    };
}
