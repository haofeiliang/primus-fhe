//! Coefficient-domain monomial accumulation.

macro_rules! impl_add_mul_monomial_single_modulus {
    ($cipher:ident) => {
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
                debug_assert!(
                    (crate::MIN_POLY_LENGTH..=crate::MAX_POLY_LENGTH).contains(&poly_length)
                        && poly_length.is_power_of_two(),
                    "invalid polynomial length"
                );
                debug_assert!(
                    exponent < 2 * poly_length,
                    "monomial exponent must be less than 2N"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(poly_length),
                    "incomplete ciphertext polynomial"
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
macro_rules! impl_add_mul_monomial_multiple_modulus {
    ($cipher:ident) => {
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
                debug_assert!(
                    (crate::MIN_POLY_LENGTH..=crate::MAX_POLY_LENGTH).contains(&poly_length)
                        && poly_length.is_power_of_two(),
                    "invalid polynomial length"
                );
                debug_assert!(
                    exponent / poly_length < 2,
                    "monomial exponent must be less than 2N"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                debug_assert!(!moduli.is_empty(), "RNS basis must be nonempty");
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(rns_poly_len),
                    "RNS polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(rns_poly_len),
                    "incomplete RNS component"
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
