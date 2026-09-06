//! Component-wise DCRT plaintext polynomial products.

#[cfg(feature = "rns")]
macro_rules! impl_dcrt_polynomial_mul {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext polynomial by `poly` in place.
            ///
            /// Operands must use the same DCRT representation and ordered modulus base.
            /// Ciphertext storage must contain whole polynomials matching `poly`;
            /// values must be valid inputs to the modular product.
            /// `poly_length` and the modulus count must be nonzero; `poly` contains
            /// `poly_length * moduli.len()` values, grouped by modulus in order.
            #[inline]
            pub fn mul_dcrt_polynomial_assign<M, A>(
                &mut self,
                poly: &primus_poly::DcrtPolynomial<A>,
                poly_length: usize,
                moduli: &[M],
            ) where
                M: primus_reduce::FieldContext<T>,
                A: primus_data::Data<Elem = T>,
            {
                let component_len = poly.dcrt_poly_length();
                debug_assert!(
                    poly_length > 0 && !moduli.is_empty(),
                    "DCRT layout must be nonempty"
                );
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(component_len),
                    "DCRT polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(component_len),
                    "incomplete ciphertext polynomial"
                );
                for values in self.as_mut().chunks_exact_mut(component_len) {
                    primus_poly::DcrtPolynomial(values).mul_assign(poly, poly_length, moduli);
                }
            }

            /// Accumulates `self += rhs * poly` without clearing `self`.
            ///
            /// Ciphertexts must use compatible keys and matching layouts, including
            /// gadget bases and level/row order. The same polynomial scales every
            /// component; no gadget decomposition or level reduction is performed.
            ///
            /// Operands must use the same DCRT representation and ordered modulus base.
            /// Ciphertexts must have equal lengths and contain whole polynomials
            /// matching `poly`; values must be valid inputs to the modular product.
            /// `poly_length` and the modulus count must be nonzero; `poly` contains
            /// `poly_length * moduli.len()` values, grouped by modulus in order.
            #[inline]
            pub fn add_mul_dcrt_polynomial_assign<M, A, B>(
                &mut self,
                rhs: &$cipher<A>,
                poly: &primus_poly::DcrtPolynomial<B>,
                poly_length: usize,
                moduli: &[M],
            ) where
                M: primus_reduce::FieldContext<T>,
                A: primus_data::Data<Elem = T>,
                B: primus_data::Data<Elem = T>,
            {
                let component_len = poly.dcrt_poly_length();
                debug_assert!(
                    poly_length > 0 && !moduli.is_empty(),
                    "DCRT layout must be nonempty"
                );
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(component_len),
                    "DCRT polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(component_len),
                    "incomplete ciphertext polynomial"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (acc, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(component_len)
                    .zip(rhs.as_ref().chunks_exact(component_len))
                {
                    primus_poly::DcrtPolynomial(acc).add_mul_assign(
                        &primus_poly::DcrtPolynomial(rhs),
                        poly,
                        poly_length,
                        moduli,
                    );
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self * poly`, overwriting every output component.
            ///
            /// Operands must use the same DCRT representation and ordered modulus base.
            /// Ciphertexts must have equal lengths and contain whole polynomials
            /// matching `poly`; values must be valid inputs to the modular product.
            /// `poly_length` and the modulus count must be nonzero; `poly` contains
            /// `poly_length * moduli.len()` values, grouped by modulus in order.
            #[inline]
            pub fn mul_dcrt_polynomial_to<M, A, B>(
                &self,
                poly: &primus_poly::DcrtPolynomial<A>,
                output: &mut $cipher<B>,
                poly_length: usize,
                moduli: &[M],
            ) where
                M: primus_reduce::FieldContext<T>,
                A: primus_data::Data<Elem = T>,
                B: primus_data::DataMut<Elem = T>,
            {
                let component_len = poly.dcrt_poly_length();
                debug_assert!(
                    poly_length > 0 && !moduli.is_empty(),
                    "DCRT layout must be nonempty"
                );
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(component_len),
                    "DCRT polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(component_len),
                    "incomplete ciphertext polynomial"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "ciphertext length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(component_len)
                    .zip(output.as_mut().chunks_exact_mut(component_len))
                {
                    primus_poly::DcrtPolynomial(input).mul_to(
                        poly,
                        &mut primus_poly::DcrtPolynomial(output),
                        poly_length,
                        moduli,
                    );
                }
            }
        }
    };
}
