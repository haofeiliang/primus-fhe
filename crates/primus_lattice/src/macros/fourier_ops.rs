//! Pointwise Fourier ciphertext arithmetic.

/// Pointwise arithmetic shared by Fourier GLWE and NTRU ciphertexts.
macro_rules! impl_fourier_basic_operation {
    ($cipher:ident) => {
        impl<S> $cipher<S>
        where
            S: primus_data::DataMut<Elem = num_complex::Complex64>,
        {
            /// Performs pointwise addition in place.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Operand lengths must match.
            #[inline]
            pub fn add_assign<A>(&mut self, rhs: &$cipher<A>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_mut())
                    .add_assign(&primus_poly::FourierPolynomial(rhs.as_ref()));
            }

            /// Performs pointwise subtraction in place.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Operand lengths must match.
            #[inline]
            pub fn sub_assign<A>(&mut self, rhs: &$cipher<A>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_mut())
                    .sub_assign(&primus_poly::FourierPolynomial(rhs.as_ref()));
            }

            /// Performs pointwise negation in place.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Every stored complex value is transformed.
            #[inline]
            pub fn neg_assign(&mut self) {
                primus_poly::FourierPolynomial(self.as_mut()).neg_assign();
            }

            /// Performs real scalar multiplication in place.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Every stored complex value is transformed.
            #[inline]
            pub fn mul_scalar_assign(&mut self, scalar: f64) {
                primus_poly::FourierPolynomial(self.as_mut()).mul_scalar_assign(scalar);
            }
        }
        impl<S> $cipher<S>
        where
            S: primus_data::Data<Elem = num_complex::Complex64>,
        {
            /// Writes `output = self + rhs` into existing storage.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Input and output lengths must match.
            #[inline]
            pub fn add_to<A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref()).add_to(
                    &primus_poly::FourierPolynomial(rhs.as_ref()),
                    &mut primus_poly::FourierPolynomial(output.as_mut()),
                );
            }

            /// Writes `output = self - rhs` into existing storage.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Input and output lengths must match.
            #[inline]
            pub fn sub_to<A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>)
            where
                A: primus_data::Data<Elem = num_complex::Complex64>,
                B: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref()).sub_to(
                    &primus_poly::FourierPolynomial(rhs.as_ref()),
                    &mut primus_poly::FourierPolynomial(output.as_mut()),
                );
            }

            /// Writes `output = -self` into existing storage.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Input and output lengths must match.
            #[inline]
            pub fn neg_to<A>(&self, output: &mut $cipher<A>)
            where
                A: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref())
                    .neg_to(&mut primus_poly::FourierPolynomial(output.as_mut()));
            }

            /// Writes `output = self * scalar` into existing storage.
            ///
            /// All ciphertexts must use the same layout and Fourier representation.
            /// Input and output lengths must match.
            #[inline]
            pub fn mul_scalar_to<A>(&self, scalar: f64, output: &mut $cipher<A>)
            where
                A: primus_data::DataMut<Elem = num_complex::Complex64>,
            {
                primus_poly::FourierPolynomial(self.as_ref())
                    .mul_scalar_to(scalar, &mut primus_poly::FourierPolynomial(output.as_mut()));
            }
        }
    };
}
