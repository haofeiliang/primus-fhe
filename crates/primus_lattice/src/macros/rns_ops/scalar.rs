//! RNS scalar arithmetic.

macro_rules! impl_mul_scalar_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies each modulus block by its scalar residue in place.
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `scalar` contains one residue per modulus, in the same order.
            /// Values and residues must satisfy each modulus multiplication input range.
            #[inline]
            pub fn mul_scalar_assign<M>(
                &mut self,
                scalar: &primus_rns::Residues<impl primus_data::Data<Elem = T>>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceMulSlice<T>,
            {
                debug_assert!(
                    poly_length > 0 && !moduli.is_empty(),
                    "RNS layout must be nonempty"
                );
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(rns_poly_len),
                    "RNS polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(rns_poly_len),
                    "incomplete RNS component"
                );
                debug_assert_eq!(scalar.len(), moduli.len(), "RNS scalar count mismatch");
                for output in self.as_mut().chunks_exact_mut(rns_poly_len) {
                    for (output, &scalar, &modulus) in itertools::izip!(
                        output.chunks_exact_mut(poly_length),
                        scalar.iter(),
                        moduli
                    ) {
                        modulus.reduce_mul_scalar_slice_assign(output, scalar);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes the scalar product into `output`, overwriting all components.
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// `scalar` contains one residue per modulus, in the same order.
            /// Values and residues must satisfy each modulus multiplication input range.
            #[inline]
            pub fn mul_scalar_to<M, A>(
                &self,
                scalar: &primus_rns::Residues<impl primus_data::Data<Elem = T>>,
                output: &mut $cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceMulSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                debug_assert!(
                    poly_length > 0 && !moduli.is_empty(),
                    "RNS layout must be nonempty"
                );
                debug_assert_eq!(
                    poly_length.checked_mul(moduli.len()),
                    Some(rns_poly_len),
                    "RNS polynomial length mismatch"
                );
                debug_assert!(
                    self.as_ref().len().is_multiple_of(rns_poly_len),
                    "incomplete RNS component"
                );
                debug_assert_eq!(scalar.len(), moduli.len(), "RNS scalar count mismatch");
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "RNS output length mismatch"
                );
                for (input, output) in self
                    .as_ref()
                    .chunks_exact(rns_poly_len)
                    .zip(output.as_mut().chunks_exact_mut(rns_poly_len))
                {
                    for (input, output, &scalar, &modulus) in itertools::izip!(
                        input.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        scalar.iter(),
                        moduli
                    ) {
                        modulus.reduce_mul_scalar_slice_to(input, scalar, output);
                    }
                }
            }
        }
    };
}
