//! RNS neg arithmetic.

macro_rules! impl_neg_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Negates every ciphertext component in place.
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus negation input range.
            #[inline]
            pub fn neg_assign<M>(&mut self, poly_length: usize, rns_poly_len: usize, moduli: &[M])
            where
                M: Copy + primus_reduce::ReduceNegSlice<T>,
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
                for output in self.as_mut().chunks_exact_mut(rns_poly_len) {
                    for (output, &modulus) in
                        itertools::izip!(output.chunks_exact_mut(poly_length), moduli)
                    {
                        modulus.reduce_neg_slice_assign(output);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = -self`, overwriting all components.
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus negation input range.
            #[inline]
            pub fn neg_to<M, A>(
                &self,
                output: &mut $cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceNegSlice<T>,
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
                    for (input, output, &modulus) in itertools::izip!(
                        input.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        moduli
                    ) {
                        modulus.reduce_neg_slice_to(input, output);
                    }
                }
            }
        }
    };
}
