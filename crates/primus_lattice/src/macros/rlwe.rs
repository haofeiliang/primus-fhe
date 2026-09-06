//! Access to the two equal-length polynomials in an RLWE ciphertext.

macro_rules! impl_rlwe_accessors {
    ($cipher:ident, $poly:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Borrows the mask `a` and body `b` slices without allocating.
            ///
            /// # Correctness
            ///
            /// Storage must contain two nonempty, equal-length polynomials in
            /// this ciphertext's representation. RNS halves include all moduli
            /// in the same order; their full layout is maintained by the caller.
            #[must_use]
            #[inline]
            pub fn a_b_slices(&self) -> (&[T], &[T]) {
                let data = self.as_ref();
                data.split_at(data.len() / 2)
            }

            /// Borrows the mask and body as polynomial views.
            ///
            /// # Correctness
            ///
            /// Storage must satisfy the layout required by `a_b_slices`.
            #[must_use]
            #[inline]
            pub fn a_b(&self) -> (primus_poly::$poly<&[T]>, primus_poly::$poly<&[T]>) {
                let (a, b) = self.a_b_slices();
                (primus_poly::$poly(a), primus_poly::$poly(b))
            }
        }

        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Borrows disjoint mask and body slices without allocating.
            ///
            /// # Correctness
            ///
            /// Storage must satisfy the layout required by `a_b_slices`.
            #[inline]
            pub fn a_b_mut_slices(&mut self) -> (&mut [T], &mut [T]) {
                let data = self.as_mut();
                let mid = data.len() / 2;
                data.split_at_mut(mid)
            }

            /// Borrows disjoint mask and body polynomial views.
            ///
            /// # Correctness
            ///
            /// Storage must satisfy the layout required by `a_b_slices`.
            #[inline]
            pub fn a_b_mut(
                &mut self,
            ) -> (primus_poly::$poly<&mut [T]>, primus_poly::$poly<&mut [T]>) {
                let (a, b) = self.a_b_mut_slices();
                (primus_poly::$poly(a), primus_poly::$poly(b))
            }
        }
    };
}
