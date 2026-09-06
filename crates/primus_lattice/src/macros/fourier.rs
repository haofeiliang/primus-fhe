//! Fourier-domain macros (Complex64 elements, no `FheUint` requirement).
//!
//! These macros generate iterator types, core methods, sub-component
//! iteration, and coefficient ↔ Fourier conversions for Fourier-domain
//! ciphertext variants (`FourierGlwe`, `FourierGlev`, `FourierGgsw`).

/// Generates `{Cipher}Iter<'a>` and `{Cipher}IterMut<'a>` chunked iterator
/// types for a Fourier ciphertext over `Complex64` elements.
macro_rules! impl_fourier_iters {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!(
                "Immutable chunked iterator over [`",
                stringify!($cipher),
                "`] ciphertexts."
            )]
            #[derive(Debug, Clone)]
            pub struct [<$cipher Iter>]<'a> {
                iter: core::slice::ChunksExact<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher Iter>]<'a> {
                #[doc = concat!(
                    "Creates an iterator yielding [`",
                    stringify!($cipher),
                    "`] views containing `", stringify!([<$cipher:snake _len>]), "` complex values each.",
                    "\n\n# Panics\n\nPanics if `", stringify!([<$cipher:snake _len>]), "` is zero or does not divide `data.len()`."
                )]
                #[must_use]
                #[inline]
                pub fn new(data: &'a [num_complex::Complex64], [<$cipher:snake _len>]: usize) -> Self {
                    assert!([<$cipher:snake _len>] != 0, "Fourier chunk length must be non-zero");
                    assert_eq!(
                        data.len() % [<$cipher:snake _len>],
                        0,
                        "Fourier data length must be divisible by the chunk length"
                    );
                    Self {
                        iter: data.chunks_exact([<$cipher:snake _len>]),
                    }
                }
            }

            impl<'a> Iterator for [<$cipher Iter>]<'a> {
                type Item = $cipher<&'a [num_complex::Complex64]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map($cipher)
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }
            }

            impl<'a> core::iter::FusedIterator for [<$cipher Iter>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher Iter>]<'a> {}
            impl<'a> core::iter::DoubleEndedIterator for [<$cipher Iter>]<'a> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map($cipher)
                }
            }
        }

        paste::paste! {
            #[doc = concat!(
                "Mutable chunked iterator over [`",
                stringify!($cipher),
                "`] ciphertexts."
            )]
            #[derive(Debug)]
            pub struct [<$cipher IterMut>]<'a> {
                iter: core::slice::ChunksExactMut<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher IterMut>]<'a> {
                #[doc = concat!(
                    "Creates a mutable iterator yielding [`",
                    stringify!($cipher),
                    "`] views containing `", stringify!([<$cipher:snake _len>]), "` complex values each.",
                    "\n\n# Panics\n\nPanics if `", stringify!([<$cipher:snake _len>]), "` is zero or does not divide `data.len()`."
                )]
                #[must_use]
                #[inline]
                pub fn new(data: &'a mut [num_complex::Complex64], [<$cipher:snake _len>]: usize) -> Self {
                    assert!([<$cipher:snake _len>] != 0, "Fourier chunk length must be non-zero");
                    assert_eq!(
                        data.len() % [<$cipher:snake _len>],
                        0,
                        "Fourier data length must be divisible by the chunk length"
                    );
                    Self {
                        iter: data.chunks_exact_mut([<$cipher:snake _len>]),
                    }
                }
            }

            impl<'a> Iterator for [<$cipher IterMut>]<'a> {
                type Item = $cipher<&'a mut [num_complex::Complex64]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map($cipher)
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }
            }

            impl<'a> core::iter::FusedIterator for [<$cipher IterMut>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher IterMut>]<'a> {}
            impl<'a> core::iter::DoubleEndedIterator for [<$cipher IterMut>]<'a> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map($cipher)
                }
            }
        }
    };
}

/// Generates `{Cipher}Owned` type alias and core methods (`new`, `zero`,
/// `set_zero`, `as_ref`, `as_mut`, `byte_count`) for a Fourier ciphertext.
macro_rules! impl_fourier_core {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!("Owned [`", stringify!($cipher), "`] backed by a [`Vec`].")]
            pub type [<$cipher Owned>] = $cipher<Vec<num_complex::Complex64>>;
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64>,
        {
            #[doc = concat!("Creates a new [`", stringify!($cipher), "`].")]
            #[must_use]
            #[inline]
            pub fn new(data: S) -> Self {
                Self(data)
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataOwned,
        {
            paste::paste! {
                #[doc = concat!("Creates a zero-initialized [`", stringify!($cipher), "`].")]
                #[inline]
                /// The length is the total number of complex Fourier values,
                /// including every polynomial and ciphertext component.
                #[must_use]
                pub fn zero([< $cipher:snake _len >]: usize) -> Self {
                    Self(S::from_vec(vec![
                        num_complex::Complex64::default();
                        [< $cipher:snake _len >]
                    ]))
                }
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
        {
            /// Sets all complex Fourier values to zero.
            #[inline]
            pub fn set_zero(&mut self) {
                self.0.fill(num_complex::Complex64::default());
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            /// Returns the total byte count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                core::mem::size_of_val(self.0.as_slice())
            }
        }

        impl<S> core::convert::AsRef<[num_complex::Complex64]> for $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            #[inline]
            fn as_ref(&self) -> &[num_complex::Complex64] {
                self.0.as_slice()
            }
        }

        impl<S> core::convert::AsMut<[num_complex::Complex64]> for $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
        {
            #[inline]
            fn as_mut(&mut self) -> &mut [num_complex::Complex64] {
                self.0.as_mut_slice()
            }
        }
    };
}

/// Generates sub-structure iteration methods for a Fourier ciphertext.
///
/// - `$sub`: the sub-component type
/// - `$sub_iter` / `$sub_iter_mut`: the sub-component's iterator types
/// - `$method`: the method name prefix (e.g., `fourier_poly` → `iter_fourier_poly`)
macro_rules! impl_fourier_iter_sub {
    ($cipher:ident, $sub:ident, $sub_iter:ident, $sub_iter_mut:ident, $method:ident) => {
        paste::paste! {
            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
            {
                #[doc = concat!(
                    "Returns an iterator over the [`", stringify!($sub), "`] sub-components, each containing `", stringify!([<$method _len>]), "` complex values.",
                    "\n\n# Panics\n\nPanics if `", stringify!([<$method _len>]), "` is zero or does not divide the ciphertext length."
                )]
                #[inline]
                pub fn [<iter_ $method>](
                    &self,
                    [<$method _len>]: usize,
                ) -> $sub_iter<'_> {
                    $sub_iter::new(self.as_ref(), [<$method _len>])
                }
            }

            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
            {
                #[doc = concat!(
                    "Returns a mutable iterator over the [`",
                    stringify!($sub),
                    "`] sub-components, each containing `", stringify!([<$method _len>]), "` complex values.",
                    "\n\n# Panics\n\nPanics if `", stringify!([<$method _len>]), "` is zero or does not divide the ciphertext length."
                )]
                #[inline]
                pub fn [<iter_ $method _mut>](
                    &mut self,
                    [<$method _len>]: usize,
                ) -> $sub_iter_mut<'_> {
                    $sub_iter_mut::new(self.0.as_mut_slice(), [<$method _len>])
                }
            }
        }
    };
}

/// Generates both coefficient-to-Fourier and Fourier-to-torus conversions.
macro_rules! impl_fourier_conversion {
    ($coeff:ident, $fourier:ident) => {
        impl<S, T> $coeff<S>
        where
            S: primus_data::RawData<Elem = T> + primus_data::Data,
            T: primus_fft::TorusFftValue,
        {
            /// Writes this ciphertext in normalized torus Fourier form.
            pub fn write_fourier_form<Table, A>(
                &self,
                output: &mut $fourier<A>,
                fft: &mut primus_fft::FftEngine<'_, Table>,
            ) where
                Table: primus_fft::FftTable,
                A: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
            {
                for (coeff, fourier) in self
                    .as_ref()
                    .chunks_exact(fft.poly_length())
                    .zip(output.as_mut().chunks_exact_mut(fft.fourier_length()))
                {
                    fft.forward_as_torus(coeff, fourier);
                }
            }
        }
        impl<S> $fourier<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            /// Writes this Fourier ciphertext back to torus coefficient form.
            pub fn write_torus_form<Table, A, T>(
                &self,
                output: &mut $coeff<A>,
                fft: &mut primus_fft::FftEngine<'_, Table>,
            ) where
                Table: primus_fft::FftTable,
                A: primus_data::RawData<Elem = T> + primus_data::DataMut,
                T: primus_fft::TorusFftValue,
            {
                for (fourier, coeff) in self
                    .as_ref()
                    .chunks_exact(fft.fourier_length())
                    .zip(output.as_mut().chunks_exact_mut(fft.poly_length()))
                {
                    fft.backward_as_torus(fourier, coeff);
                }
            }
        }
    };
}
