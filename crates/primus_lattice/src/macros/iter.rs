//! Chunked iterator generation and sub-component iteration.
//!
//! These macros generate `{Type}Iter` / `{Type}IterMut` types and the
//! `iter_{sub}()` / `iter_{sub}_mut()` methods for navigating ciphertext
//! sub-structures.

macro_rules! impl_iters {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!("Immutable chunked iterator over [`", stringify!($cipher), "`] ciphertexts.")]
            pub struct [<$cipher Iter>]<'a, T>
            where
                T: FheUint,
            {
                /// Exact chunks backing this immutable ciphertext iterator.
                pub(crate) iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher Iter>]<'a, T> {
                #[doc = concat!("Creates an iterator yielding [`", stringify!($cipher), "`] chunks of `", stringify!([<$cipher:snake _len>]), "` elements each.")]
                #[inline]
                pub fn new(data:&'a [T], [<$cipher:snake _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact([<$cipher:snake _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$cipher Iter>]<'a, T> {
                type Item = $cipher<&'a [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $cipher(slice))
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher Iter>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$cipher Iter>]<'a, T> {}
        }

        paste::paste! {
            #[doc = concat!("Mutable chunked iterator over [`", stringify!($cipher), "`] ciphertexts.")]
            pub struct [<$cipher IterMut>]<'a, T>
            where
                T: FheUint,
            {
                /// Exact chunks backing this mutable ciphertext iterator.
                pub(crate) iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher IterMut>]<'a, T> {
                #[doc = concat!("Creates a mutable iterator yielding [`", stringify!($cipher), "`] chunks of `", stringify!([<$cipher:snake _len>]), "` elements each.")]
                #[inline]
                pub fn new(data:&'a mut [T], [<$cipher:snake _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact_mut([<$cipher:snake _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$cipher IterMut>]<'a, T> {
                type Item = $cipher<&'a mut [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $cipher(slice))
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher IterMut>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$cipher IterMut>]<'a, T> {}
        }
    };
}

macro_rules! impl_iter_sub_structure {
    ($cipher:ident < $s:ident >, $sub:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns an iterator over the [`", stringify!($sub), "`] sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub:snake>]<'a>(&'a self, [<$sub:snake _len>]: usize) -> [<$sub Iter>]<'a, T> {
                    [<$sub Iter>]::new(self.0.as_slice(), [<$sub:snake _len>])
                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns a mutable iterator over the [`", stringify!($sub), "`] sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub:snake _mut>]<'a>(
                    &'a mut self,
                    [<$sub:snake _len>]: usize,
                ) -> [<$sub IterMut>]<'a, T> {
                    [<$sub IterMut>]::new(self.0.as_mut_slice(), [<$sub:snake _len>])
                }
            }
        }
    };
    ($cipher:ident < $s:ident >, $sub:ident, $sub_short:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns an iterator over the [`", stringify!($sub), "`] sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub_short>]<'a>(&'a self, [<$sub_short _len>]: usize) -> [<$sub Iter>]<'a, T> {
                    [<$sub Iter>]::new(self.0.as_slice(), [<$sub_short _len>])
                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns a mutable iterator over the [`", stringify!($sub), "`] sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub_short _mut>]<'a>(
                    &'a mut self,
                    [<$sub_short _len>]: usize,
                ) -> [<$sub IterMut>]<'a, T> {
                    [<$sub IterMut>]::new(self.0.as_mut_slice(), [<$sub_short _len>])
                }
            }
        }
    };
}
