//! Basic ciphertext constructors and byte conversion.
//!
//! These macros generate `new`, `AsRef`, `AsMut`, byte conversion traits,
//! and zero-initialization for every integer-domain ciphertext type.

macro_rules! impl_common {
    ($cipher:ident) => {
        impl<S> $cipher<S>
        where
            S: RawData,
            <S as RawData>::Elem: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!(S),">`].")]
            ///
            /// # Correctness
            ///
            /// This only wraps storage. The caller must supply the complete layout and
            /// representation documented for this ciphertext; no cryptographic metadata
            /// is inferred or validated.
            #[must_use]
            #[inline(always)]
            pub fn new(data: S) -> Self {
                Self(data)
            }
        }

        impl<S, T> AsRef<[T]> for $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            #[inline(always)]
            fn as_ref(&self) -> &[T] {
                self.0.as_slice()
            }
        }

        impl<S, T> AsMut<[T]> for $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            #[inline(always)]
            fn as_mut(&mut self) -> &mut [T] {
                self.0.as_mut_slice()
            }
        }
    };
}

macro_rules! impl_bytes_io {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataOwned<Elem = T>,
            T: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!(S),">`] from bytes `data`.")]
            ///
            /// The byte representation is native-endian raw element storage, without
            /// layout, modulus, or transform metadata. It is not a portable serialization
            /// format; an enclosing format must supply that metadata.
            ///
            /// # Correctness
            ///
            /// Decoded elements must satisfy the target ciphertext layout and numerical
            /// representation. Decoding does not validate these contracts.
            ///
            /// # Panics
            ///
            /// Panics if the byte length is not a multiple of the element size or the
            /// input cannot be cast to an aligned element slice.
            #[must_use]
            #[inline]
            pub fn from_bytes(data: &[u8]) -> Self {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                Self(<S>::from_slice(converted_data))
            }
        }

        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Copy from bytes `data`.
            ///
            /// The byte representation is native-endian raw element storage, without
            /// layout, modulus, or transform metadata. It is not a portable serialization
            /// format; an enclosing format must supply that metadata.
            ///
            /// # Correctness
            ///
            /// Decoded elements must satisfy the target ciphertext layout and numerical
            /// representation. Decoding does not validate these contracts.
            ///
            /// # Panics
            ///
            /// Panics if the byte length is not a multiple of the element size or the
            /// input cannot be cast to an aligned element slice. Also panics if the
            /// decoded element count differs from the destination length.
            #[inline]
            pub fn read_bytes(&mut self, data: &[u8]) {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                self.0.copy_from_slice(converted_data);
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Converts `self` into bytes.
            ///
            /// The byte representation is native-endian raw element storage, without
            /// layout, modulus, or transform metadata. It is not a portable serialization
            /// format; an enclosing format must supply that metadata.
            ///
            #[inline]
            pub fn to_bytes(&self) -> Vec<u8> {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                converted_data.to_vec()
            }

            /// Converts `self` into bytes, stored in `data`.
            ///
            /// The byte representation is native-endian raw element storage, without
            /// layout, modulus, or transform metadata. It is not a portable serialization
            /// format; an enclosing format must supply that metadata.
            ///
            /// # Panics
            ///
            /// Panics if `data.len()` differs from the raw storage byte count.
            #[inline]
            pub fn write_bytes(&self, data: &mut [u8]) {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                data.copy_from_slice(converted_data);
            }
        }
    };
}

macro_rules! impl_zero {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataOwned<Elem = T>,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!(S),">`] with all values or coefficients equal to zero.")]
                ///
                /// # Correctness
                ///
                /// The length is the total number of stored elements, including all
                /// components, levels, rows, and modulus blocks. The caller chooses a valid
                /// ciphertext layout. This initializes zeros without sampling an encryption.
                #[must_use]
                #[inline]
                pub fn zero([<$cipher:snake _len>]: usize) -> Self {
                    Self(<S>::from_vec(vec![T::ZERO; [<$cipher:snake _len>]]))
                }
            }
        }

        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Set all values or coefficients equal to zero.
            #[inline]
            pub fn set_zero(&mut self) {
                self.0.fill(T::ZERO);
            }
        }
    };
}

/// Byte I/O and the inherent size accessor used by integer ciphertexts.
macro_rules! impl_bytes_conversion {
    ($cipher:ident) => {
        impl_bytes_io!($cipher);
        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Returns the bytes count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                self.0.len() * T::BYTES
            }
        }
    };
}

/// Standard integer ciphertext storage APIs. LWE keeps its dimension-based
/// zero constructors and `Size` trait, so it uses the constituent macros.
macro_rules! impl_ciphertext_core {
    ($cipher:ident) => {
        impl_common!($cipher);
        impl_bytes_conversion!($cipher);
        impl_zero!($cipher);
    };
}
