//! Basic ciphertext constructors and byte conversion.
//!
//! These macros generate `new`, `AsRef`, `AsMut`, byte conversion traits,
//! and zero-initialization for every integer-domain ciphertext type.

macro_rules! impl_common {
    ($cipher:ident < $s:ident >) => {
        impl<$s> $cipher<$s>
        where
            $s: RawData,
            <$s as RawData>::Elem: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`].")]
            #[inline(always)]
            pub fn new(data: $s) -> Self {
                Self(data)
            }
        }

        impl<$s, T> AsRef<[T]> for $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            #[inline(always)]
            fn as_ref(&self) -> &[T] {
                self.0.as_slice()
            }
        }

        impl<$s, T> AsMut<[T]> for $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            #[inline(always)]
            fn as_mut(&mut self) -> &mut [T] {
                self.0.as_mut_slice()
            }
        }
    };
}

macro_rules! impl_bytes_conversion {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataOwned,
            T: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`] from bytes `data`.")]
            #[inline]
            pub fn from_bytes(data: &[u8]) -> Self {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                Self(<$s>::from_slice(converted_data))
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Copy from bytes `data`.
            #[inline]
            pub fn read_bytes(&mut self, data: &[u8]) {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                self.0.copy_from_slice(converted_data);
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Converts `self` into bytes.
            #[inline]
            pub fn to_bytes(&self) -> Vec<u8> {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                converted_data.to_vec()
            }

            /// Converts `self` into bytes, stored in `data`.
            #[inline]
            pub fn write_bytes(&self, data: &mut [u8]) {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                data.copy_from_slice(converted_data);
            }

            /// Returns the bytes count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                self.0.len() * T::BYTES
            }
        }
    };
}

macro_rules! impl_zero {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataOwned,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`] with all values or coefficients equal to zero.")]
                #[inline]
                pub fn zero([<$cipher:snake _len>]: usize) -> Self {
                    Self(<$s>::from_vec(vec![T::ZERO; [<$cipher:snake _len>]]))
                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
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
