use primus_modulus::NativeModulus;

use crate::ClientKey;

/// Encryptor role for the native-torus Fourier backend.
///
/// Only client-key encryption is implemented currently; the key type is kept
/// generic so public-key encryption can be added without replacing this type.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe::Encryptor<'a, T, NativeModulus<T>, NativeModulus<T>, Key>;

/// Client-key decryptor for the native-torus Fourier backend.
pub type Decryptor<'a, T> = primus_tfhe::Decryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;
