use primus_modulus::NativeModulus;

use crate::ClientKey;

/// Encryptor role for the native-torus Fourier backend.
///
/// Accepts the client secret key or an external LWE public key.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::GlweEncryptor<'a, T, NativeModulus<T>, NativeModulus<T>, Key>;

/// Client-key decryptor for the native-torus Fourier backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::GlweDecryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;
