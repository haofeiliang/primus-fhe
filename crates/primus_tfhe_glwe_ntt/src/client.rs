use primus_modulus::BarrettModulus;

use crate::ClientKey;

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Accepts the client secret key or an external LWE public key.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::GlweEncryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::GlweDecryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>>;
