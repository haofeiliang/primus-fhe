use primus_modulus::BarrettModulus;

use crate::ClientKey;

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Only client-key encryption is implemented currently; the key type is kept
/// generic so public-key encryption can be added without replacing this type.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::GlweEncryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::GlweDecryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>>;
