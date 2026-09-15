use primus_modulus::BarrettModulus;

/// Secret-key or LWE public-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T, Key = crate::ClientKey<T>> =
    primus_tfhe_ntru::NtruEncryptor<'a, T, BarrettModulus<T>, Key>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, BarrettModulus<T>>;
