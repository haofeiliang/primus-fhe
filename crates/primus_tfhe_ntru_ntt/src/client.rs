use primus_modulus::BarrettModulus;

/// Client-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T> = primus_tfhe_ntru::NtruEncryptor<'a, T, BarrettModulus<T>>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, BarrettModulus<T>>;
