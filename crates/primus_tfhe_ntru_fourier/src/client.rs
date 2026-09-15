use primus_modulus::NativeModulus;

/// Secret-key or LWE public-key encryptor for the Fourier NTRU backend.
pub type Encryptor<'a, T, Key = crate::ClientKey<T>> =
    primus_tfhe_ntru::NtruEncryptor<'a, T, NativeModulus<T>, Key>;

/// Client-key decryptor for the Fourier NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, NativeModulus<T>>;
