use primus_modulus::NativeModulus;

/// Client-key encryptor for the Fourier NTRU backend.
pub type Encryptor<'a, T> = primus_tfhe_ntru::NtruEncryptor<'a, T, NativeModulus<T>>;

/// Client-key decryptor for the Fourier NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, NativeModulus<T>>;
