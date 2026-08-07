use primus_modulus::NativeModulus;

/// NTRU-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> = primus_tfhe_ntru::NtruTfheParameters<T, NativeModulus<T>>;
