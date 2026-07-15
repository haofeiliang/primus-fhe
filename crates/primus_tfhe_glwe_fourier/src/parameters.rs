//! Parameter types and built-in parameter sets for the Fourier backend.

use primus_modulus::NativeModulus;

/// GLWE-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> = primus_fhe_core::TfheParameters<T, NativeModulus<T>, NativeModulus<T>>;
