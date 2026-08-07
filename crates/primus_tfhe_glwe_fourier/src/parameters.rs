//! Parameter types and built-in parameter sets for the Fourier backend.

use primus_modulus::NativeModulus;

/// GLWE-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> =
    primus_tfhe_glwe::GlweTfheParameters<T, NativeModulus<T>, NativeModulus<T>>;
