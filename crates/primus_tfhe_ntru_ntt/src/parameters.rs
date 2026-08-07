use primus_modulus::BarrettModulus;

/// NTRU-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> = primus_tfhe_ntru::NtruTfheParameters<T, BarrettModulus<T>>;
