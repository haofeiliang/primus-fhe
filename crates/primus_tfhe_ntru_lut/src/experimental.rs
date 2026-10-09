//! Experimental u64 lookup configs, without security or failure-probability estimates.
//!
//! The 2026-10-08 teaching workload uses n800/h32/N1024, alpha*q24 input noise,
//! two-bit chunks and c8/d5/o8. Its public function is `(x*x+3*x+7) mod 65536`.
//! These constants share the matching one-hot CBS description, including its
//! required return-KS material, and add public table layout. Candidate CMux codecs, tables and keys are not constructed.

use primus_modulus::PowOf2Modulus;

use crate::HighPrecLutConfig;

/// Classic NTT lookup, Q50→q24, eight input/eight output two-bit chunks, d=5.
#[cfg(feature = "ntt")]
pub const NTT_CLASSIC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::BarrettModulus<u64>,
    PowOf2Modulus<u64>,
> = HighPrecLutConfig {
    one_hot: primus_tfhe_ntru_ntt::experimental::CLASSIC_ONE_HOT_U64,
    input_chunk_count: 8,
    output_chunk_count: 8,
    coefficient_chunk_count: None,
};

/// Native-torus Fourier lookup, with the chunk/return workload of NTT_CLASSIC_LOOKUP_U64.
#[cfg(feature = "fourier")]
pub const FOURIER_CLASSIC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::NativeModulus<u64>,
    PowOf2Modulus<u64>,
> = HighPrecLutConfig {
    one_hot: primus_tfhe_ntru_fourier::experimental::CLASSIC_ONE_HOT_U64,
    input_chunk_count: 8,
    output_chunk_count: 8,
    coefficient_chunk_count: None,
};
