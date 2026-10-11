//! Candidate u64 lookup parameters with independent q52 LWE and N4096 NTRU keys.
//!
//! LowPrec/HighPrec name the gadget precision, not the integer input width.
//! Both default to M=16, c=4, d=3 and four output chunks; chunk counts remain
//! independently configurable. NTT samples f and g with sigma=1; Fourier uses
//! sigma=1.5. Reference security estimates do not transfer to these enlarged
//! Gaussians or establish a complete lookup failure rate.

use primus_modulus::PowOf2Modulus;
use primus_ntru::{LweDimension, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionBaseLog, DecompositionConfig,
    DecompositionLevelCount, GadgetEncryptionConfig, LweConfig, ModulusConfig, PbsMessageConfig,
};
use primus_tfhe_ntru::{CbsConfig, PbsConfig};

use crate::HighPrecLutConfig;

/// 50-bit NTT prime: 2^50-16383, congruent to 1 modulo 2N for N=4096.
/// Its strict Q<2^50 bound permits AVX-512 IFMA when supported by the CPU.
pub const NTT_MODULUS: u64 = 1_125_899_906_826_241;

/// External LWE modulus shared by inputs, returned chunks and KS rows.
pub const LWE_MODULUS: u64 = 1 << 52;

const LWE_NOISE: f64 = 3.2 * (1u64 << 28) as f64;

/// LowPrec NTT: BR (L=4,b=10), SS (6,8), Ext (6,7), LUT (2,10), KS (6,3).
#[cfg(feature = "ntt")]
pub const NTT_LOW_PREC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::BarrettModulus<u64>,
    PowOf2Modulus<u64>,
> = lookup_config(ModulusConfig::Explicit(NTT_MODULUS), 1.0, false);

/// HighPrec NTT: BR (L=9,b=5), SS (6,8), Ext (15,3), LUT (1,17), KS (9,2).
#[cfg(feature = "ntt")]
pub const NTT_HIGH_PREC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::BarrettModulus<u64>,
    PowOf2Modulus<u64>,
> = lookup_config(ModulusConfig::Explicit(NTT_MODULUS), 1.0, true);

/// LowPrec Fourier: native64 Q, sigma_f=sigma_g=1.5; same (L,b) as NTT LowPrec.
#[cfg(feature = "fourier")]
pub const FOURIER_LOW_PREC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::NativeModulus<u64>,
    PowOf2Modulus<u64>,
> = lookup_config(ModulusConfig::Native, 1.5, false);

/// HighPrec Fourier: native64 Q, sigma_f=sigma_g=1.5; same (L,b) as NTT HighPrec.
#[cfg(feature = "fourier")]
pub const FOURIER_HIGH_PREC_LOOKUP_U64: HighPrecLutConfig<
    u64,
    primus_modulus::NativeModulus<u64>,
    PowOf2Modulus<u64>,
> = lookup_config(ModulusConfig::Native, 1.5, true);

/// Specify both gadget dimensions explicitly; never extend levels to fill Q.
const fn decomposition(base_log: u32, levels: usize) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base_log),
        level_count: Some(DecompositionLevelCount::new(levels)),
    }
}

/// Keeps the two reference gadget sets paired while only changing the ring
/// representation and f/g sampling width between backends. Ext maps to trace,
/// SS to scheme switch, and LUT to the selectors consumed by the selection tree
/// and low-chunk rotations. Both paths retain classic BR and independent KS.
const fn lookup_config<M: RingContext<u64>>(
    acc_modulus: ModulusConfig<M>,
    ring_sigma: f64,
    high_precision: bool,
) -> HighPrecLutConfig<u64, M, PowOf2Modulus<u64>> {
    let (br, extraction, output, ks) = if high_precision {
        (
            decomposition(5, 9),
            decomposition(3, 15),
            decomposition(17, 1),
            decomposition(2, 9),
        )
    } else {
        (
            decomposition(10, 4),
            decomposition(7, 6),
            decomposition(10, 2),
            decomposition(3, 6),
        )
    };
    HighPrecLutConfig {
        one_hot: CbsConfig {
            pbs: PbsConfig {
                external_lwe: LweConfig {
                    dimension: LweDimension::new(1024),
                    cipher_modulus: ModulusConfig::Explicit(LWE_MODULUS),
                    secret_key_distr: SecretKeyDistr::FixedHammingWeightBinary {
                        hamming_weight: 128,
                    },
                    noise_standard_deviation: LWE_NOISE,
                },
                acc_modulus,
                bsk_poly_length: PolyLength::new(4096),
                bsk_secret_distr: SecretKeyDistr::gaussian(ring_sigma),
                bsk_gadget: GadgetEncryptionConfig {
                    decomposition: br,
                    noise_standard_deviation: ring_sigma,
                },
                key_switching: GadgetEncryptionConfig {
                    decomposition: ks,
                    noise_standard_deviation: LWE_NOISE,
                },
                algorithm: BlindRotationMethod::Classic,
                messages: PbsMessageConfig::new(32),
            },
            gadget: CbsGadgetConfig {
                trace: extraction,
                scheme_switch: decomposition(8, 6),
                output,
            },
        },
        input_chunk_count: 4,
        output_chunk_count: 4,
        coefficient_chunk_count: Some(3),
    }
}
