//! PBS workload geometry shared by the four backend benchmarks.
//! These are performance fixtures, not security parameter sets. Numerical
//! parameters remain backend-specific; see `crates/primus_tfhe/BENCHMARKS.md`.

/// Geometry and plaintext domain of one benchmark workload.
#[derive(Clone, Copy)]
pub struct PbsWorkload {
    pub name: &'static str,
    pub lwe_dimension: usize,
    pub poly_length: usize,
    /// Includes the padding bit: 4 for Boolean, 32 for 2 message + 2 carry bits.
    pub plaintext_modulus: u32,
}

pub const PBS_WORKLOADS: [PbsWorkload; 2] = [
    PbsWorkload {
        name: "boolean",
        lwe_dimension: 800,
        poly_length: 1024,
        plaintext_modulus: 4,
    },
    PbsWorkload {
        name: "shortint_2_2",
        lwe_dimension: 866,
        poly_length: 2048,
        plaintext_modulus: 32,
    },
];

pub const NTT_Q32: u32 = 132_120_577;
pub const NTT_Q64: u64 = 1_125_899_906_826_241;

// Normalized torus standard deviations from TFHE-rs 1.8.1's
// V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, which aliases V1_4.
// Select this explicit Gaussian set when comparing; the default shortint
// alias uses TUniform noise and different LWE/KS parameters.
pub const LWE_STD_DEV: f64 = 2.046_151_696_979_124e-6;
pub const GLWE_STD_DEV: f64 = 2.845_267_479_601_915e-15;
