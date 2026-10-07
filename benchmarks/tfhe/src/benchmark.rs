//! PBS workload geometry shared by the four backend benchmarks.
//! These are performance fixtures, not security parameter sets. Numerical
//! parameters remain backend-specific; see `benchmarks/tfhe/BENCHMARKS.md`.

/// Geometry and plaintext domain of one benchmark workload.
#[derive(Clone, Copy)]
pub struct PbsWorkload {
    /// Stable label used in benchmark IDs and validation reports.
    pub name: &'static str,
    /// Small LWE dimension for GLWE; independent external dimension for NTRU.
    pub lwe_dimension: usize,
    /// Accumulator ring length N.
    pub poly_length: usize,
    /// Includes the padding bit: 4 for Boolean, 32 for 2 message + 2 carry bits.
    pub plaintext_modulus: u32,
}

/// Boolean and two-message-bit/two-carry-bit workloads at representative sizes.
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

/// Dense u32 PBS prime; circuit products use the wider profile in `parameters`.
pub const NTT_Q32: u32 = 132_120_577;
/// u64 NTT prime shared by dense PBS and circuit products.
pub const NTT_Q64: u64 = 1_125_899_906_826_241;

// Normalized torus standard deviations from TFHE-rs 1.8.1's
// V1_8_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, which aliases V1_4.
// Select this explicit Gaussian set when comparing; the default shortint
// alias uses TUniform noise and different LWE/KS parameters.
/// Reference LWE sigma as a fraction of the ciphertext modulus, not coefficients.
pub const LWE_STD_DEV: f64 = 2.046_151_696_979_124e-6;
/// Reference GLWE sigma as a fraction of the ciphertext modulus, not coefficients.
pub const GLWE_STD_DEV: f64 = 2.845_267_479_601_915e-15;

/// Matched sparse diagnostics use the same mapping in every consumer.
/// Paper-specific copies/buckets remain in the paper profile.
#[must_use]
pub fn blind_rotation(sparse: bool) -> primus_tfhe::BlindRotationConfig {
    if sparse {
        primus_tfhe::BlindRotationConfig::Sparse {
            copy_count: 3,
            bucket_count: 64,
        }
    } else {
        primus_tfhe::BlindRotationConfig::Classic
    }
}

/// One request returns all threshold bits, regardless of the evaluation path.
#[derive(Clone, Copy)]
pub struct ThresholdWorkload {
    pub domain: usize,
    pub outputs: usize,
    pub sparse: bool,
}

/// D8 compares all paths and both BR algorithms; D64 exceeds interleaved capacity.
pub const MVB_WORKLOADS: [ThresholdWorkload; 3] = [
    ThresholdWorkload {
        domain: 8,
        outputs: 3,
        sparse: false,
    },
    ThresholdWorkload {
        domain: 8,
        outputs: 3,
        sparse: true,
    },
    ThresholdWorkload {
        domain: 64,
        outputs: 17,
        sparse: false,
    },
];

/// Algorithms are selected before timing; no string dispatch in numerical calls.
#[derive(Clone, Copy)]
pub enum MvbPath {
    Independent,
    Interleaved,
    Factorized,
}

impl MvbPath {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::Interleaved => "interleaved",
            Self::Factorized => "factorized",
        }
    }
}

impl ThresholdWorkload {
    #[must_use]
    pub fn paths(self) -> &'static [MvbPath] {
        use MvbPath::*;
        if self.domain == 8 {
            &[Independent, Interleaved, Factorized]
        } else {
            &[Independent, Factorized]
        }
    }

    /// The encrypted input is the midpoint; thresholds span the padded domain.
    #[must_use]
    pub fn value<T: primus_integer::FheUint>(self, message: usize, output: usize) -> T {
        if message >= (output + 1) * self.domain / (self.outputs + 1) {
            T::ONE
        } else {
            T::ZERO
        }
    }
}
