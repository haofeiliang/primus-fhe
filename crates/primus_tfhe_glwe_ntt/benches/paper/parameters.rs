//! Table 3 of https://eprint.iacr.org/2026/1730, with explicit adaptations.
//!
//! The paper gives small q and ring Q, but this backend binds both roles to Q.
//! The harness encrypts at q, lifts to Q, uses the existing BR -> ring KS ->
//! extraction pipeline, then returns to q. It does not emulate OpenFHE's Q'
//! LWE key switch. These are reproducible cost profiles, not security presets.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::{LweDimension, LweEncryptionParameters};
use primus_modulus::BarrettModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe::{PbsOrder, TfheConfig, TfheParameters};

/// Geometry quoted by the paper and arithmetic choices resolved for this backend.
#[derive(Clone, Copy)]
pub(super) struct Case {
    pub name: &'static str,
    pub dense_dimension: usize,
    pub sparse_dimension: usize,
    pub weight: usize,
    pub poly_length: usize,
    pub lwe_modulus: u32,
    pub ring_modulus: u64,
    pub br_base_log: u32,
    pub ks_base_log: u32,
    pub plaintext_modulus: u32,
    // Validated consumer candidate; None keeps the original comparison alone.
    pub candidate_br_levels: Option<usize>,
}

/// Largest primes below 2^28 / 2^54 congruent to one modulo 2N.
/// Table 3's powers of two describe the size of Q, not valid NTT moduli.
pub(super) const CASES: [Case; 3] = [
    Case {
        name: "std128_nand",
        dense_dimension: 503,
        sparse_dimension: 1024,
        weight: 43,
        poly_length: 1024,
        lwe_modulus: 512,
        ring_modulus: 268_369_921,
        br_base_log: 7,
        ks_base_log: 7,
        plaintext_modulus: 4,
        candidate_br_levels: Some(3),
    },
    Case {
        name: "medium_nand",
        // MEDIUM's dense dimension comes from the cited OpenFHE revision;
        // its q was 1024. Using Table 3's q=512 is an unassessed adaptation.
        dense_dimension: 422,
        sparse_dimension: 1024,
        weight: 31,
        poly_length: 1024,
        lwe_modulus: 512,
        ring_modulus: 268_369_921,
        // OpenFHE retains ceil(28/10)=3 digits. Our approximate basis retains
        // floor(28/10)=2, dropping eight low bits; do not call this an exact port.
        br_base_log: 10,
        ks_base_log: 7,
        plaintext_modulus: 4,
        candidate_br_levels: None,
    },
    Case {
        name: "std128_padded_func3",
        dense_dimension: 1350,
        sparse_dimension: 2048,
        weight: 70,
        poly_length: 2048,
        lwe_modulus: 4096,
        ring_modulus: 18_014_398_509_404_161,
        br_base_log: 27,
        ks_base_log: 5,
        plaintext_modulus: 16,
        candidate_br_levels: Some(1),
    },
];

/// The same sparse secret in classic mode isolates BR algorithm costs; dense
/// ternary follows OpenFHE's secret family but has a different dimension.
#[derive(Clone, Copy)]
pub(super) enum Mode {
    DenseClassic,
    FixedWeightClassic,
    Sparse,
    SparseCandidate,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::DenseClassic => "dense_ternary_classic",
            Self::FixedWeightClassic => "fixed_weight_classic",
            Self::Sparse => "sparse",
            Self::SparseCandidate => "sparse_candidate_r2",
        }
    }

    /// Original paper-shaped map or the separately validated r2/B=2h choice.
    /// Both retain every encrypted selector and dummy in online evaluation.
    pub fn sparse_counts(self, case: Case) -> Option<(usize, usize)> {
        match self {
            Self::Sparse => Some((3, case.weight + 3)),
            Self::SparseCandidate => Some((2, 2 * case.weight)),
            Self::DenseClassic | Self::FixedWeightClassic => None,
        }
    }
}

impl Case {
    pub fn dimension(self, mode: Mode) -> usize {
        match mode {
            Mode::DenseClassic => self.dense_dimension,
            Mode::FixedWeightClassic | Mode::Sparse | Mode::SparseCandidate => {
                self.sparse_dimension
            }
        }
    }

    /// Selects the actual secret support; no online loop skips encrypted zeros.
    pub fn secret(self, mode: Mode) -> SecretKeyDistr {
        match mode {
            Mode::DenseClassic => SecretKeyDistr::UniformTernary,
            Mode::FixedWeightClassic | Mode::Sparse | Mode::SparseCandidate => {
                SecretKeyDistr::fixed_hamming_weight_binary(self.sparse_dimension, self.weight)
            }
        }
    }

    /// A nonlinear map on all eight padded three-bit inputs. This is one PBS,
    /// unlike OpenFHE's full-domain arbitrary-function evaluation with two PBSes.
    pub fn function(self, message: usize) -> usize {
        (message * message + 3 * message + 1) & 7
    }

    /// OpenFHE's cited revision uses sigma=3.19 in coefficient units. Only
    /// the small-LWE sampler description is rescaled here: actual inputs are
    /// sampled at q in the harness. BR and our ring KS both use sigma=3.19 at Q.
    pub fn parameters<T: FheUint>(self, mode: Mode) -> TfheParameters<T, BarrettModulus<T>> {
        let modulus = BarrettModulus::new(T::as_from(self.ring_modulus));
        let decomposition = |base_log| DecompositionConfig {
            log_basis: DecompositionBaseLog::new(base_log),
            level_count: None,
        };
        TfheParameters::try_from_config(TfheConfig {
            small_lwe: LweEncryptionParameters::new(
                LweDimension::new(self.dimension(mode)),
                modulus,
                self.secret(mode),
                3.19 * self.ring_modulus as f64 / f64::from(self.lwe_modulus),
            ),
            accumulator_dimension: GlweDimension::new(1),
            poly_length: PolyLength::new(self.poly_length),
            accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
            accumulator_noise_standard_deviation: 3.19,
            blind_rotation: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(self.br_base_log),
                level_count: match mode {
                    Mode::SparseCandidate => Some(DecompositionLevelCount::new(
                        self.candidate_br_levels
                            .expect("this profile has no validated sparse candidate"),
                    )),
                    _ => None,
                },
            },
            key_switching: decomposition(self.ks_base_log),
            key_switching_noise_standard_deviation: 3.19,
            pbs_order: PbsOrder::BootstrapKeyswitch,
        })
        .unwrap()
    }
}
