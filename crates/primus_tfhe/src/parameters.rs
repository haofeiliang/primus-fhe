//! Independent choices for blind rotation and circuit bootstrapping.

use primus_decompose::DecompositionConfig;

/// Blind-rotation algorithm used to generate evaluation material for an existing client.
///
/// This choice does not change the secret distribution in TFHE parameters. A fixed-weight
/// binary secret can use either algorithm; selecting sparse with an unsupported distribution
/// is an error, never a request to resample the secret or fall back to classic.
/// Backend key generation validates bucket geometry against the actual secret and ciphertext
/// layout. This configuration carries no keys, return policy, CBS material or runtime scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRotationConfig {
    /// Per-coordinate binary or ternary CMux controls, including fixed-weight distributions.
    Classic,
    /// Bucketed controls for a fixed-weight binary secret with weight `0 < h < n`.
    /// Matching retries the public map while keeping the client secret fixed.
    Sparse {
        /// Number of distinct buckets containing each input index; must be at least one.
        copy_count: usize,
        /// Number of buckets; must be at least `max(copy_count, h)`.
        bucket_count: usize,
    },
}

/// Independent choices for circuit-bootstrap output, trace and scheme switching.
///
/// The backend derives the modulus, ring layout and secret distribution from
/// its TFHE accumulator. Noise standard deviations are in coefficient units;
/// no security or failure-rate defaults are supplied.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBootstrapConfig {
    /// Gadget scalars encoded by the output GGSW/NGSW.
    pub output: DecompositionConfig,
    /// Decomposition used by reverse-trace key switching.
    pub trace: DecompositionConfig,
    /// Standard deviation for trace-key encryption.
    pub trace_noise_standard_deviation: f64,
    /// Decomposition used by scheme switching.
    pub scheme_switch: DecompositionConfig,
    /// Standard deviation for scheme-switch-key encryption.
    pub scheme_switch_noise_standard_deviation: f64,
}
