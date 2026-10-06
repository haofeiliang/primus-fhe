//! Independent choices for evaluation keys and bootstrapping.

use primus_decompose::DecompositionConfig;

/// Gadget decomposition and row-encryption noise for one evaluation-key role.
///
/// By default, `D` is [`DecompositionConfig`], resolved at parameter construction.
/// Constructors that accept a prepared basis use it as `D` and take ownership
/// without rebuilding it.
/// The consuming constructor supplies the key's layout and modulus and validates
/// the choices; this configuration alone does not establish a noise/security budget.
#[derive(Debug, Clone, Copy)]
pub struct GadgetEncryptionConfig<D = DecompositionConfig> {
    /// Decomposition choices or an already prepared basis, as required by the constructor.
    pub decomposition: D,
    /// Encryption noise standard deviation in coefficient units at the key's modulus.
    /// Each key role selects its noise independently of fresh ciphertext encryption.
    pub noise_standard_deviation: f64,
}

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
    /// This selects the output encoding, not a separate key's encryption noise.
    pub output: DecompositionConfig,
    /// Reverse-trace key decomposition and noise at the accumulator modulus.
    pub trace: GadgetEncryptionConfig,
    /// Scheme-switch key decomposition and noise at the accumulator modulus.
    pub scheme_switch: GadgetEncryptionConfig,
}
