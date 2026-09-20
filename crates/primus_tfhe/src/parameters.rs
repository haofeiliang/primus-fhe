//! Independent mathematical choices for circuit bootstrapping.

use primus_decompose::DecompositionConfig;

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
