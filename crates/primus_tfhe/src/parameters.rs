//! Mathematical choices whose modulus and layout are supplied by a backend.

use primus_decompose::{ApproxSignedBasisError, primitive::ApproxSignedBasis};
use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Signed gadget decomposition before binding it to a ciphertext modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompositionConfig {
    /// Base-2 logarithm of the radix; must lie in `2..T::BITS`.
    pub log_basis: u32,
    /// Retained high levels, or `None` for the full decomposition.
    /// A specified count must be nonzero and no larger than the full count.
    pub level_count: Option<usize>,
}

impl DecompositionConfig {
    /// Prepares the basis in `modulus`, checking [`ApproxSignedBasis::try_new`]'s
    /// radix and retained-level constraints.
    pub fn try_build<T: FheUint>(
        self,
        modulus: impl RingContext<T>,
    ) -> Result<ApproxSignedBasis<T>, ApproxSignedBasisError> {
        ApproxSignedBasis::try_new(modulus.explicit_value(), self.log_basis, self.level_count)
    }
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
