//! Packed one-hot geometry shared by the NTT and Fourier CBS backends.

use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::RingContext;

use crate::{CircuitBootstrapParameters, TfheEvaluationError, TfheParameters};

/// Failure to bind one-hot CBS resources or compile its packed test polynomial.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OneHotBootstrapError {
    /// Missing or incompatible CBS/BR material, including sparse keys.
    #[error(transparent)]
    Evaluation(#[from] TfheEvaluationError),
    /// Chunk encoding requires plaintext modulus 2*M, with M=2^tau and tau>=1.
    #[error("one-hot CBS requires a power-of-two plaintext modulus of at least four")]
    InvalidPlaintextModulus,
    /// No nonempty guard interval fits around a selector's gadget group.
    #[error("one-hot CBS requires 2 * selector_count * padded_level_count <= N")]
    InsufficientCapacity,
    /// The full selector output cannot be represented by an allocation length.
    #[error("one-hot selector storage size overflow")]
    StorageSizeOverflow,
}

/// Packed test polynomial for negative blind rotation and all M one-hot selectors.
///
/// Let L be the output basis length, W=next_power_of_two(L), S=N/M and
/// A=N/(2*M*W). This stores `sum_{j=1-A}^{A} sum_l g_l X^(l-j*W)`
/// in the negacyclic ring. Gadget padding `L..W` is zero.
/// For a quantized phase `u_bar=S*m+W*e mod 2N` with `-A<=e<A`, the constant
/// coefficient of `X^(r*S-l) * T(X) * X^(-u_bar)` is `g_l*[r=m]`.
/// The lower endpoint is included; a midpoint belongs to the higher message.
/// In particular, selectors r>0 require a signed negacyclic extraction.
/// The default selector r=0 is included, rather than implicitly omitted.
#[derive(Clone, Debug)]
pub struct OneHotLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    selector_count: usize,
    level_count: usize,
    output_nlev_len: usize,
}

impl<T: FheUint> OneHotLookupTable<T> {
    /// Compiles from compatible TFHE/CBS parameters, before online evaluation.
    /// Requires t=2*M with M>=2 a power of two, and 2*M*W<=N.
    /// Checks coefficient-output storage size before allocating the polynomial.
    /// Input noise, encoding rounding and BR quantization must satisfy the guard
    /// condition on [`Self`]; shape checks do not establish that margin.
    /// NTRU evaluation errors require a separate output-noise budget.
    pub fn try_new<M, LM>(
        tfhe: &TfheParameters<T, M, LM>,
        cbs: &CircuitBootstrapParameters<T, M>,
    ) -> Result<Self, OneHotBootstrapError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
    {
        if !cbs.is_compatible(tfhe) {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters.into());
        }
        let t: usize = tfhe
            .plain_modulus_value()
            .try_into()
            .map_err(|_| OneHotBootstrapError::InvalidPlaintextModulus)?;
        if t < 4 || !t.is_power_of_two() {
            return Err(OneHotBootstrapError::InvalidPlaintextModulus);
        }
        let n = tfhe.poly_length();
        let selector_count = t / 2;
        let level_count = cbs.output_basis().decompose_length();
        let w = level_count.next_power_of_two();
        if selector_count > n / (2 * w) {
            return Err(OneHotBootstrapError::InsufficientCapacity);
        }
        let output_nlev_len = selector_count
            .checked_mul(cbs.output_nlev_len())
            .filter(|&len| len <= isize::MAX as usize / size_of::<T>())
            .ok_or(OneHotBootstrapError::StorageSizeOverflow)?;
        let a = n / (2 * selector_count * w);
        let modulus = tfhe.accumulator_ntru().cipher_modulus();
        let mut polynomial = PolynomialOwned::zero(n);
        // k=j+A avoids signed host arithmetic. Negative BR reads j=-e, so
        // j=1-A..=A gives the left-closed error window -A<=e<A.
        // Distinct (j,l) pairs cannot collide because L<=W and this support
        // spans fewer than N positions.
        let two_n_mask = 2 * n - 1;
        let n_mask = n - 1;
        for k in 1..=2 * a {
            let shift = (2 * n + a * w - k * w) & two_n_mask;
            for (level, scalar) in cbs.output_basis().scalar_iter().enumerate() {
                let exponent = (shift + level) & two_n_mask;
                polynomial.as_mut()[exponent & n_mask] = if exponent < n {
                    scalar
                } else {
                    modulus.reduce_neg(scalar)
                };
            }
        }
        Ok(Self {
            polynomial,
            selector_count,
            level_count,
            output_nlev_len,
        })
    }

    /// Returns the negacyclic test polynomial, before any blind rotation.
    #[must_use]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns M, including the explicit default selector r=0.
    #[must_use]
    pub fn selector_count(&self) -> usize {
        self.selector_count
    }

    /// Returns L, in `output_basis.scalar_iter()` order, excluding padding.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.level_count
    }

    /// Returns W, the power-of-two BR quantization step and padded gadget width.
    #[must_use]
    pub fn rotation_step(&self) -> usize {
        self.level_count.next_power_of_two()
    }

    /// Returns S=N/M, the spacing between selector groups.
    #[must_use]
    pub fn selector_stride(&self) -> usize {
        self.polynomial.as_ref().len() / self.selector_count
    }

    /// Returns A for the quantized-phase error window `-A<=e<A`, in units of W.
    #[must_use]
    pub fn guard_radius(&self) -> usize {
        self.selector_stride() / (2 * self.rotation_step())
    }

    /// Returns M*L*N, the length of the complete coefficient-domain NLEV batch.
    /// Layout is `[selector][level][coefficient]`, without gadget padding.
    #[must_use]
    pub fn output_nlev_len(&self) -> usize {
        self.output_nlev_len
    }
}
