use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};

use super::{LookupTableEncoding, compile::compile_front_half};
use crate::LookupTableError;

/// Fixed-scale multi-value bootstrapping (MVB) via negacyclic differences.
///
/// For each output, let `p_i` be the unscaled integer front-half LUT, including
/// its signed tail. This stores `V = (delta/2) * (1 + X + ... + X^(N-1))`
/// and `W_i = (1-X)*p_i` modulo an odd `q`, so `V*W_i = delta*p_i` in
/// `Z_q[X]/(X^N+1)`. The division by two is modular and occurs only in the
/// noiseless public `V`. Factors are reduced modulo **q**, never the plaintext
/// modulus. Backends blind-rotate `V` once at step one, then multiply by each
/// factor. Output count does not reduce the input's rotation resolution.
///
/// Inputs use unsigned rounded encoding; all outputs share unsigned fixed-scale
/// encoding. Multiplication amplifies BR error by the integer factor: a bound is
/// `||W_i||_1 * ||e_BR||_infinity`. Compilation checks geometry and output values,
/// not a sufficient noise budget. The type owns no keys or transform tables.
#[derive(Clone, Debug)]
pub struct FactorizedLookupTable<T: FheUint> {
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<PolynomialOwned<T>>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
    encoding: LookupTableEncoding<T>,
}

impl<T: FheUint> FactorizedLookupTable<T> {
    /// Compiles `function(input, output_index)` over a nonempty front-half prefix.
    ///
    /// Requires `1 <= input_domain_len <= ceil(t_in/2)`, valid single-output
    /// rotation geometry, a positive `output_count` and an explicit odd output
    /// ciphertext modulus. Output count need not be a power of two or at most N.
    /// Each result must be below `output_codec.plaintext_modulus()`.
    /// On success the callback runs once per pair, with `output_index` outermost
    /// and increasing input indices within each output.
    ///
    /// The input modulus may differ from the coefficient/output modulus in this
    /// shared representation; a backend may impose a stricter compatibility
    /// requirement. Retain `output_codec` to decode extracted LWE phases.
    pub fn try_new<LM, M, F>(
        input_domain_len: usize,
        poly_length: usize,
        output_count: usize,
        input_codec: &RoundedCodec<T, LM>,
        output_codec: &ScaledCodec<T, M>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        LM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        if output_count == 0 {
            return Err(LookupTableError::EmptyOutputs);
        }
        let modulus = output_codec.ciphertext_modulus();
        let q = modulus
            .explicit_value()
            .filter(|q| *q % T::TWO == T::ONE)
            .ok_or(LookupTableError::UnsupportedFactorizationModulus)?;
        let factors = (0..output_count)
            .map(|output_index| {
                let mut factor = compile_front_half(
                    input_domain_len,
                    poly_length,
                    1,
                    input_codec.plaintext_modulus(),
                    input_codec.ciphertext_modulus(),
                    modulus,
                    |input, _| {
                        let value = function(input, output_index);
                        if value >= output_codec.plaintext_modulus() {
                            return Err(LookupTableError::OutputOutOfRange { input });
                        }
                        Ok(value)
                    },
                )?;
                // Multiplication by (1-X) in the negacyclic ring: the wrapped
                // last coefficient adds at index zero. Reverse traversal keeps
                // each predecessor intact, including when the negative tail is empty.
                let coefficients = factor.as_mut();
                let seam = modulus.reduce_add(coefficients[0], coefficients[poly_length - 1]);
                for index in (1..poly_length).rev() {
                    coefficients[index] =
                        modulus.reduce_sub(coefficients[index], coefficients[index - 1]);
                }
                coefficients[0] = seam;
                Ok(factor)
            })
            .collect::<Result<Vec<_>, LookupTableError>>()?;
        let delta = output_codec.encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        // q is odd, hence (q/2 + 1) is its inverse of two. Scale V before BR;
        // applying this inverse to the noisy BR output would magnify its error.
        let half_scale = modulus.reduce_mul(delta, q / T::TWO + T::ONE);
        Ok(Self {
            common_polynomial: PolynomialOwned::new(vec![half_scale; poly_length]),
            factors,
            input_domain_len,
            output_plaintext_modulus: output_codec.plaintext_modulus(),
            encoding: LookupTableEncoding {
                input_plaintext_modulus: input_codec.plaintext_modulus(),
                input_ciphertext_modulus: input_codec.ciphertext_modulus().explicit_value(),
                coefficient_modulus: Some(q),
            },
        })
    }

    /// Returns the programmed input prefix length.
    #[must_use]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the number of factors and extracted outputs, without padding.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.factors.len()
    }

    /// Returns the plaintext modulus of the shared unsigned Scaled output codec.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }

    /// Checks the ring length and input/coefficient moduli, not keys or noise.
    /// The input message must also lie in [`Self::input_domain_len`].
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        coefficient_modulus: Option<T>,
    ) -> bool {
        self.common_polynomial.as_ref().len() == poly_length
            && self.encoding.is_compatible(
                input_plaintext_modulus,
                input_ciphertext_modulus,
                coefficient_modulus,
            )
    }

    /// Returns V in coefficient form, ready to initialize blind rotation.
    #[must_use]
    pub fn common_polynomial(&self) -> &PolynomialOwned<T> {
        &self.common_polynomial
    }

    /// Returns the coefficient-domain W_i, stored as canonical residues modulo q.
    /// Use their small signed integer lifts when computing noise amplification.
    #[must_use]
    pub fn factors(&self) -> &[PolynomialOwned<T>] {
        &self.factors
    }

    /// Consumes this table for backend preparation, returning V and all W_i.
    #[must_use]
    pub fn into_polynomials(self) -> (PolynomialOwned<T>, Vec<PolynomialOwned<T>>) {
        (self.common_polynomial, self.factors)
    }
}
