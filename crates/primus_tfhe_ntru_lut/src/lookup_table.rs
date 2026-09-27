use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::{OneHotBootstrapError, TfheParameters};

/// Chunk counts and the split between table selection and coefficient selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupTableConfig {
    /// Positive number of input chunks, ordered from least to most significant.
    pub input_chunk_count: usize,
    /// Positive number of output chunks, independently chosen, least significant first.
    pub output_chunk_count: usize,
    /// Number of low input chunks selecting a coefficient within a polynomial.
    /// May be zero or all input chunks; M raised to this count must fit in N.
    /// For fixed N and M, increasing this count reduces table storage and CMux
    /// work, at the cost of one more rotation product per output chunk.
    pub coefficient_chunk_count: usize,
}

/// Invalid table geometry, encoding, storage size or bound evaluation resources.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// One-hot chunks need t=2*M with M>=2 a power of two.
    #[error("high-precision lookup requires a power-of-two plaintext modulus of at least four")]
    InvalidPlaintextModulus,
    /// At least one input and one output chunk are required.
    #[error("input and output chunk counts must be positive")]
    EmptyChunks,
    /// The coefficient suffix cannot contain more chunks than the input.
    #[error("coefficient chunk count exceeds input chunk count")]
    InvalidCoefficientChunkCount,
    /// The coefficient suffix does not fit in one ring polynomial.
    #[error("coefficient selection domain exceeds the polynomial length")]
    InsufficientCapacity,
    /// A domain, buffer length or byte size exceeds host indexing limits.
    #[error("high-precision lookup domain or storage size overflow")]
    StorageSizeOverflow,
    /// A callback returned a value outside the unsigned chunk domain.
    #[error("output chunk {output} at input {input} is outside 0..M")]
    OutputChunkOutOfRange {
        /// Full unsigned input index.
        input: usize,
        /// Output chunk index.
        output: usize,
    },
    /// The table was compiled with another N, t, Q or q.
    #[error("lookup table and context have incompatible ring or encoding parameters")]
    IncompatibleParameters,
    /// The context/server material cannot provide the required one-hot CBS.
    #[error(transparent)]
    OneHot(#[from] OneHotBootstrapError),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    pub config: LookupTableConfig,
    pub radix: usize,
    pub chunk_bits: usize,
    pub polynomial_length: usize,
    pub input_value_count: usize,
    pub entries_per_polynomial: usize,
    pub polynomials_per_output: usize,
}

impl Layout {
    fn try_new<T: FheUint>(
        plaintext_modulus: T,
        polynomial_length: usize,
        config: LookupTableConfig,
    ) -> Result<Self, LookupTableError> {
        let plaintext_modulus: usize = plaintext_modulus
            .try_into()
            .map_err(|_| LookupTableError::InvalidPlaintextModulus)?;
        if plaintext_modulus < 4 || !plaintext_modulus.is_power_of_two() {
            return Err(LookupTableError::InvalidPlaintextModulus);
        }
        if config.input_chunk_count == 0 || config.output_chunk_count == 0 {
            return Err(LookupTableError::EmptyChunks);
        }
        if config.coefficient_chunk_count > config.input_chunk_count {
            return Err(LookupTableError::InvalidCoefficientChunkCount);
        }

        let radix = plaintext_modulus / 2;
        let chunk_bits = radix.trailing_zeros() as usize;
        let input_bit_count = chunk_bits
            .checked_mul(config.input_chunk_count)
            .filter(|&bits| bits < usize::BITS as usize)
            .ok_or(LookupTableError::StorageSizeOverflow)?;
        // The complete M^c-entry domain is materialized. Its size, not just
        // its largest input value, must fit in usize.
        let input_value_count = 1usize << input_bit_count;
        // d <= c makes this shift safe after the input-bit-count check.
        let entries_per_polynomial = 1usize << (chunk_bits * config.coefficient_chunk_count);
        if entries_per_polynomial > polynomial_length {
            return Err(LookupTableError::InsufficientCapacity);
        }
        let polynomials_per_output = input_value_count / entries_per_polynomial;
        Ok(Self {
            config,
            radix,
            chunk_bits,
            polynomial_length,
            input_value_count,
            entries_per_polynomial,
            polynomials_per_output,
        })
    }

    pub fn table_chunk_count(self) -> usize {
        self.config.input_chunk_count - self.config.coefficient_chunk_count
    }

    pub fn candidate_count(self) -> usize {
        self.polynomials_per_output / self.radix
    }

    pub fn check_io<T: FheUint>(
        self,
        input: &[LweCiphertext<T>],
        output: &[LweCiphertext<T>],
        dimension: usize,
    ) {
        assert_eq!(
            input.len(),
            self.config.input_chunk_count,
            "lookup input chunk count mismatch"
        );
        assert_eq!(
            output.len(),
            self.config.output_chunk_count,
            "lookup output chunk count mismatch"
        );
        assert!(
            input.iter().all(|c| c.dimension() == dimension),
            "lookup input LWE dimension mismatch"
        );
        assert!(
            output.iter().all(|c| c.dimension() == dimension),
            "lookup output LWE dimension mismatch"
        );
    }
}

pub(crate) fn allocation_len<T>(factors: &[usize]) -> Result<usize, LookupTableError> {
    factors
        .iter()
        .try_fold(1usize, |len, &factor| len.checked_mul(factor))
        .filter(|&len| len <= isize::MAX as usize / size_of::<T>())
        .ok_or(LookupTableError::StorageSizeOverflow)
}

/// Public output-chunk polynomials for a uniform radix M=2^tau lookup.
///
/// Input x is `sum_i m_i*M^i`. With d coefficient chunks, each polynomial
/// holds K=M^d table entries: z=x mod K selects a coefficient and p=x/K
/// selects a polynomial. Polynomial p stores `E_Q(F(p*K+z,j))` at coefficient
/// z for output chunk j. Each polynomial has N coefficients; its unused
/// coefficients K..N are zero. Storage is
/// `[output chunk][table prefix][coefficient]`; all exponents are nonnegative.
/// The evaluator selects polynomial p, rotates by X^(-z), then returns its
/// constant coefficient at q under the external LWE secret.
///
/// Unlike an ordinary PBS LUT, this data table does not repeat function values
/// to tolerate input noise. One-hot CBS provides that guard before selection;
/// the subsequent encrypted choices still carry additive ciphertext noise.
pub struct HighPrecisionLookupTable<T: FheUint> {
    pub(crate) layout: Layout,
    pub(crate) coefficients: Vec<T>,
    plaintext_modulus: T,
    input_modulus: Option<T>,
    ring_modulus: Option<T>,
}

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Compiles an arbitrary finite mapping by enumerating every input value
    /// and every output chunk in the complete domain.
    /// The callback receives `(x, output_chunk)` and must return a digit in 0..M.
    /// It is called in output-major order, then ascending x, once per pair.
    /// Geometry and host storage overflow are checked before allocation/callbacks;
    /// a bad callback value stops compilation at that pair.
    ///
    /// All chunks use unsigned Rounded encoding with t=2*M from `parameters`.
    /// The input value count M^c must fit in usize, so tau*c < usize::BITS.
    /// This is a limit of full table enumeration, not of the cryptographic
    /// construction. Storage grows exponentially with input chunk count;
    /// representable sizes do not guarantee available memory.
    pub fn try_new<M, LM, F>(
        parameters: &TfheParameters<T, M, LM>,
        config: LookupTableConfig,
        mut function: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
        F: FnMut(usize, usize) -> T,
    {
        let layout = Layout::try_new(
            parameters.plain_modulus_value(),
            parameters.poly_length(),
            config,
        )?;
        let len = allocation_len::<T>(&[
            config.output_chunk_count,
            layout.polynomials_per_output,
            layout.polynomial_length,
        ])?;
        let mut coefficients = vec![T::ZERO; len];
        let codec = RoundedCodec::new(
            parameters.plain_modulus_value(),
            parameters.accumulator_ntru().cipher_modulus(),
        );
        let digit_limit = parameters.plain_modulus_value() >> 1u32;
        for (output_chunk, polynomials) in coefficients
            .chunks_exact_mut(layout.polynomials_per_output * layout.polynomial_length)
            .enumerate()
        {
            for (table_prefix, polynomial) in polynomials
                .chunks_exact_mut(layout.polynomial_length)
                .enumerate()
            {
                // x = prefix*K + z: high chunks choose this polynomial, low
                // chunks choose coefficient z. The remaining N-K slots stay zero.
                let first_input_value = table_prefix * layout.entries_per_polynomial;
                for (coefficient_index, coefficient) in polynomial[..layout.entries_per_polynomial]
                    .iter_mut()
                    .enumerate()
                {
                    let input_value = first_input_value + coefficient_index;
                    let digit = function(input_value, output_chunk);
                    if digit >= digit_limit {
                        return Err(LookupTableError::OutputChunkOutOfRange {
                            input: input_value,
                            output: output_chunk,
                        });
                    }
                    *coefficient = codec.encode_value(digit, PlaintextEmbedding::Unsigned);
                }
            }
        }
        Ok(Self {
            layout,
            coefficients,
            plaintext_modulus: parameters.plain_modulus_value(),
            input_modulus: parameters.external_lwe().cipher_modulus_value(),
            ring_modulus: parameters.accumulator_ntru().cipher_modulus_value(),
        })
    }

    /// Returns the input/output counts and coefficient/table split.
    #[must_use]
    pub fn config(&self) -> LookupTableConfig {
        self.layout.config
    }

    /// Returns tau, the common input and output chunk bit width.
    #[must_use]
    pub fn chunk_bits(&self) -> usize {
        self.layout.chunk_bits
    }

    /// Returns M raised to the input chunk count, the complete input domain size.
    #[must_use]
    pub fn input_value_count(&self) -> usize {
        self.layout.input_value_count
    }

    /// Returns the number of public polynomials per output chunk.
    #[must_use]
    pub fn polynomials_per_output(&self) -> usize {
        self.layout.polynomials_per_output
    }

    /// Returns the number of table entries stored in each polynomial, M^d <= N.
    /// This counts meaningful LUT positions, including any encoded zero values;
    /// the backing polynomial always has N coefficients, with M^d..N zero-filled.
    #[must_use]
    pub fn entries_per_polynomial(&self) -> usize {
        self.layout.entries_per_polynomial
    }

    /// Returns the encoded Q-domain coefficients in `[output][prefix][coefficient]` order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.coefficients
    }

    /// Checks N, t, q and Q; key identity and noise margins are not table properties.
    #[must_use]
    pub fn is_compatible<M: RingContext<T>, LM: RingContext<T>>(
        &self,
        parameters: &TfheParameters<T, M, LM>,
    ) -> bool {
        self.layout.polynomial_length == parameters.poly_length()
            && self.plaintext_modulus == parameters.plain_modulus_value()
            && self.input_modulus == parameters.external_lwe().cipher_modulus_value()
            && self.ring_modulus == parameters.accumulator_ntru().cipher_modulus_value()
    }
}
