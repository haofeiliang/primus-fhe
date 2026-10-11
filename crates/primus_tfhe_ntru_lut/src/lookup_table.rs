use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
#[cfg(any(feature = "ntt", feature = "fourier"))]
use primus_tfhe_ntru::OneHotBootstrapError;

#[cfg(any(feature = "ntt", feature = "fourier"))]
mod buffer_lengths;
mod compile;

use crate::ChunkFormat;

/// Chunk counts and the split between table selection and coefficient selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupTableConfig {
    /// Positive number of input chunks, ordered from least to most significant.
    pub input_chunk_count: usize,
    /// Positive number of output chunks, independently chosen, least significant first.
    pub output_chunk_count: usize,
    /// Number of low input chunks selecting a coefficient within a polynomial.
    /// May be zero or all input chunks; M raised to this count must fit in N.
    /// For fixed N and M, increasing this count reduces worst-case table storage and CMux
    /// work, at the cost of one more rotation product per output chunk.
    pub coefficient_chunk_count: usize,
}

/// Invalid table geometry, encoding, storage size or bound evaluation resources.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// Chunk outputs cannot be represented by a Rounded codec at accumulator Q.
    #[error("invalid high-precision output encoding")]
    OutputEncoding(#[from] primus_encoding::CodecError),
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
    /// A combined width exceeds u32, or a domain/buffer size exceeds host indexing.
    #[error("high-precision lookup bit count, domain or storage size overflow")]
    StorageSizeOverflow,
    /// A callback returned a value outside the unsigned chunk domain.
    #[error("output chunk {output} at input {input} is outside 0..M")]
    OutputChunkOutOfRange {
        /// Full unsigned input index.
        input: usize,
        /// Output chunk index.
        output: usize,
    },
    /// The chosen cleartext integer cannot hold the complete input or output.
    #[error("lookup needs {required} cleartext bits, but the integer holds {available}")]
    WordCapacity {
        /// Required input or output bit count.
        required: u32,
        /// Capacity of the selected cleartext integer.
        available: u32,
    },
    /// An integer callback result exceeds the independently configured output width.
    #[error("function result at input {input} exceeds the output bit count")]
    OutputValueOutOfRange {
        /// Full unsigned input index.
        input: usize,
    },
    /// The table was compiled with another N, Q or external q.
    #[error("lookup table and context have incompatible ring or encoding parameters")]
    IncompatibleParameters,
    /// With no table-selection chunks (c=d), no `NLEV[1]` was supplied to lift the table.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    #[error("lookup selection requires a public NLEV lift key")]
    MissingPublicLiftKey,
    /// The supplied NLEV length or its parameters do not match the accumulator ring.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    #[error("public NLEV lift key has incompatible parameters or storage length")]
    IncompatiblePublicLiftKey,
    /// The context/server material cannot provide the required one-hot CBS.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    #[error(transparent)]
    OneHot(#[from] OneHotBootstrapError),
    /// Independent return material is incompatible with the TFHE context.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    #[error(transparent)]
    Evaluation(#[from] primus_tfhe::TfheEvaluationError),
}

/// Validated geometry of the complete public table and its fixed selection tree.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    /// Input/output chunk counts and the low-chunk/table-chunk partition.
    pub config: LookupTableConfig,
    /// Number M of possible values per padded chunk: half the plaintext modulus.
    pub radix: usize,
    /// Uniform chunk format derived from the input codec's t=2*M.
    pub chunk_format: ChunkFormat,
    /// Validated total unsigned input width tau*c, below usize::BITS.
    #[cfg_attr(
        not(any(feature = "ntt", feature = "fourier")),
        expect(
            dead_code,
            reason = "Validated widths are retained for backend client adapters"
        )
    )]
    pub input_bits: u32,
    /// Validated total unsigned output width tau*o, which may exceed word capacity.
    #[cfg_attr(
        not(any(feature = "ntt", feature = "fourier")),
        expect(
            dead_code,
            reason = "Validated widths are retained for backend client adapters"
        )
    )]
    pub output_bits: u32,
    /// Ring degree N, including each polynomial's zero-padded tail.
    pub polynomial_length: usize,
    /// Complete input domain size M^c, which must fit in usize.
    pub input_value_count: usize,
    /// Number K=M^d of meaningful coefficients in each polynomial.
    pub entries_per_polynomial: usize,
    /// Number P=M^(c-d) of stored polynomials per output chunk.
    pub polynomials_per_output: usize,
}

impl Layout {
    /// Derives the chunk geometry and checks domain size and coefficient capacity.
    /// Allocation sizes are checked separately during compilation; this allocates nothing.
    pub(crate) fn try_new<T: FheUint>(
        plaintext_modulus: T,
        polynomial_length: usize,
        config: LookupTableConfig,
    ) -> Result<Self, LookupTableError> {
        let chunk_format = ChunkFormat::from_plaintext_modulus(plaintext_modulus)
            .ok_or(LookupTableError::InvalidPlaintextModulus)?;
        if config.input_chunk_count == 0 || config.output_chunk_count == 0 {
            return Err(LookupTableError::EmptyChunks);
        }
        if config.coefficient_chunk_count > config.input_chunk_count {
            return Err(LookupTableError::InvalidCoefficientChunkCount);
        }

        let radix = chunk_format.radix();
        let chunk_bits = chunk_format.bits();
        let input_bits = chunk_format
            .checked_bit_count(config.input_chunk_count)
            .filter(|&bits| bits < usize::BITS)
            .ok_or(LookupTableError::StorageSizeOverflow)?;
        // The complete M^c-entry domain is enumerated. Its size, not just
        // its largest input value, must fit in usize.
        let input_value_count = 1usize << input_bits;
        // d <= c makes this shift safe after the input-bit-count check.
        let coefficient_bits = chunk_bits * config.coefficient_chunk_count as u32;
        let entries_per_polynomial = 1usize << coefficient_bits;
        if entries_per_polynomial > polynomial_length {
            return Err(LookupTableError::InsufficientCapacity);
        }
        let polynomials_per_output = input_value_count / entries_per_polynomial;
        let output_bits = chunk_format
            .checked_bit_count(config.output_chunk_count)
            .ok_or(LookupTableError::StorageSizeOverflow)?;
        Ok(Self {
            config,
            radix,
            chunk_format,
            input_bits,
            output_bits,
            polynomial_length,
            input_value_count,
            entries_per_polynomial,
            polynomials_per_output,
        })
    }

    /// Number h=c-d of selection layers; zero means one public polynomial per output.
    #[must_use]
    pub fn table_chunk_count(self) -> usize {
        self.config.input_chunk_count - self.config.coefficient_chunk_count
    }
}

/// Computes an element count, checking multiplication and the isize::MAX byte limit.
/// Requires a nonzero-sized T. Does not allocate or check available memory.
pub(crate) fn checked_allocation_len<T>(factors: &[usize]) -> Result<usize, LookupTableError> {
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
/// coefficients K..N are zero. Storage is contiguous in
/// `[output chunk][table prefix][coefficient]` order, including repeated polynomials.
/// Every output uses the complete selection tree, regardless of table contents.
/// All polynomial exponents are nonnegative.
/// The evaluator selects polynomial p, rotates by X^(-z), then returns its
/// constant coefficient at q under the external LWE secret.
///
/// Unlike an ordinary PBS LUT, this data table does not repeat function values
/// to tolerate input noise. One-hot CBS provides that guard before selection;
/// the subsequent encrypted choices still carry additive ciphertext noise.
pub struct HighPrecisionLookupTable<T: FheUint> {
    pub(crate) layout: Layout,
    coefficients: Box<[T]>,
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
    /// Compilation needs no keys, secret distributions, noise samplers or transforms.
    /// `input_codec` fixes external q and chunk modulus t; `ring_modulus` fixes
    /// accumulator Q. The evaluator checks these domains against its context.
    /// All chunks use unsigned Rounded encoding with t=2*M from `input_codec`.
    /// The input value count M^c must fit in usize, so tau*c < usize::BITS.
    /// This is a limit of full table enumeration, not of the cryptographic
    /// construction. Total input/output bit counts must fit u32; the output
    /// need not fit one machine word. These limits precede table allocation.
    /// Storage grows exponentially with input chunk count;
    /// representable sizes do not guarantee available memory.
    pub fn try_new<M, LM, F>(
        poly_length: PolyLength,
        ring_modulus: M,
        input_codec: &RoundedCodec<T, LM>,
        config: LookupTableConfig,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
        F: FnMut(usize, usize) -> T,
    {
        let layout = Layout::try_new(input_codec.plaintext_modulus(), poly_length.get(), config)?;
        let output_codec = RoundedCodec::try_new(input_codec.plaintext_modulus(), ring_modulus)?;
        let mut function = function;
        Self::compile(&output_codec, input_codec, layout, |x, output| {
            Ok(function(x, output))
        })
    }

    /// Compiles using the accumulator N/Q and external q from TFHE parameters.
    /// The codec's q must match the external LWE domain; a mismatch is rejected
    /// before allocation or callbacks. This needs no context, keys or transforms
    /// and delegates to [`Self::try_new`] without creating another codec.
    ///
    /// Available with `ntt` or `fourier`. The backend-independent entry remains
    /// [`Self::try_new`] for offline compilation without TFHE parameters.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    pub fn try_from_parameters<M, LM, F>(
        parameters: &primus_tfhe_ntru::PbsParameters<T, M, LM>,
        input_codec: &RoundedCodec<T, LM>,
        config: LookupTableConfig,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
        F: FnMut(usize, usize) -> T,
    {
        if input_codec.ciphertext_modulus().explicit_value()
            != parameters.external_lwe().cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::IncompatibleParameters);
        }
        Self::try_new(
            parameters.poly_length(),
            parameters.accumulator_ntru().cipher_modulus(),
            input_codec,
            config,
            function,
        )
    }

    /// Returns the common input/output chunk plaintext modulus t=2*M.
    /// Input and returned ciphertexts use this Rounded encoding at external q;
    /// public table coefficients are encoded at accumulator Q.
    #[must_use]
    pub fn plaintext_modulus(&self) -> T {
        self.plaintext_modulus
    }

    /// Returns the input/output counts and coefficient/table split.
    #[must_use]
    pub fn config(&self) -> LookupTableConfig {
        self.layout.config
    }

    /// Returns tau, the common input and output chunk bit width.
    #[must_use]
    pub fn chunk_bits(&self) -> u32 {
        self.layout.chunk_format.bits()
    }

    /// Returns the uniform format fixed by this table's input codec.
    /// Counts and the coefficient/table partition remain in [`Self::config`].
    #[must_use]
    pub fn chunk_format(&self) -> ChunkFormat {
        self.layout.chunk_format
    }

    /// Returns M raised to the input chunk count, the complete input domain size.
    #[must_use]
    pub fn input_value_count(&self) -> usize {
        self.layout.input_value_count
    }

    /// Returns the stored polynomial count per output chunk, P=M^(c-d).
    /// This equals the number of high-chunk value combinations.
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

    /// Whether c=d, so the sole public polynomial needs a bound `NLEV[1]` lift.
    /// When c>d, the first selection layer lifts through its full one-hot NLEV batch.
    #[must_use]
    pub fn needs_public_lift(&self) -> bool {
        self.layout.table_chunk_count() == 0
    }

    /// Returns the encoded polynomial for one logical output chunk and high-chunk prefix.
    ///
    /// # Panics
    /// Panics if either index exceeds its configured range.
    #[must_use]
    pub fn polynomial(&self, output_chunk: usize, table_prefix: usize) -> Polynomial<&[T]> {
        assert!(
            output_chunk < self.config().output_chunk_count,
            "lookup output chunk out of range"
        );
        assert!(
            table_prefix < self.polynomials_per_output(),
            "lookup table prefix out of range"
        );
        let n = self.layout.polynomial_length;
        let first = (output_chunk * self.polynomials_per_output() + table_prefix) * n;
        Polynomial::new(&self.coefficients[first..first + n])
    }

    /// Borrows one output's P complete polynomials in ascending prefix order.
    /// The evaluator supplies a valid output index from the validated request.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    #[must_use]
    pub(crate) fn output_polynomials(&self, output_chunk: usize) -> &[T] {
        let len = self.layout.polynomials_per_output * self.layout.polynomial_length;
        &self.coefficients[output_chunk * len..(output_chunk + 1) * len]
    }

    /// Checks N, q and Q; the compiled program owns its chunk encoding t.
    /// Key identity and noise margins are not table properties.
    #[must_use]
    pub fn is_compatible<M: RingContext<T>, LM: RingContext<T>>(
        &self,
        poly_length: PolyLength,
        ring_modulus: M,
        input_modulus: LM,
    ) -> bool {
        self.layout.polynomial_length == poly_length.get()
            && self.input_modulus == input_modulus.explicit_value()
            && self.ring_modulus == ring_modulus.explicit_value()
    }
}
