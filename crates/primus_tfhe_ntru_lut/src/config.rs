//! Transform-independent lookup preparation and public function compilation.

use primus_integer::{FheUint, UnsignedInteger};
use primus_reduce::RingContext;
use primus_tfhe::RoundedPbsCodecs;
use primus_tfhe_ntru::{
    CbsConfig, CbsParameters, LweReturnParameters, PbsParameters, TfheParameterError,
};

use crate::lookup_table::Layout;
use crate::{ChunkFormat, HighPrecisionLookupTable, LookupTableConfig, LookupTableError};

/// Complete high-precision lookup choices, independent of the public function.
///
/// One-hot's input modulus fixes the common chunk radix M=t/2. Counts are
/// independent. Preparation does not establish the phase guard or joint noise budget.
#[derive(Debug, Clone, Copy)]
pub struct HighPrecLutConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// CBS input/BR/return domains and the three gadget decompositions.
    pub one_hot: CbsConfig<T, M, LM>,
    /// Positive input chunk count, ordered from least to most significant.
    pub input_chunk_count: usize,
    /// Positive output chunk count, independent of the input count.
    pub output_chunk_count: usize,
    /// Low chunks selecting a coefficient; None uses min(c, floor(log2(N)/tau)).
    /// An explicit count may be zero or all input chunks, provided M^d<=N.
    pub coefficient_chunk_count: Option<usize>,
}

/// Failure to prepare complete high-precision operation parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum HighPrecLutParameterError {
    /// BR, CBS or return sampling/decomposition parameters are invalid.
    #[error(transparent)]
    Tfhe(#[from] TfheParameterError),
    /// Chunk geometry or output encoding is invalid.
    #[error(transparent)]
    Layout(#[from] LookupTableError),
    /// Input/output chunks cannot be encoded at their q/Q domains.
    #[error(transparent)]
    Encoding(#[from] primus_tfhe::LookupTableError),
}

/// Complete lookup state, before constructing a transform table or any keys.
/// Contains one CBS domain, required return parameters, checked geometry and
/// q/Q encodings. Public compilation works directly from this offline owner.
#[derive(Clone)]
pub struct HighPrecLutParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    pub(crate) one_hot: CbsParameters<T, M, LM>,
    pub(crate) lookup: LookupDomain<T, M, LM>,
}

/// Lookup-only geometry/encoding, moved beside the backend's single CBS owner.
/// Keeps compilation and client chunk handling common to NTT and Fourier;
/// it contains no secrets, transform table or evaluation buffers.
#[derive(Clone)]
pub(crate) struct LookupDomain<T: FheUint, M: RingContext<T>, LM: RingContext<T>> {
    pub(crate) layout: Layout,
    pub(crate) codecs: RoundedPbsCodecs<T, M, LM>,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> HighPrecLutParameters<T, M, LM> {
    /// Prepares CBS and lookup state once, deriving the default coefficient partition.
    pub fn try_from_config(
        config: HighPrecLutConfig<T, M, LM>,
    ) -> Result<Self, HighPrecLutParameterError>
    where
        M: TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let one_hot = CbsParameters::try_from_config(config.one_hot.pbs, config.one_hot.gadget)?;
        let chunks = ChunkFormat::from_plaintext_modulus(one_hot.input_codec().plaintext_modulus())
            .ok_or(LookupTableError::InvalidPlaintextModulus)?;
        let default_count = (one_hot.as_ref().poly_length().get().ilog2() / chunks.bits()) as usize;
        let layout = LookupTableConfig {
            input_chunk_count: config.input_chunk_count,
            output_chunk_count: config.output_chunk_count,
            coefficient_chunk_count: config
                .coefficient_chunk_count
                .unwrap_or(config.input_chunk_count.min(default_count)),
        };
        Self::try_new(one_hot, layout)
    }

    /// Adds checked lookup geometry to an already prepared CBS domain.
    /// Reuses its return state and samplers without enumerating the function.
    pub fn try_new(
        one_hot: CbsParameters<T, M, LM>,
        layout: LookupTableConfig,
    ) -> Result<Self, HighPrecLutParameterError> {
        let br = one_hot.as_ref();
        let t = one_hot.input_codec().plaintext_modulus();
        let layout = Layout::try_new(t, br.poly_length().get(), layout)?;
        let padded_levels = one_hot.gadget().lookup_table_padded_output_count();
        if layout.radix > br.poly_length().get() / (2 * padded_levels) {
            return Err(LookupTableError::OneHot(
                primus_tfhe_ntru::OneHotBootstrapError::InsufficientCapacity,
            )
            .into());
        }
        let codecs = br.pbs_codecs(primus_tfhe::PbsMessageConfig::new(t))?;
        Ok(Self {
            one_hot,
            lookup: LookupDomain { layout, codecs },
        })
    }

    /// Borrows the complete CBS operation used to generate chunk selectors.
    #[must_use]
    pub fn one_hot(&self) -> &CbsParameters<T, M, LM> {
        &self.one_hot
    }

    /// Borrows the shared BR domain with external q and accumulator Q.
    #[must_use]
    pub fn pbs_parameters(&self) -> &PbsParameters<T, M, LM> {
        self.one_hot.as_ref()
    }

    /// Borrows the required independent return-key parameters at q.
    #[must_use]
    pub fn key_switching(&self) -> &LweReturnParameters<T, LM> {
        self.pbs_parameters().key_switching()
    }

    /// Returns the validated uniform chunk width and radix.
    #[must_use]
    pub fn chunk_format(&self) -> ChunkFormat {
        self.lookup.layout.chunk_format
    }

    /// Returns the independent chunk counts and resolved coefficient partition.
    #[must_use]
    pub fn layout(&self) -> LookupTableConfig {
        self.lookup.layout.config
    }

    /// Returns the complete unsigned input width.
    #[must_use]
    pub fn input_bits(&self) -> u32 {
        self.lookup.layout.input_bits
    }

    /// Returns the complete unsigned output width, which may exceed one word.
    #[must_use]
    pub fn output_bits(&self) -> u32 {
        self.lookup.layout.output_bits
    }

    /// Borrows input/returned codecs at q and LUT-output encoding at Q.
    #[must_use]
    pub fn codecs(&self) -> &RoundedPbsCodecs<T, M, LM> {
        &self.lookup.codecs
    }

    /// Compiles a pure integer mapping, automatically extracting output chunks.
    /// W is independent of the ciphertext coefficient type. Both complete widths
    /// must fit W; results exceeding the output width are rejected, never truncated.
    /// Enumerates in output-major order: F(x) is called once for each output chunk,
    /// so costly functions may instead supply explicitly prepared chunk values.
    pub fn compile_fn<W: UnsignedInteger>(
        &self,
        function: impl Fn(W) -> W,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        self.lookup.compile_fn(function)
    }

    /// Compiles (full input index, output chunk) -> digit in 0..M.
    /// Output width may exceed a cleartext word. Inherits the callback order and
    /// enumeration/storage contracts of HighPrecisionLookupTable::try_new.
    pub fn compile_chunks_fn(
        &self,
        function: impl FnMut(usize, usize) -> T,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        self.lookup.compile_chunks_fn(function)
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<PbsParameters<T, M, LM>>
    for HighPrecLutParameters<T, M, LM>
{
    fn as_ref(&self) -> &PbsParameters<T, M, LM> {
        self.pbs_parameters()
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> LookupDomain<T, M, LM> {
    /// Uses already checked geometry and q/Q encoding, avoiding repeated parameter preparation.
    pub(crate) fn compile_chunks_fn(
        &self,
        mut function: impl FnMut(usize, usize) -> T,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        HighPrecisionLookupTable::compile(
            self.codecs.lut_output_codec(),
            self.codecs.input_codec(),
            self.layout,
            |x, output| Ok(function(x, output)),
        )
    }

    /// Checks integer capacity before enumeration; extracts a digit only after checking F(x).
    /// Reuses output-major compilation and allocates no complete cleartext value cache.
    pub(crate) fn compile_fn<W: UnsignedInteger>(
        &self,
        function: impl Fn(W) -> W,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        let required = self.layout.input_bits.max(self.layout.output_bits);
        if required > W::BITS {
            return Err(LookupTableError::WordCapacity {
                required,
                available: W::BITS,
            });
        }
        HighPrecisionLookupTable::compile(
            self.codecs.lut_output_codec(),
            self.codecs.input_codec(),
            self.layout,
            |x, output| {
                let value = function(W::try_from(x).expect("checked complete input width"));
                if self.layout.output_bits < W::BITS && value >> self.layout.output_bits != W::ZERO
                {
                    return Err(LookupTableError::OutputValueOutOfRange { input: x });
                }
                let chunk: usize = self
                    .layout
                    .chunk_format
                    .chunk(value, output)
                    .try_into()
                    .expect("chunk radix fits host indexing");
                Ok(T::as_from(chunk))
            },
        )
    }

    /// Checks the complete public domain before key sampling. Evaluator binding
    /// uses check_table_layout because its lower boundary already checks N/q/Q.
    pub(crate) fn check_table(
        &self,
        table: &HighPrecisionLookupTable<T>,
    ) -> Result<(), LookupTableError> {
        self.check_table_layout(table)?;
        if !table.is_compatible(
            primus_poly::PolyLength::new(self.layout.polynomial_length),
            self.codecs.lut_output_codec().ciphertext_modulus(),
            self.codecs.input_codec().ciphertext_modulus(),
        ) {
            return Err(LookupTableError::IncompatibleParameters);
        }
        Ok(())
    }

    /// Checks the operation's additional chunk contract before raw evaluator binding.
    pub(crate) fn check_table_layout(
        &self,
        table: &HighPrecisionLookupTable<T>,
    ) -> Result<(), LookupTableError> {
        if table.config() != self.layout.config
            || table.plaintext_modulus() != self.codecs.input_codec().plaintext_modulus()
        {
            return Err(LookupTableError::IncompatibleParameters);
        }
        Ok(())
    }
}

/// Failure to pair a public lookup plan or generate its required server material.
#[derive(Debug, thiserror::Error)]
pub enum HighPrecLutKeyGenerationError {
    /// The public table has another chunk layout or encoding domain.
    #[error(transparent)]
    Lookup(#[from] LookupTableError),
    /// Secret sampling, sparse matching or evaluation-key generation failed.
    #[error(transparent)]
    KeyGeneration(#[from] primus_tfhe_ntru::KeyGenerationError),
}
