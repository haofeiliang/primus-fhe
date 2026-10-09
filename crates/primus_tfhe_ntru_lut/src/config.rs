//! One-hot CBS, return material and public table geometry composed for lookup.

use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{
    CbsConfig, CbsParameters, LweReturnParameters, ModulusConfig, ModulusConfigError,
    PbsParameters, TfheParameterError,
};

use crate::{ChunkFormat, LookupTableConfig, LookupTableError};

/// Complete high-precision lookup choices, without preparing unused CMux codecs.
///
/// The one-hot input modulus determines the common radix `M=t/2` and chunk width.
/// Counts and coefficient/table partition belong to `layout`. The public function
/// remains an explicit compilation argument. Preparing keys does not establish
/// one-hot's phase guard or the complete lookup's joint noise budget.
#[derive(Debug, Clone, Copy)]
pub struct HighPrecLutConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// One-hot CBS input/BR domains and the three gadget decompositions.
    pub one_hot: CbsConfig<T, M, LM>,
    /// Independent input/output chunk counts and coefficient-selection partition.
    pub layout: LookupTableConfig,
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

/// Complete high-precision operation state, independent of function and transform backend.
/// Contains one CBS domain, mandatory return parameters, checked chunk geometry and
/// q/Q encodings. Preparation neither enumerates the function nor generates keys.
#[derive(Clone)]
pub struct HighPrecLutParameters<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    one_hot: CbsParameters<T, M, LM>,
    layout: crate::lookup_table::Layout,
    codecs: primus_tfhe::RoundedPbsCodecs<T, M, LM>,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> HighPrecLutParameters<T, M, LM> {
    /// Checks lookup geometry while reusing the existing CBS domain and return state.
    /// The one-hot phase guard, complete noise budget and public-lift material remain
    /// execution/program requirements, not parameter-construction guarantees.
    pub fn try_new(
        one_hot: CbsParameters<T, M, LM>,
        layout: LookupTableConfig,
    ) -> Result<Self, HighPrecLutParameterError> {
        let br = one_hot.as_ref();
        let t = one_hot.input_codec().plaintext_modulus();
        let layout = crate::lookup_table::Layout::try_new(t, br.poly_length().get(), layout)?;
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
            layout,
            codecs,
        })
    }

    /// Borrows the complete CBS operation used to generate chunk selectors.
    #[must_use]
    pub fn one_hot(&self) -> &CbsParameters<T, M, LM> {
        &self.one_hot
    }

    /// Borrows the shared BR domain, with independent external q and accumulator Q.
    #[must_use]
    pub fn pbs_parameters(&self) -> &PbsParameters<T, M, LM> {
        self.one_hot.as_ref()
    }

    /// Borrows the required independent return-key parameters at q.
    #[must_use]
    pub fn key_switching(&self) -> &LweReturnParameters<T, LM> {
        self.one_hot.pbs_parameters().key_switching()
    }

    /// Returns the validated uniform chunk width and radix.
    #[must_use]
    pub fn chunk_format(&self) -> ChunkFormat {
        self.layout.chunk_format
    }

    /// Returns the validated input/output counts and coefficient-selection partition.
    #[must_use]
    pub fn layout(&self) -> LookupTableConfig {
        self.layout.config
    }

    /// Borrows the paired chunk codecs: input/returned output at q, LUT output at Q.
    #[must_use]
    pub fn codecs(&self) -> &primus_tfhe::RoundedPbsCodecs<T, M, LM> {
        &self.codecs
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> AsRef<PbsParameters<T, M, LM>>
    for HighPrecLutParameters<T, M, LM>
{
    fn as_ref(&self) -> &PbsParameters<T, M, LM> {
        self.one_hot.pbs_parameters()
    }
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> HighPrecLutConfig<T, M, LM> {
    /// Prepares CBS, required return state, chunk geometry and q/Q encodings once.
    pub fn try_prepare(self) -> Result<HighPrecLutParameters<T, M, LM>, HighPrecLutParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        let one_hot = CbsParameters::try_from_config(self.one_hot.pbs, self.one_hot.gadget)?;
        HighPrecLutParameters::try_new(one_hot, self.layout)
    }

    /// Derives the uniform chunk width from one-hot's padded input modulus.
    /// Returns an error unless t=2*M, with power-of-two M>=2 fitting host indexing.
    pub fn try_chunk_format(self) -> Result<ChunkFormat, LookupTableError> {
        ChunkFormat::from_plaintext_modulus(self.one_hot.pbs.messages.input_modulus)
            .ok_or(LookupTableError::InvalidPlaintextModulus)
    }
}
