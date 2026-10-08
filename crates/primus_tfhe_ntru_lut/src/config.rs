//! One-hot CBS, return material and public table geometry composed for lookup.

use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{
    CbsConfig, GadgetEncryptionConfig, ModulusConfig, ModulusConfigError, PbsParameters,
    TfheParameterError,
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
    /// Independent return-q key-switch decomposition and coefficient-unit row noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Independent input/output chunk counts and coefficient-selection partition.
    pub layout: LookupTableConfig,
}

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> HighPrecLutConfig<T, M, LM> {
    /// Prepares one-hot's BR domain plus the required LWE return state.
    /// CBS gadget state is subsequently prepared by key generation using `one_hot.gadget`.
    pub fn try_prepare(self) -> Result<PbsParameters<T, M, LM>, TfheParameterError>
    where
        M: TryFrom<ModulusConfig<M>, Error = ModulusConfigError>,
        LM: TryFrom<ModulusConfig<LM>, Error = ModulusConfigError>,
    {
        self.one_hot
            .try_prepare()?
            .try_with_key_switching(self.key_switching)
    }

    /// Derives the uniform chunk width from one-hot's padded input modulus.
    /// Returns an error unless t=2*M, with power-of-two M>=2 fitting host indexing.
    pub fn try_chunk_format(self) -> Result<ChunkFormat, LookupTableError> {
        let t = self.one_hot.input_modulus;
        if !t.is_power_of_two() {
            return Err(LookupTableError::InvalidPlaintextModulus);
        }
        ChunkFormat::try_new(t.trailing_zeros().saturating_sub(1))
            .map_err(|_| LookupTableError::InvalidPlaintextModulus)
    }
}
