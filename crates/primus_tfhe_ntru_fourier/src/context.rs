use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_ntru::NtruCiphertext;

use crate::{
    CbsConfig, CbsGadgetConfig, CbsParameters, LweCiphertext, PbsConfig, PbsParameters,
    TfheContextError,
};

/// One boxed owner of the configured operation state, without duplicated samplers.
/// Mixed operations retain their PBS parameters inside the same CBS owner;
/// there is no second BR/domain handle or duplicated sampling state.
enum OperationParameters<T: TorusFftValue, LM: primus_reduce::RingContext<T>> {
    Pbs(Box<PbsParameters<T, LM>>),
    Cbs(Box<CbsParameters<T, LM>>),
}

/// Immutable PBS/CBS parameters and one Fourier transform table.
/// Keys and mutable evaluation workspaces are owned independently.
pub struct TfheContext<T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    parameters: OperationParameters<T, LM>,
    table: Table,
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares and moves one complete BR/KS domain into its transform environment.
    /// No evaluation scratch is allocated.
    pub fn try_from_pbs_config(config: PbsConfig<T, LM>) -> Result<Self, TfheContextError>
    where
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let parameters = PbsParameters::try_from_config(config)?;
        Ok(Self::from_parameters(parameters))
    }

    /// Prepares complete CBS state with the required shared KS.
    /// Input and ring secrets remain independent; the common domain is owned once.
    pub fn try_from_cbs_config(config: CbsConfig<T, LM>) -> Result<Self, TfheContextError>
    where
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        let parameters = CbsParameters::try_from_config(config.pbs, config.gadget)?;
        Ok(Self::from_cbs_parameters(parameters))
    }

    /// Moves prepared PBS parameters into a new transform environment.
    /// Borrow them afterward through [`Self::parameters`]; no sampler is cloned.
    #[must_use]
    pub fn from_parameters(parameters: PbsParameters<T, LM>) -> Self {
        let table = Table::new(parameters.poly_length());
        Self {
            parameters: OperationParameters::Pbs(Box::new(parameters)),
            table,
        }
    }

    /// Moves complete CBS parameters into a new transform environment.
    /// Direct-input CBS keeps its independent small and ring secret roles.
    #[must_use]
    pub fn from_cbs_parameters(parameters: CbsParameters<T, LM>) -> Self {
        let domain = parameters.pbs_parameters();
        let table = Table::new(domain.poly_length());
        Self {
            parameters: OperationParameters::Cbs(Box::new(parameters)),
            table,
        }
    }

    /// Binds a prepared PBS domain to an independently supplied transform table.
    /// Checks only the table pairing; ownership moves without cloning samplers.
    pub fn try_new(
        parameters: PbsParameters<T, LM>,
        table: Table,
    ) -> Result<Self, TfheContextError> {
        let expected = parameters.poly_length().get();
        let actual = table.poly_length().get();
        if expected != actual {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self {
            parameters: OperationParameters::Pbs(Box::new(parameters)),
            table,
        })
    }

    /// Adds CBS by moving the same PBS domain into the combined operation owner.
    /// Only new gadgets and selector encoding are prepared; the table is retained.
    pub fn try_with_circuit_bootstrap(
        self,
        gadget: CbsGadgetConfig,
    ) -> Result<Self, TfheContextError> {
        let parameters = match self.parameters {
            OperationParameters::Pbs(parameters) => *parameters,
            OperationParameters::Cbs(parameters) => parameters.into_parts().0,
        };
        let parameters = CbsParameters::try_with_config(parameters, gadget)?;
        Ok(Self {
            parameters: OperationParameters::Cbs(Box::new(parameters)),
            table: self.table,
        })
    }

    /// Adds independently prepared CBS after checking its domain and algorithm.
    /// The existing PBS owner replaces the duplicate domain.
    pub fn try_with_cbs_parameters(
        self,
        parameters: CbsParameters<T, LM>,
    ) -> Result<Self, TfheContextError> {
        let common = match self.parameters {
            OperationParameters::Pbs(parameters) => *parameters,
            OperationParameters::Cbs(parameters) => parameters.into_parts().0,
        };
        let parameters = parameters.try_with_pbs_parameters(common)?;
        Ok(Self {
            parameters: OperationParameters::Cbs(Box::new(parameters)),
            table: self.table,
        })
    }

    /// Borrows complete CBS state, which contains the single common domain.
    #[must_use]
    pub fn cbs_parameters(&self) -> Option<&CbsParameters<T, LM>> {
        match &self.parameters {
            OperationParameters::Cbs(parameters) => Some(parameters),
            OperationParameters::Pbs(_) => None,
        }
    }

    /// Borrows the common checked domain used by numerical kernels and clients.
    #[must_use]
    #[inline(always)]
    pub fn parameters(&self) -> &PbsParameters<T, LM> {
        match &self.parameters {
            OperationParameters::Pbs(parameters) => parameters,
            OperationParameters::Cbs(parameters) => parameters.pbs_parameters(),
        }
    }

    /// Borrows the immutable transform table; transformed keys use this representation.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates independent reusable FFT scratch, borrowing the immutable table.
    #[must_use]
    pub fn new_fft_engine(&self) -> FftEngine<'_, Table> {
        FftEngine::new(&self.table)
    }

    /// Allocates zero storage for an external LWE; this does not encrypt a message.
    #[must_use]
    pub fn allocate_lwe_ciphertext(&self) -> LweCiphertext<T> {
        LweCiphertext::zero(self.parameters().external_lwe_dimension().get())
    }

    /// Allocates zero storage in the accumulator layout, without encrypting.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> NtruCiphertext<Vec<T>> {
        NtruCiphertext::zero(self.parameters().poly_length().get())
    }
}
