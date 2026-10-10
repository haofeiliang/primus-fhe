//! Complete lookup workflow over the existing native-torus Fourier backend.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_integer::UnsignedInteger;
use primus_modulus::NativeModulus;
use primus_ntru::{FourierNlevCiphertext, NlevParameters};
use primus_reduce::RingContext;
use primus_tfhe_ntru::{ClientKey, KeyGenerationError};
use primus_tfhe_ntru_fourier::{CircuitBootstrapServerKey, KeyGenerator, TfheContext};

use crate::{
    ChunkFormat, FourierLookupTableEvaluator, FourierPublicLift, HighPrecLutClientError,
    HighPrecLutConfig, HighPrecLutDecryptor, HighPrecLutEncryptor, HighPrecLutParameterError,
    HighPrecLutParameters, HighPrecisionLookupTable, LookupTableConfig, LookupTableError,
    config::LookupDomain,
};

/// High-precision operation with one backend CBS owner and one transform table.
/// Immutable lookup geometry/codecs are retained beside the common domain.
/// Keys, compiled functions and mutable evaluator buffers are owned independently.
pub struct FourierHighPrecLutContext<T, Table, LM = NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: RingContext<T>,
{
    context: TfheContext<T, Table, LM>,
    lookup: LookupDomain<T, NativeModulus<T>, LM>,
}

impl<T, Table, LM> FourierHighPrecLutContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: RingContext<T>,
{
    /// Prepares the complete operation and one FFT table, without keys or evaluation scratch.
    pub fn try_from_config(
        config: HighPrecLutConfig<T, NativeModulus<T>, LM>,
    ) -> Result<Self, HighPrecLutParameterError>
    where
        LM: TryFrom<primus_tfhe::ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
    {
        Ok(Self::from_parameters(
            HighPrecLutParameters::try_from_config(config)?,
        ))
    }

    /// Moves prepared offline state into one FFT environment, without cloning samplers.
    #[must_use]
    pub fn from_parameters(parameters: HighPrecLutParameters<T, NativeModulus<T>, LM>) -> Self {
        let HighPrecLutParameters { one_hot, lookup } = parameters;
        Self {
            context: TfheContext::from_cbs_parameters(one_hot),
            lookup,
        }
    }

    /// Borrows the single backend owner for explicit component workflows.
    #[must_use]
    pub fn backend_context(&self) -> &TfheContext<T, Table, LM> {
        &self.context
    }

    /// Returns uniform input/output chunk geometry.
    #[must_use]
    pub fn chunk_format(&self) -> ChunkFormat {
        self.lookup.layout.chunk_format
    }

    /// Returns independent counts and the resolved low-chunk coefficient partition.
    #[must_use]
    pub fn layout(&self) -> LookupTableConfig {
        self.lookup.layout.config
    }

    /// Returns the complete unsigned input width.
    #[must_use]
    pub fn input_bits(&self) -> u32 {
        self.lookup.layout.input_bits
    }

    /// Returns the complete unsigned output width; chunk APIs allow more than one word.
    #[must_use]
    pub fn output_bits(&self) -> u32 {
        self.lookup.layout.output_bits
    }

    /// Compiles a pure integer function in output-major order, extracting each output digit.
    /// W is independent of coefficient type T. Rejects widths exceeding W and results
    /// exceeding the output domain; does not cache the full cleartext value domain.
    /// Inherits [`HighPrecLutParameters::compile_fn`]'s callback and enumeration contracts.
    pub fn compile_fn<W: UnsignedInteger>(
        &self,
        function: impl Fn(W) -> W,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        self.lookup.compile_fn(function)
    }

    /// Compiles (full input index, output chunk) -> digit in 0..M, including wide outputs.
    /// Inherits [`HighPrecisionLookupTable::try_new`]'s callback and storage contracts.
    pub fn compile_chunks_fn(
        &self,
        function: impl FnMut(usize, usize) -> T,
    ) -> Result<HighPrecisionLookupTable<T>, LookupTableError> {
        self.lookup.compile_chunks_fn(function)
    }

    /// Binds chunk input encoding and fresh noise to only the client's external secret.
    /// This client needs no compiled table or ring secret for its online operations.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
    ) -> Result<HighPrecLutEncryptor<'a, T, LM>, HighPrecLutClientError> {
        self.lookup.encryptor(self.context.parameters(), key)
    }

    /// Copies the configured output decoding state and borrows only the external secret.
    /// Does not receive a table/function or borrow the transform context.
    pub fn decryptor<'a>(
        &self,
        key: &'a ClientKey<T>,
    ) -> Result<HighPrecLutDecryptor<'a, T, LM>, HighPrecLutClientError> {
        self.lookup.decryptor(self.context.parameters(), key)
    }

    /// Generates one BR/CBS/return bundle from the configured geometry, without a LUT.
    /// Classic borrows its initializer. Sparse generates independent `NLEV[1]` with
    /// BR's basis/noise only when c=d; otherwise no separate lift is stored.
    /// All ring material reuses the accepted secret transform and inverse.
    ///
    /// # Correctness
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`] and
    /// [`KeyGenerator::try_generate_public_lift_key`]'s numerical/security contracts.
    /// A key may serve another compatible table with the same geometry and encoding;
    /// changing function values does not change the required material.
    pub fn try_generate_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, FourierHighPrecLutServerKey<T>), KeyGenerationError> {
        let domain = self.context.parameters();
        let needs_lift = matches!(
            domain.algorithm(),
            primus_tfhe::BlindRotationMethod::Sparse { .. }
        ) && self.lookup.layout.table_chunk_count() == 0;
        let lift_parameters = needs_lift.then(|| domain.blind_rotation());
        let (client, circuit, lift) = KeyGenerator::new(&self.context)
            .try_generate_circuit_bootstrap_keys_with_public_lift(lift_parameters, rng)?;
        let public_lift = lift.map(|key| (key, domain.blind_rotation().clone()));
        Ok((
            client,
            FourierHighPrecLutServerKey {
                circuit,
                public_lift,
            },
        ))
    }

    /// Binds the complete public key and table, preparing only the original evaluator buffers.
    /// Reuses its classic initializer or the bundle's explicit lift. Missing sparse
    /// lift material is an error; no keys are generated online.
    ///
    /// # Correctness
    /// Inherits [`FourierLookupTableEvaluator::try_from_parts`]'s key/transform identity
    /// and complete noise-budget contracts. The table must use this operation's layout.
    pub fn evaluator<'a>(
        &'a self,
        key: &'a FourierHighPrecLutServerKey<T>,
        table: &'a HighPrecisionLookupTable<T>,
    ) -> Result<FourierLookupTableEvaluator<'a, T, Table, LM>, LookupTableError> {
        self.lookup.check_table_layout(table)?;
        match key.public_lift() {
            Some(lift) => FourierLookupTableEvaluator::try_with_public_lift(
                &self.context,
                self.context.parameters().key_switching(),
                &key.circuit,
                table,
                lift,
            ),
            None => FourierLookupTableEvaluator::try_new(
                &self.context,
                self.context.parameters().key_switching(),
                &key.circuit,
                table,
            ),
        }
    }
}

/// Owned independent `NLEV[1]` and its declared generation parameters.
/// The raw pair performs no validation; evaluator binding checks ring and storage.
/// Actual secret, encoded one and transform identity inherit [`FourierPublicLift`]'s contracts.
pub type FourierPublicLiftKey<T> = (
    FourierNlevCiphertext<Vec<Complex64>>,
    NlevParameters<T, NativeModulus<T>>,
);

/// Complete public lookup material with one BR/CBS/return owner and optional independent lift.
/// Does not duplicate BR or store a second classic initializer.
pub struct FourierHighPrecLutServerKey<T: TorusFftValue> {
    circuit: CircuitBootstrapServerKey<T>,
    public_lift: Option<FourierPublicLiftKey<T>>,
}

impl<T: TorusFftValue> FourierHighPrecLutServerKey<T> {
    /// Moves independent material into a bundle without copying buffers.
    /// Evaluator binding checks domains/layouts; the caller guarantees actual
    /// secrets, `NLEV[1]` encoding and the exact FFT table instance.
    #[must_use]
    pub fn new(
        circuit: CircuitBootstrapServerKey<T>,
        public_lift: Option<FourierPublicLiftKey<T>>,
    ) -> Self {
        Self {
            circuit,
            public_lift,
        }
    }

    /// Borrows complete BR/CBS/return material for existing backend operations.
    #[must_use]
    pub fn circuit_bootstrap_server_key(&self) -> &CircuitBootstrapServerKey<T> {
        &self.circuit
    }

    /// Borrows only independently generated lift material; classic fallback stays in BR.
    #[must_use]
    pub fn public_lift(&self) -> Option<FourierPublicLift<'_, T>> {
        self.public_lift
            .as_ref()
            .map(|(key, parameters)| (key.as_view(), parameters))
    }

    /// Moves out independently reusable components without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CircuitBootstrapServerKey<T>,
        Option<FourierPublicLiftKey<T>>,
    ) {
        (self.circuit, self.public_lift)
    }
}
