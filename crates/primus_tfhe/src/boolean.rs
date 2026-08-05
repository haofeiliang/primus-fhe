use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{
    Ciphertext, ClientKey, Decryptor, Encryptor, LookupTable, LookupTableError, LweCiphertext,
    PlaintextCodec, PlaintextEmbedding, TfheClientError, TfheEvaluationError, TfheParameters,
};

/// The complete plaintext modulus used by the Boolean gate encoding.
pub const BOOLEAN_PLAINTEXT_BITS: u32 = 2;

/// An LWE ciphertext encoding false as 0 and true as 1 modulo 4.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct BooleanCiphertext<T: FheUint>(Ciphertext<T>);

impl<T: FheUint> BooleanCiphertext<T> {
    /// Wraps a raw ciphertext that is known to use the Boolean encoding.
    ///
    /// This operation cannot verify the encrypted plaintext.
    #[inline]
    pub fn from_raw(ciphertext: Ciphertext<T>) -> Self {
        Self(ciphertext)
    }

    /// Returns the underlying raw TFHE ciphertext.
    #[inline]
    pub fn as_raw(&self) -> &Ciphertext<T> {
        &self.0
    }

    /// Returns the underlying mutable raw TFHE ciphertext.
    #[inline]
    pub fn as_raw_mut(&mut self) -> &mut Ciphertext<T> {
        &mut self.0
    }

    /// Decomposes this wrapper into its raw TFHE ciphertext.
    #[inline]
    pub fn into_raw(self) -> Ciphertext<T> {
        self.0
    }
}

/// Encrypts Boolean values under the standard 0/1 encoding modulo 4.
pub struct BooleanEncryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: Encryptor<'a, T, LM, GM, ClientKey<T>>,
}

impl<'a, T, LM, GM> BooleanEncryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a Boolean encryptor and validates the required plaintext
    /// modulus.
    pub fn new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: Encryptor::with_client_key(parameters, key)?,
        })
    }

    /// Encrypts one Boolean value.
    pub fn encrypt<R>(
        &self,
        message: bool,
        rng: &mut R,
    ) -> Result<BooleanCiphertext<T>, BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(BooleanCiphertext::from_raw(
            self.inner.encrypt_padded(message, rng)?,
        ))
    }
}

/// Decrypts ciphertexts using the standard 0/1 Boolean encoding.
pub struct BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: Decryptor<'a, T, LM, GM>,
}

impl<'a, T, LM, GM> BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a Boolean decryptor and validates the required plaintext
    /// modulus.
    pub fn new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: Decryptor::new(parameters, key)?,
        })
    }

    /// Decrypts one Boolean ciphertext.
    pub fn decrypt(&self, ciphertext: &BooleanCiphertext<T>) -> Result<bool, BooleanError> {
        let message = self.inner.decrypt::<T>(ciphertext.as_raw())?;
        if message == T::ZERO {
            Ok(false)
        } else if message == T::ONE {
            Ok(true)
        } else {
            Err(BooleanError::InvalidPlaintext)
        }
    }
}

/// A binary Boolean gate evaluated by one programmable bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanGate {
    /// Logical conjunction.
    And,
    /// Negated logical conjunction.
    Nand,
    /// Logical disjunction.
    Or,
    /// Negated logical disjunction.
    Nor,
    /// Logical exclusive disjunction.
    Xor,
    /// Logical equivalence.
    Xnor,
}

impl BooleanGate {
    #[inline]
    fn lookup_table_index(self) -> usize {
        match self {
            Self::And => 0,
            Self::Nand => 1,
            Self::Or | Self::Xor => 2,
            Self::Nor | Self::Xnor => 3,
        }
    }
}

/// Minimal interface required by the backend-independent Boolean layer.
pub trait ProgrammableBootstrap<T: FheUint> {
    /// Applies a compiled lookup table into an existing ciphertext allocation.
    ///
    /// The lookup table must have been compiled for the same parameter set as
    /// the backend evaluator.
    ///
    /// # Panics
    ///
    /// Panics if an operand does not have the dimensions required by the
    /// backend context.
    fn apply_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    );
}

/// Backend-independent Boolean gate evaluator.
///
/// The backend supplies only programmable bootstrapping; Boolean encodings,
/// affine gate preprocessing, and accumulators are shared.
/// Online operations panic when passed ciphertexts with a dimension different
/// from the configured external LWE dimension.
pub struct BooleanEvaluator<'a, T, LM, GM, E>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    parameters: &'a TfheParameters<T, LM, GM>,
    bootstrapper: E,
    gate_lookup_tables: [LookupTable<T>; 4],
    output_shift: T,
    gate_input: Ciphertext<T>,
    mux_branch: BooleanCiphertext<T>,
}

impl<'a, T, LM, GM, E> BooleanEvaluator<'a, T, LM, GM, E>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    /// Creates a Boolean evaluator from a backend PBS implementation.
    pub fn try_new(
        parameters: &'a TfheParameters<T, LM, GM>,
        bootstrapper: E,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        let gate_lookup_tables = [
            compile_boolean_lookup_table(parameters, [false, false])?,
            compile_boolean_lookup_table(parameters, [true, true])?,
            compile_boolean_lookup_table(parameters, [false, true])?,
            compile_boolean_lookup_table(parameters, [true, false])?,
        ];
        let output_shift = PlaintextCodec::new(
            boolean_accumulator_plaintext_modulus::<T>(),
            parameters.small_lwe().cipher_modulus().explicit_value(),
        )
        .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        let dimension = parameters.ciphertext_lwe_dimension();
        let gate_input = Ciphertext::try_from_lwe(LweCiphertext::zero(dimension), dimension)?;
        let mux_branch = BooleanCiphertext::from_raw(Ciphertext::try_from_lwe(
            LweCiphertext::zero(dimension),
            dimension,
        )?);
        Ok(Self {
            parameters,
            bootstrapper,
            gate_lookup_tables,
            output_shift,
            gate_input,
            mux_branch,
        })
    }

    /// Evaluates a binary gate and allocates its output ciphertext.
    pub fn evaluate_binary(
        &mut self,
        gate: BooleanGate,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        let mut output = lhs.clone();
        self.evaluate_binary_to(gate, lhs, rhs, &mut output);
        output
    }

    /// Evaluates a binary gate into an existing output allocation.
    pub fn evaluate_binary_to(
        &mut self,
        gate: BooleanGate,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
        output: &mut BooleanCiphertext<T>,
    ) {
        prepare_binary_gate(gate, lhs, rhs, &mut self.gate_input, self.parameters);
        let lookup_table = &self.gate_lookup_tables[gate.lookup_table_index()];
        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            lookup_table,
            output.as_raw_mut(),
        );
        self.parameters
            .small_lwe()
            .cipher_modulus()
            .reduce_add_assign(output.as_raw_mut().as_lwe_mut().b_mut(), self.output_shift);
    }

    /// Evaluates an AND gate.
    #[inline]
    pub fn and(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::And, lhs, rhs)
    }

    /// Evaluates a NAND gate.
    #[inline]
    pub fn nand(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nand, lhs, rhs)
    }

    /// Evaluates an OR gate.
    #[inline]
    pub fn or(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::Or, lhs, rhs)
    }

    /// Evaluates a NOR gate.
    #[inline]
    pub fn nor(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nor, lhs, rhs)
    }

    /// Evaluates an XOR gate.
    #[inline]
    pub fn xor(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xor, lhs, rhs)
    }

    /// Evaluates an XNOR gate.
    #[inline]
    pub fn xnor(
        &mut self,
        lhs: &BooleanCiphertext<T>,
        rhs: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xnor, lhs, rhs)
    }

    /// Selects 'then_value' when 'condition' is true and 'else_value'
    /// otherwise.
    ///
    /// This uses two bootstrapped AND terms followed by one LWE addition.
    pub fn mux(
        &mut self,
        condition: &BooleanCiphertext<T>,
        then_value: &BooleanCiphertext<T>,
        else_value: &BooleanCiphertext<T>,
    ) -> BooleanCiphertext<T> {
        let mut output = condition.clone();
        self.mux_to(condition, then_value, else_value, &mut output);
        output
    }

    /// Evaluates a multiplexer into an existing output allocation.
    pub fn mux_to(
        &mut self,
        condition: &BooleanCiphertext<T>,
        then_value: &BooleanCiphertext<T>,
        else_value: &BooleanCiphertext<T>,
        output: &mut BooleanCiphertext<T>,
    ) {
        prepare_binary_gate(
            BooleanGate::And,
            condition,
            then_value,
            &mut self.gate_input,
            self.parameters,
        );
        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            self.mux_branch.as_raw_mut(),
        );
        let modulus = self.parameters.small_lwe().cipher_modulus();
        modulus.reduce_add_assign(
            self.mux_branch.as_raw_mut().as_lwe_mut().b_mut(),
            self.output_shift,
        );

        assert_dimension(else_value.as_raw(), self.parameters);
        self.gate_input
            .as_lwe_mut()
            .0
            .copy_from_slice(else_value.as_raw().as_lwe().0.as_slice());
        self.gate_input
            .as_lwe_mut()
            .sub_component_wise_assign(condition.as_raw().as_lwe(), modulus);
        let encoded_one = self
            .parameters
            .small_lwe()
            .plaintext_codec()
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        modulus.reduce_add_assign(self.gate_input.as_lwe_mut().b_mut(), encoded_one);

        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            output.as_raw_mut(),
        );
        modulus.reduce_add_assign(output.as_raw_mut().as_lwe_mut().b_mut(), self.output_shift);
        output
            .as_raw_mut()
            .as_lwe_mut()
            .add_component_wise_assign(self.mux_branch.as_raw().as_lwe(), modulus);
    }

    /// Negates a Boolean ciphertext without programmable bootstrapping.
    pub fn not(&self, input: &BooleanCiphertext<T>) -> BooleanCiphertext<T> {
        let mut output = input.clone();
        self.not_to(input, &mut output);
        output
    }

    /// Negates a Boolean ciphertext into an existing allocation without PBS.
    pub fn not_to(&self, input: &BooleanCiphertext<T>, output: &mut BooleanCiphertext<T>) {
        assert_dimension(input.as_raw(), self.parameters);
        assert_dimension(output.as_raw(), self.parameters);
        output
            .as_raw_mut()
            .as_lwe_mut()
            .0
            .copy_from_slice(input.as_raw().as_lwe().0.as_slice());
        let modulus = self.parameters.small_lwe().cipher_modulus();
        output.as_raw_mut().as_lwe_mut().neg_assign(modulus);
        let encoded_one = self
            .parameters
            .small_lwe()
            .plaintext_codec()
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        modulus.reduce_add_assign(output.as_raw_mut().as_lwe_mut().b_mut(), encoded_one);
    }

    /// Returns the backend PBS evaluator.
    #[inline]
    pub fn bootstrapper(&self) -> &E {
        &self.bootstrapper
    }

    /// Returns the backend PBS evaluator mutably.
    #[inline]
    pub fn bootstrapper_mut(&mut self) -> &mut E {
        &mut self.bootstrapper
    }

    /// Decomposes this evaluator into its backend PBS evaluator.
    #[inline]
    pub fn into_bootstrapper(self) -> E {
        self.bootstrapper
    }
}

fn prepare_binary_gate<T, LM, GM>(
    gate: BooleanGate,
    lhs: &BooleanCiphertext<T>,
    rhs: &BooleanCiphertext<T>,
    output: &mut Ciphertext<T>,
    parameters: &TfheParameters<T, LM, GM>,
) where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    assert_dimension(lhs.as_raw(), parameters);
    assert_dimension(rhs.as_raw(), parameters);
    output
        .as_lwe_mut()
        .0
        .copy_from_slice(lhs.as_raw().as_lwe().0.as_slice());
    let modulus = parameters.small_lwe().cipher_modulus();

    match gate {
        BooleanGate::And | BooleanGate::Nand | BooleanGate::Or | BooleanGate::Nor => {
            output
                .as_lwe_mut()
                .add_component_wise_assign(rhs.as_raw().as_lwe(), modulus);
        }
        BooleanGate::Xor | BooleanGate::Xnor => {
            output
                .as_lwe_mut()
                .sub_component_wise_assign(rhs.as_raw().as_lwe(), modulus);
            output.as_lwe_mut().mul_scalar_assign(T::TWO, modulus);
        }
    }
}

fn compile_boolean_lookup_table<T, LM, GM>(
    parameters: &TfheParameters<T, LM, GM>,
    positive: [bool; 2],
) -> Result<LookupTable<T>, LookupTableError>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    let modulus = parameters.glwe().cipher_modulus();
    let positive_value = PlaintextCodec::new(
        boolean_accumulator_plaintext_modulus::<T>(),
        modulus.explicit_value(),
    )
    .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
    let negative_value = modulus.reduce_neg(positive_value);
    parameters.compile_encoded_lookup_table(2, |input| {
        Ok(if positive[input] {
            positive_value
        } else {
            negative_value
        })
    })
}

fn assert_dimension<T, LM, GM>(ciphertext: &Ciphertext<T>, parameters: &TfheParameters<T, LM, GM>)
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    let expected = parameters.ciphertext_lwe_dimension();
    assert_eq!(ciphertext.dimension(), expected);
}

fn validate_boolean_parameters<T, LM, GM>(
    parameters: &TfheParameters<T, LM, GM>,
) -> Result<(), BooleanError>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    if parameters.plain_modulus_value() == boolean_plaintext_modulus::<T>() {
        Ok(())
    } else {
        Err(BooleanError::PlaintextModulusMustBeFour)
    }
}

#[inline]
fn boolean_plaintext_modulus<T: FheUint>() -> T {
    T::ONE << BOOLEAN_PLAINTEXT_BITS
}

#[inline]
fn boolean_accumulator_plaintext_modulus<T: FheUint>() -> T {
    T::ONE << (BOOLEAN_PLAINTEXT_BITS + 1)
}

/// An error produced by the Boolean TFHE layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    /// Gate bootstrapping uses the 0/1 encoding modulo 4.
    #[error("Boolean TFHE requires plaintext modulus 4")]
    PlaintextModulusMustBeFour,

    /// A decrypted value is neither the -1 nor +1 Boolean representative.
    #[error("decrypted value is not a valid Boolean plaintext")]
    InvalidPlaintext,

    /// Raw client-side encryption or decryption failed.
    #[error(transparent)]
    Client(#[from] TfheClientError),

    /// Lookup-table compilation failed.
    #[error(transparent)]
    LookupTable(#[from] LookupTableError),

    /// Backend evaluator construction failed.
    #[error(transparent)]
    Evaluation(#[from] TfheEvaluationError),
}
