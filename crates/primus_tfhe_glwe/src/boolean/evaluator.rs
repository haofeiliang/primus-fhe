use super::{BOOLEAN_PLAINTEXT_BITS, BooleanCiphertext, BooleanError, validate_boolean_parameters};
use crate::{GlweTfheParameters, LweCiphertext, PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{LookupTable, LookupTableError, ProgrammableBootstrap};

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

/// Backend-independent Boolean gate evaluator.
///
/// The backend supplies only programmable bootstrapping; Boolean encodings,
/// affine gate preprocessing, and accumulators are shared.
/// Gate LUTs use opposite values at the rounded modulus-8 scale. After PBS,
/// a positive shift at that scale restores the external 0/1 encoding modulo 4.
/// These signed LUT values are internal accumulator values, not external
/// Boolean plaintext representatives.
///
/// Online operations panic when passed ciphertexts with a dimension different
/// from the configured external LWE dimension.
pub struct BooleanEvaluator<'a, T, LM, GM, E>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    parameters: &'a GlweTfheParameters<T, LM, GM>,
    bootstrapper: E,
    gate_lookup_tables: [LookupTable<T>; 4],
    output_shift: T,
    gate_input: LweCiphertext<T>,
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
    /// Allocates gate LUTs and reusable ciphertext workspace.
    ///
    /// # Correctness
    ///
    /// `parameters` must describe `bootstrapper`'s external LWE dimension,
    /// input encoding, ciphertext moduli and accumulator polynomial length.
    /// `bootstrapper` must preserve the LUT output scale as required by
    /// [`ProgrammableBootstrap::apply_lookup_table_to`]. This constructor cannot
    /// check that binding through the trait; backend context factories supply it.
    pub fn try_new(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        bootstrapper: E,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        let gate_lookup_tables = [
            compile_boolean_lookup_table(parameters, [false, false])?,
            compile_boolean_lookup_table(parameters, [true, true])?,
            compile_boolean_lookup_table(parameters, [false, true])?,
            compile_boolean_lookup_table(parameters, [true, false])?,
        ];
        let output_shift = RoundedCodec::new(
            boolean_accumulator_plaintext_modulus::<T>(),
            parameters.small_lwe().cipher_modulus(),
        )
        .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        let dimension = parameters.ciphertext_lwe_dimension();
        let gate_input = LweCiphertext::zero(dimension);
        let mux_branch = BooleanCiphertext::from_raw(LweCiphertext::zero(dimension));
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
        let mut output = BooleanCiphertext::from_raw(LweCiphertext::zero(
            self.parameters.ciphertext_lwe_dimension(),
        ));
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
            .reduce_add_assign(output.as_raw_mut().b_mut(), self.output_shift);
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
        let mut output = BooleanCiphertext::from_raw(LweCiphertext::zero(
            self.parameters.ciphertext_lwe_dimension(),
        ));
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
        modulus.reduce_add_assign(self.mux_branch.as_raw_mut().b_mut(), self.output_shift);

        assert_dimension(else_value.as_raw(), self.parameters);
        self.gate_input
            .0
            .copy_from_slice(else_value.as_raw().0.as_slice());
        self.gate_input.sub_assign(condition.as_raw(), modulus);
        let encoded_one = self
            .parameters
            .small_lwe()
            .plaintext_codec()
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        modulus.reduce_add_assign(self.gate_input.b_mut(), encoded_one);

        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            output.as_raw_mut(),
        );
        modulus.reduce_add_assign(output.as_raw_mut().b_mut(), self.output_shift);
        output
            .as_raw_mut()
            .add_assign(self.mux_branch.as_raw(), modulus);
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
            .0
            .copy_from_slice(input.as_raw().0.as_slice());
        let modulus = self.parameters.small_lwe().cipher_modulus();
        output.as_raw_mut().neg_assign(modulus);
        let encoded_one = self
            .parameters
            .small_lwe()
            .plaintext_codec()
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        output
            .as_raw_mut()
            .add_plaintext_assign(encoded_one, modulus);
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
    output: &mut LweCiphertext<T>,
    parameters: &GlweTfheParameters<T, LM, GM>,
) where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    assert_dimension(lhs.as_raw(), parameters);
    assert_dimension(rhs.as_raw(), parameters);
    let modulus = parameters.small_lwe().cipher_modulus();

    match gate {
        BooleanGate::And | BooleanGate::Nand | BooleanGate::Or | BooleanGate::Nor => {
            lhs.as_raw().add_to(rhs.as_raw(), output, modulus);
        }
        BooleanGate::Xor | BooleanGate::Xnor => {
            lhs.as_raw().sub_to(rhs.as_raw(), output, modulus);
            output.mul_scalar_assign(T::TWO, modulus);
        }
    }
}

fn compile_boolean_lookup_table<T, LM, GM>(
    parameters: &GlweTfheParameters<T, LM, GM>,
    positive: [bool; 2],
) -> Result<LookupTable<T>, LookupTableError>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    let modulus = parameters.glwe().cipher_modulus();
    let positive_value = RoundedCodec::new(boolean_accumulator_plaintext_modulus::<T>(), modulus)
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

fn assert_dimension<T, LM, GM>(
    ciphertext: &LweCiphertext<T>,
    parameters: &GlweTfheParameters<T, LM, GM>,
) where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    let expected = parameters.ciphertext_lwe_dimension();
    assert_eq!(ciphertext.dimension(), expected);
}

#[inline]
fn boolean_accumulator_plaintext_modulus<T: FheUint>() -> T {
    T::ONE << (BOOLEAN_PLAINTEXT_BITS + 1)
}
