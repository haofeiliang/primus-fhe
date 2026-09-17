use super::{BOOLEAN_PLAINTEXT_BITS, BooleanError, validate_boolean_parameters};
use crate::{LweCiphertext, PlaintextEmbedding, RoundedCodec, TfheParameters};
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
/// # Correctness
///
/// Inputs must encode 0/1 with unsigned rounded encoding modulo 4, under the
/// configured external key and ciphertext modulus. Explicit-modulus coefficients
/// must be canonical. Encoding and key identity cannot be checked from raw LWE
/// ciphertexts; the PBS backend's noise requirements also apply.
///
/// # Panics
///
/// Online operations panic when passed ciphertexts with a dimension different
/// from the configured external LWE dimension.
pub struct BooleanEvaluator<T, M, E>
where
    T: FheUint,
    M: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    ciphertext_modulus: M,
    external_lwe_dimension: usize,
    encoded_one: T,
    bootstrapper: E,
    gate_lookup_tables: [LookupTable<T>; 4],
    output_shift: T,
    gate_input: LweCiphertext<T>,
    mux_branch: LweCiphertext<T>,
}

impl<T, M, E> BooleanEvaluator<T, M, E>
where
    T: FheUint,
    M: RingContext<T>,
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
    pub fn try_new<GM>(
        parameters: &TfheParameters<T, M, GM>,
        bootstrapper: E,
    ) -> Result<Self, BooleanError>
    where
        GM: RingContext<T>,
    {
        validate_boolean_parameters(parameters)?;
        let ciphertext_modulus = parameters.small_lwe().cipher_modulus();
        let encoded_one = parameters
            .input_plaintext_codec()
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
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
        let dimension = parameters.external_lwe_dimension();
        let gate_input = LweCiphertext::zero(dimension);
        let mux_branch = LweCiphertext::zero(dimension);
        Ok(Self {
            ciphertext_modulus,
            external_lwe_dimension: dimension,
            encoded_one,
            bootstrapper,
            gate_lookup_tables,
            output_shift,
            gate_input,
            mux_branch,
        })
    }

    /// Evaluates a binary gate and allocates its output ciphertext.
    #[must_use]
    pub fn evaluate_binary(
        &mut self,
        gate: BooleanGate,
        lhs: &LweCiphertext<T>,
        rhs: &LweCiphertext<T>,
    ) -> LweCiphertext<T> {
        let mut output = LweCiphertext::zero(self.external_lwe_dimension);
        self.evaluate_binary_to(gate, lhs, rhs, &mut output);
        output
    }

    /// Evaluates a binary gate into an existing output allocation.
    pub fn evaluate_binary_to(
        &mut self,
        gate: BooleanGate,
        lhs: &LweCiphertext<T>,
        rhs: &LweCiphertext<T>,
        output: &mut LweCiphertext<T>,
    ) {
        prepare_binary_gate(
            gate,
            lhs,
            rhs,
            &mut self.gate_input,
            self.ciphertext_modulus,
        );
        let lookup_table = &self.gate_lookup_tables[gate.lookup_table_index()];
        self.bootstrapper
            .apply_lookup_table_to(&self.gate_input, lookup_table, output);
        self.ciphertext_modulus
            .reduce_add_assign(output.b_mut(), self.output_shift);
    }

    /// Evaluates an AND gate.
    #[must_use]
    #[inline]
    pub fn and(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::And, lhs, rhs)
    }

    /// Evaluates a NAND gate.
    #[must_use]
    #[inline]
    pub fn nand(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nand, lhs, rhs)
    }

    /// Evaluates an OR gate.
    #[must_use]
    #[inline]
    pub fn or(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Or, lhs, rhs)
    }

    /// Evaluates a NOR gate.
    #[must_use]
    #[inline]
    pub fn nor(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nor, lhs, rhs)
    }

    /// Evaluates an XOR gate.
    #[must_use]
    #[inline]
    pub fn xor(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xor, lhs, rhs)
    }

    /// Evaluates an XNOR gate.
    #[must_use]
    #[inline]
    pub fn xnor(&mut self, lhs: &LweCiphertext<T>, rhs: &LweCiphertext<T>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xnor, lhs, rhs)
    }

    /// Selects 'then_value' when 'condition' is true and 'else_value'
    /// otherwise.
    ///
    /// This uses two bootstrapped AND terms followed by one LWE addition.
    #[must_use]
    pub fn mux(
        &mut self,
        condition: &LweCiphertext<T>,
        then_value: &LweCiphertext<T>,
        else_value: &LweCiphertext<T>,
    ) -> LweCiphertext<T> {
        let mut output = LweCiphertext::zero(self.external_lwe_dimension);
        self.mux_to(condition, then_value, else_value, &mut output);
        output
    }

    /// Evaluates a multiplexer into an existing output allocation.
    pub fn mux_to(
        &mut self,
        condition: &LweCiphertext<T>,
        then_value: &LweCiphertext<T>,
        else_value: &LweCiphertext<T>,
        output: &mut LweCiphertext<T>,
    ) {
        prepare_binary_gate(
            BooleanGate::And,
            condition,
            then_value,
            &mut self.gate_input,
            self.ciphertext_modulus,
        );
        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            &mut self.mux_branch,
        );
        let modulus = self.ciphertext_modulus;
        modulus.reduce_add_assign(self.mux_branch.b_mut(), self.output_shift);

        assert_dimension(else_value, self.external_lwe_dimension);
        self.gate_input.0.copy_from_slice(else_value.0.as_slice());
        self.gate_input.sub_assign(condition, modulus);
        modulus.reduce_add_assign(self.gate_input.b_mut(), self.encoded_one);

        self.bootstrapper.apply_lookup_table_to(
            &self.gate_input,
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            output,
        );
        modulus.reduce_add_assign(output.b_mut(), self.output_shift);
        output.add_assign(&self.mux_branch, modulus);
    }

    /// Negates a Boolean ciphertext without programmable bootstrapping.
    #[must_use]
    pub fn not(&self, input: &LweCiphertext<T>) -> LweCiphertext<T> {
        assert_dimension(input, self.external_lwe_dimension);
        let mut output = input.clone();
        self.not_assign(&mut output);
        output
    }

    /// Negates a Boolean ciphertext into an existing allocation without PBS.
    pub fn not_to(&self, input: &LweCiphertext<T>, output: &mut LweCiphertext<T>) {
        assert_dimension(input, self.external_lwe_dimension);
        assert_dimension(output, self.external_lwe_dimension);
        output.0.copy_from_slice(input.0.as_slice());
        self.not_assign(output);
    }

    fn not_assign(&self, ciphertext: &mut LweCiphertext<T>) {
        let modulus = self.ciphertext_modulus;
        ciphertext.neg_assign(modulus);
        ciphertext.add_plaintext_assign(self.encoded_one, modulus);
    }

    /// Returns the backend PBS evaluator.
    #[must_use]
    #[inline]
    pub fn bootstrapper(&self) -> &E {
        &self.bootstrapper
    }

    /// Returns the backend PBS evaluator mutably.
    #[must_use]
    #[inline]
    pub fn bootstrapper_mut(&mut self) -> &mut E {
        &mut self.bootstrapper
    }

    /// Decomposes this evaluator into its backend PBS evaluator.
    #[must_use]
    #[inline]
    pub fn into_bootstrapper(self) -> E {
        self.bootstrapper
    }
}

fn prepare_binary_gate<T, M>(
    gate: BooleanGate,
    lhs: &LweCiphertext<T>,
    rhs: &LweCiphertext<T>,
    output: &mut LweCiphertext<T>,
    modulus: M,
) where
    T: FheUint,
    M: RingContext<T>,
{
    assert_dimension(lhs, output.dimension());
    assert_dimension(rhs, output.dimension());

    match gate {
        BooleanGate::And | BooleanGate::Nand | BooleanGate::Or | BooleanGate::Nor => {
            lhs.add_to(rhs, output, modulus);
        }
        BooleanGate::Xor | BooleanGate::Xnor => {
            lhs.sub_to(rhs, output, modulus);
            output.mul_scalar_assign(T::TWO, modulus);
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
    let modulus = parameters.accumulator_glwe().cipher_modulus();
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

fn assert_dimension<T: FheUint>(ciphertext: &LweCiphertext<T>, expected: usize) {
    assert_eq!(
        ciphertext.dimension(),
        expected,
        "Boolean LWE dimension mismatch"
    );
}

#[inline]
fn boolean_accumulator_plaintext_modulus<T: FheUint>() -> T {
    T::ONE << (BOOLEAN_PLAINTEXT_BITS + 1)
}
