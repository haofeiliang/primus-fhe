use primus_fhe_core::{LookupTable, NttGadgetDomain};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{
    BooleanEvaluator, Evaluator, ServerKey, TfheParameters,
    error::{BooleanError, LookupTableError, TfheContextError},
};

/// A validated binding between explicit-modulus TFHE parameters and an NTT
/// table.
pub struct TfheContext<T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    parameters: TfheParameters<T>,
    table: Table,
}

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Binds TFHE parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.glwe().poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }

        let expected = parameters.glwe().cipher_modulus_value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }

        Ok(Self { parameters, table })
    }

    /// Returns the validated TFHE parameters.
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable NTT table.
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Returns the checked NTT domain used by GLWE key switching.
    #[inline]
    pub fn key_switching_domain(
        &self,
    ) -> NttGadgetDomain<'_, T, primus_modulus::BarrettModulus<T>, Table> {
        NttGadgetDomain::try_new(self.parameters.glwe_key_switching().output(), &self.table)
            .expect("TfheContext must contain a compatible key-switching domain")
    }

    /// Returns the checked NTT domain used by bootstrapping.
    #[inline]
    pub fn bootstrapping_domain(
        &self,
    ) -> NttGadgetDomain<'_, T, primus_modulus::BarrettModulus<T>, Table> {
        NttGadgetDomain::try_new(self.parameters.bootstrapping(), &self.table)
            .expect("TfheContext must contain a compatible bootstrapping domain")
    }

    /// Creates a Boolean gate evaluator.
    pub fn new_boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, BooleanError> {
        let evaluator = Evaluator::try_new(self, server_key)?;
        primus_fhe_core::BooleanEvaluator::try_new(&self.parameters, evaluator)
    }

    /// Compiles a unary function into a coefficient-domain GLWE accumulator.
    #[inline]
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        self.parameters.compile_lookup_table_fn(function)
    }

    /// Compiles one output per plaintext input into a GLWE accumulator.
    #[inline]
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        self.parameters.compile_lookup_table_slice(outputs)
    }

    /// Decomposes this context into its parameters and NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
