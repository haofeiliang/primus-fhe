use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{
    CircuitBootstrapConfig, ClientKey, Decryptor, Encryptor, Evaluator, KeyGenerationError,
    KeyGenerator, ServerKey, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheParameters,
};

/// Validated binding between NTRU TFHE parameters and one exact NTT table.
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
    /// Builds the selected NTT table using the accumulator length and modulus.
    ///
    /// Preserves table-construction errors, including an unavailable primitive
    /// root or unsupported modulus. Use [`Self::try_new`] to inject an existing table.
    pub fn try_from_parameters(parameters: TfheParameters<T>) -> Result<Self, TfheContextError<T>> {
        let accumulator = parameters.accumulator_ntru();
        let table = Table::new(
            accumulator.poly_length().trailing_zeros(),
            accumulator.cipher_modulus(),
        )?;
        Ok(Self { parameters, table })
    }

    /// Binds parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        let expected = parameters.accumulator_ntru().cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the bound NTT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client(
        &self,
        client_key: &ClientKey<T>,
    ) -> Result<crate::AccumulatorClient<'_, T, Table>, crate::KeyGenerationError> {
        crate::AccumulatorClient::try_new(self, client_key)
    }

    /// Generates a fresh client/server pair; `None` selects PBS only and
    /// `Some(config)` also generates the configured CBS material.
    /// Inherits [`KeyGenerator::try_generate`]'s rejection-sampling errors and CBS requirements.
    pub fn try_generate_keys<R>(
        &self,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate(circuit_bootstrap, rng)
    }

    /// Creates a secret-key or public-key encryptor after checking compatibility.
    /// Public-key contracts follow [`primus_tfhe_ntru::EncryptionKey`].
    pub fn encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<Encryptor<'a, T, Key>, TfheClientError>
    where
        Key: primus_tfhe_ntru::EncryptionKey<T, primus_modulus::BarrettModulus<T>>,
    {
        Encryptor::try_new(&self.parameters, key)
    }

    /// Creates a client decryptor after checking the key once.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        Decryptor::try_new(&self.parameters, client_key)
    }

    /// Creates an evaluator with reusable NTT and coefficient workspaces.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }

    /// Generates optional CBS material under this client's accumulator secret.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        parameters: crate::CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<crate::CircuitBootstrapKey<T>, crate::KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(client_key, parameters, rng)
    }

    /// Binds the server key's optional CBS material to reusable workspace.
    /// Returns an error if the capability is absent or incompatible.
    ///
    /// # Correctness
    /// Inherits [`crate::CircuitBootstrapEvaluator::try_new`]'s transform requirements.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<crate::CircuitBootstrapEvaluator<'a, T, Table>, crate::TfheEvaluationError> {
        crate::CircuitBootstrapEvaluator::try_new(self, server_key)
    }

    /// Decomposes this context into parameters and its NTT table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
