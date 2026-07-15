use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_fhe_core::{
    ClientKey, FourierFunctionalBootstrappingKey, FourierGadgetEncryptContext,
    FourierGlweSecretKey, GlweSecretKey, LweKeySwitchingKey, LweSecretKey,
};

use crate::{TfheContext, error::TfheKeyError};

/// Fourier-domain evaluation keys used by a TFHE server.
pub struct ServerKey<T: TorusFftValue> {
    bootstrapping_key: FourierFunctionalBootstrappingKey<T>,
    key_switching_key: LweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Returns the Fourier functional bootstrapping key.
    #[inline]
    pub fn bootstrapping_key(&self) -> &FourierFunctionalBootstrappingKey<T> {
        &self.bootstrapping_key
    }

    /// Returns the LWE key-switching key.
    #[inline]
    pub fn key_switching_key(&self) -> &LweKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Decomposes this server key into its bootstrapping and key-switching
    /// keys.
    #[inline]
    pub fn into_parts(self) -> (FourierFunctionalBootstrappingKey<T>, LweKeySwitchingKey<T>) {
        (self.bootstrapping_key, self.key_switching_key)
    }
}

/// Generates client and Fourier-domain server keys for one TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    fft: FftEngine<'a, Table>,
    gadget: FourierGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a key generator with reusable Fourier scratch.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        let parameters = context.parameters().bootstrapping();
        Self {
            context,
            fft: context.new_fft_engine(),
            gadget: FourierGadgetEncryptContext::new(
                parameters.poly_length(),
                parameters.decompose_length(),
            ),
        }
    }

    /// Generates fresh client-side secret keys.
    pub fn generate_client_key<R>(&self, rng: &mut R) -> ClientKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        ClientKey::new(
            LweSecretKey::generate(parameters.lwe(), rng),
            GlweSecretKey::generate(parameters.glwe(), rng),
        )
    }

    /// Generates a server key from an existing compatible client key.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;

        let fourier_glwe_secret_key = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        let bootstrapping_key = FourierFunctionalBootstrappingKey::generate_fourier(
            client_key.lwe_secret_key(),
            &fourier_glwe_secret_key,
            parameters.bootstrapping(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        let key_switching_key = LweKeySwitchingKey::generate(
            client_key.glwe_secret_key().as_slice(),
            client_key.lwe_secret_key(),
            parameters.lwe(),
            parameters.key_switching(),
            rng,
        );

        Ok(ServerKey {
            bootstrapping_key,
            key_switching_key,
        })
    }

    /// Generates a fresh compatible client/server key pair.
    pub fn generate<R>(&mut self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let client_key = self.generate_client_key(rng);
        let server_key = self.try_generate_server_key(&client_key, rng)?;
        Ok((client_key, server_key))
    }
}
