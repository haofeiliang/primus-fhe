use primus_fhe_core::{
    ClientKey, GlweSecretKey, LweKeySwitchingKey, LweSecretKey, NttFunctionalBootstrappingKey,
    NttGadgetEncryptContext, NttGlweSecretKey,
};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{TfheContext, error::TfheKeyError};

/// NTT-domain evaluation keys used by a TFHE server.
pub struct ServerKey<T: FheUint> {
    bootstrapping_key: NttFunctionalBootstrappingKey<T>,
    key_switching_key: LweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    /// Returns the NTT functional bootstrapping key.
    #[inline]
    pub fn bootstrapping_key(&self) -> &NttFunctionalBootstrappingKey<T> {
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
    pub fn into_parts(self) -> (NttFunctionalBootstrappingKey<T>, LweKeySwitchingKey<T>) {
        (self.bootstrapping_key, self.key_switching_key)
    }
}

/// Generates client and NTT-domain server keys for one TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    gadget: NttGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Creates a key generator with reusable NTT gadget scratch.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        let parameters = context.parameters().bootstrapping();
        Self {
            context,
            gadget: NttGadgetEncryptContext::new(
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

        let ntt_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        let bootstrapping_key = NttFunctionalBootstrappingKey::generate_ntt(
            client_key.lwe_secret_key(),
            &ntt_glwe_secret_key,
            parameters.bootstrapping(),
            self.context.table(),
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
