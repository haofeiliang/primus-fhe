use primus_fhe_core::{
    ClientKey, GlweSecretKey, LweSecretKey, NttFunctionalBootstrappingKey, NttGadgetEncryptContext,
    NttGlweKeySwitchingKey, NttGlweSecretKey,
};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{TfheContext, error::TfheKeyError};

/// NTT-domain evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: FheUint> {
    bootstrapping_key: NttFunctionalBootstrappingKey<T>,
    glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    /// Returns the NTT functional bootstrapping key.
    #[inline]
    pub fn bootstrapping_key(&self) -> &NttFunctionalBootstrappingKey<T> {
        &self.bootstrapping_key
    }

    /// Returns the NTT GLWE key-switching key.
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &NttGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Decomposes this server key into its bootstrapping and key-switching
    /// keys.
    #[inline]
    pub fn into_parts(self) -> (NttFunctionalBootstrappingKey<T>, NttGlweKeySwitchingKey<T>) {
        (self.bootstrapping_key, self.glwe_key_switching_key)
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
            gadget: NttGadgetEncryptContext::new(parameters.size()),
        }
    }

    /// Generates fresh client-side secret keys.
    pub fn generate_client_key<R>(&self, rng: &mut R) -> ClientKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        ClientKey::new(
            LweSecretKey::generate(parameters.small_lwe(), rng),
            GlweSecretKey::generate(parameters.glwe(), rng),
            parameters.pbs_order(),
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

        let main_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        let bootstrapping_domain = self.context.bootstrapping_domain();
        self.gadget.resize(bootstrapping_domain.size());
        let bootstrapping_key = NttFunctionalBootstrappingKey::generate_ntt(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main_glwe_secret_key,
            &bootstrapping_domain,
            rng,
            &mut self.gadget,
        );
        let padded_small_glwe_secret_key = GlweSecretKey::from_padded_lwe(
            client_key.small_lwe_secret_key(),
            parameters.glwe().poly_length(),
            parameters.small_lwe().cipher_modulus_minus_one(),
        )
        .expect("validated TFHE parameters must admit a padded small-LWE key");
        let padded_small_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            &padded_small_glwe_secret_key,
            self.context.table(),
        );
        let key_switching_domain = self.context.key_switching_domain();
        self.gadget.resize(key_switching_domain.size());
        let glwe_key_switching_key = NttGlweKeySwitchingKey::generate(
            client_key.glwe_secret_key(),
            &padded_small_glwe_secret_key,
            &key_switching_domain,
            rng,
            &mut self.gadget,
        );

        Ok(ServerKey {
            bootstrapping_key,
            glwe_key_switching_key,
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
