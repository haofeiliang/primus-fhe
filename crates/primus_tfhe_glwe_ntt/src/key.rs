use primus_glwe::{
    GlweSecretKey, NttGadgetEncryptContext, NttGlweKeySwitchingKey, NttGlweSecretKey,
};
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_ntt::NttTable;
use primus_tfhe_glwe::GlweClientKey as ClientKey;

use crate::{NttGlweBootstrappingKey, TfheContext, TfheParameters, error::TfheKeyError};

/// NTT-domain evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: FheUint> {
    bootstrapping_key: NttGlweBootstrappingKey<T>,
    glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        let bootstrapping = parameters.bootstrapping();
        let key_switching = parameters.glwe_key_switching();
        self.bootstrapping_key.input_dimension() == parameters.small_lwe().dimension()
            && self.bootstrapping_key.input_modulus()
                == parameters.small_lwe().cipher_modulus_value()
            && self.bootstrapping_key.size() == bootstrapping.size()
            && self.bootstrapping_key.basis() == bootstrapping.basis()
            && self.bootstrapping_key.cipher_modulus()
                == Some(parameters.glwe().cipher_modulus_value())
            && self.glwe_key_switching_key.input_dimension() == key_switching.input_dimension()
            && self.glwe_key_switching_key.output_dimension() == key_switching.output_dimension()
            && self.glwe_key_switching_key.poly_length() == key_switching.poly_length()
            && self.glwe_key_switching_key.output_size() == key_switching.output_size()
            && self.glwe_key_switching_key.basis() == key_switching.output().basis()
    }

    /// Returns the NTT functional bootstrapping key.
    #[inline]
    pub fn bootstrapping_key(&self) -> &NttGlweBootstrappingKey<T> {
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
    pub fn into_parts(self) -> (NttGlweBootstrappingKey<T>, NttGlweKeySwitchingKey<T>) {
        (self.bootstrapping_key, self.glwe_key_switching_key)
    }
}

/// Generates client and NTT-domain server keys for one TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) gadget: NttGadgetEncryptContext<T>,
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
            GlweSecretKey::generate(
                parameters.glwe().size(),
                parameters.glwe().secret_key_sampler(),
                rng,
            ),
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
        Ok(self.generate_server_key_with_main(client_key, main_glwe_secret_key, rng))
    }

    /// The caller has checked the client key and prepared its matching main
    /// transform with this context's table. Taking ownership bounds its lifetime
    /// to BSK generation, before allocating the key-switching material.
    fn generate_server_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: NttGlweSecretKey<T>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        self.gadget.resize(parameters.bootstrapping().size());
        let bootstrapping_key = NttGlweBootstrappingKey::generate_ntt(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main_glwe_secret_key,
            parameters.bootstrapping(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        drop(main_glwe_secret_key);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        ServerKey {
            bootstrapping_key,
            glwe_key_switching_key,
        }
    }

    fn generate_glwe_key_switching_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> NttGlweKeySwitchingKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let padded_small_glwe_secret_key = client_key.padded_small_glwe_secret_key(parameters);
        let padded_small_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            &padded_small_glwe_secret_key,
            self.context.table(),
        );
        self.gadget
            .resize(parameters.glwe_key_switching().output().size());
        NttGlweKeySwitchingKey::generate(
            client_key.glwe_secret_key(),
            &padded_small_glwe_secret_key,
            parameters.glwe_key_switching().output(),
            self.context.table(),
            rng,
            &mut self.gadget,
        )
    }

    /// Generates a fresh compatible client/server key pair.
    pub fn generate<R>(&mut self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let small_lwe_secret_key = LweSecretKey::generate(parameters.small_lwe(), rng);
        let (glwe_secret_key, main_glwe_secret_key) =
            NttGlweSecretKey::generate_pair(parameters.glwe(), self.context.table(), rng);
        let client_key = ClientKey::new(
            small_lwe_secret_key,
            glwe_secret_key,
            parameters.pbs_order(),
        );
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_with_main(&client_key, main_glwe_secret_key, rng);
        Ok((client_key, server_key))
    }
}
