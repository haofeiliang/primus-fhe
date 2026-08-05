use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweKeySwitchingKey, FourierGlweSecretKey, GlweSecretKey,
};
use primus_lwe::LweSecretKey;
use primus_tfhe::ClientKey;

use crate::{FourierFunctionalBootstrappingKey, TfheContext, TfheParameters, error::TfheKeyError};

/// Fourier-domain evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: TorusFftValue> {
    bootstrapping_key: FourierFunctionalBootstrappingKey<T>,
    glwe_key_switching_key: FourierGlweKeySwitchingKey,
}

impl<T: TorusFftValue> ServerKey<T> {
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        let bootstrapping = parameters.bootstrapping();
        let key_switching = parameters.glwe_key_switching();
        self.bootstrapping_key.input_dimension() == parameters.small_lwe().dimension()
            && self.bootstrapping_key.input_modulus()
                == parameters.small_lwe().cipher_modulus_value()
            && self.bootstrapping_key.size() == bootstrapping.size()
            && self.glwe_key_switching_key.input_dimension() == key_switching.input_dimension()
            && self.glwe_key_switching_key.output_dimension() == key_switching.output_dimension()
            && self.glwe_key_switching_key.poly_length() == key_switching.poly_length()
    }

    /// Returns the Fourier functional bootstrapping key.
    #[inline]
    pub fn bootstrapping_key(&self) -> &FourierFunctionalBootstrappingKey<T> {
        &self.bootstrapping_key
    }

    /// Returns the Fourier GLWE key-switching key.
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &FourierGlweKeySwitchingKey {
        &self.glwe_key_switching_key
    }

    /// Decomposes this server key into its bootstrapping and key-switching
    /// keys.
    #[inline]
    pub fn into_parts(
        self,
    ) -> (
        FourierFunctionalBootstrappingKey<T>,
        FourierGlweKeySwitchingKey,
    ) {
        (self.bootstrapping_key, self.glwe_key_switching_key)
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
        let bootstrapping_parameters = context.parameters().bootstrapping();
        Self {
            context,
            fft: context.new_fft_engine(),
            gadget: FourierGadgetEncryptContext::new(bootstrapping_parameters.size()),
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

        let bootstrapping_key = self.generate_bootstrapping_key(client_key, rng);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);

        Ok(ServerKey {
            bootstrapping_key,
            glwe_key_switching_key,
        })
    }

    fn generate_bootstrapping_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> FourierFunctionalBootstrappingKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let main_glwe_secret_key = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        let bootstrapping_parameters = parameters.bootstrapping();
        self.gadget.resize(bootstrapping_parameters.size());
        FourierFunctionalBootstrappingKey::generate_fourier(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main_glwe_secret_key,
            bootstrapping_parameters,
            &mut self.fft,
            rng,
            &mut self.gadget,
        )
    }

    fn generate_glwe_key_switching_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> FourierGlweKeySwitchingKey
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let padded_small_glwe_secret_key = client_key.padded_small_glwe_secret_key(parameters);
        let padded_small_glwe_secret_key = FourierGlweSecretKey::from_coeff_secret_key(
            &padded_small_glwe_secret_key,
            &mut self.fft,
        );
        let key_switching = parameters.glwe_key_switching().output();
        self.gadget.resize(key_switching.size());
        FourierGlweKeySwitchingKey::generate(
            client_key.glwe_secret_key(),
            &padded_small_glwe_secret_key,
            key_switching,
            &mut self.fft,
            rng,
            &mut self.gadget,
        )
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
