use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGadgetEncryptContext, FourierGlweKeySwitchingKey, FourierGlweSecretKey, SecretKeyDistr,
};
use primus_lwe::LweSecretKey;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters,
    FourierGlweBootstrappingKey, KeyGenerationError, SparseGlweBootstrappingKey, TfheContext,
    TfheParameters,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store Fourier GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BootstrappingKey<T: TorusFftValue> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(FourierGlweBootstrappingKey<T, NativeModulus<T>>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T>),
}

impl<T: TorusFftValue> BootstrappingKey<T> {
    fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        // Both variants and the backend parameters fix the modulus to Native<T>.
        let (dimension, distribution, size, basis) = match self {
            Self::Classic(key) => (
                key.input_dimension(),
                key.input_distribution(),
                key.size(),
                key.basis(),
            ),
            Self::Sparse(key) => (
                key.input_dimension(),
                SecretKeyDistr::FixedHammingWeightBinary {
                    hamming_weight: key.hamming_weight(),
                },
                key.size(),
                key.basis(),
            ),
        };
        dimension == parameters.small_lwe().dimension()
            && distribution == parameters.small_lwe().secret_key_distr()
            && size == parameters.blind_rotation_ggsw().size()
            && basis == parameters.blind_rotation_ggsw().basis()
    }
}

/// Classic or sparse evaluation keys used by a Fourier TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: TorusFftValue> {
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
    bootstrapping_key: BootstrappingKey<T>,
    glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Returns the bound CBS parameters and keys, if requested during generation.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> Option<&CircuitBootstrapKey<T>> {
        self.circuit_bootstrap.as_deref()
    }

    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        let key_switching = parameters.glwe_key_switching();
        self.bootstrapping_key.is_compatible(parameters)
            && self.glwe_key_switching_key.input_dimension() == key_switching.input_dimension()
            && self.glwe_key_switching_key.output_dimension() == key_switching.output_dimension()
            && self.glwe_key_switching_key.poly_length() == key_switching.poly_length()
            && self.glwe_key_switching_key.output_size() == key_switching.output_size()
            && self.glwe_key_switching_key.basis() == key_switching.output().basis()
    }

    /// Returns the selected classic or sparse blind-rotation key.
    #[must_use]
    #[inline]
    pub fn bootstrapping_key(&self) -> &BootstrappingKey<T> {
        &self.bootstrapping_key
    }

    /// Returns the Fourier GLWE key-switching key.
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &FourierGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Decomposes this server key into its bootstrapping and key-switching
    /// keys and optional CBS material.
    #[must_use]
    #[inline]
    pub fn into_parts(
        self,
    ) -> (
        BootstrappingKey<T>,
        FourierGlweKeySwitchingKey<T>,
        Option<CircuitBootstrapKey<T>>,
    ) {
        (
            self.bootstrapping_key,
            self.glwe_key_switching_key,
            self.circuit_bootstrap.map(|key| *key),
        )
    }
}

/// Generates client and classic or sparse server keys for one Fourier context.
pub struct KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) fft: FftEngine<'a, Table>,
    pub(crate) gadget: FourierGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a key generator with reusable Fourier scratch.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        let blind_rotation_ggsw = context.parameters().blind_rotation_ggsw();
        Self {
            context,
            fft: context.new_fft_engine(),
            gadget: FourierGadgetEncryptContext::new(blind_rotation_ggsw.size()),
        }
    }

    /// Generates the selected capabilities from one compatible client key.
    /// Invalid CBS configuration is rejected before sampling evaluation material.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let circuit_parameters = self.prepare_circuit_bootstrap(circuit_bootstrap)?;
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;

        let main_glwe_secret_key = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        Ok(self.generate_server_key_with_main(
            client_key,
            main_glwe_secret_key,
            circuit_parameters,
            rng,
        ))
    }

    /// Generates a sparse server key with optional CBS material for an existing client.
    ///
    /// Uses the client's fixed-weight binary small-LWE secret in both PBS orders.
    /// The GLWE key-switching key has the same domains as in classic PBS. Sparse
    /// generation checks parameters and privately retries matching before KSK
    /// allocation; a failure returns no partial server key.
    ///
    /// # Errors
    /// Invalid CBS configuration is rejected before sampling. Otherwise inherits
    /// [`Self::try_generate_sparse_bootstrapping_key`]'s errors.
    ///
    /// # Correctness
    /// Inherits that method's secret and security requirements. The caller must
    /// budget sparse aggregation noise and, for interleaved LUTs, coarser rotations.
    /// Enabling CBS also inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// requirements; aggregate FFT, native halving and trace/scheme-switch errors
    /// must fit the smallest output gadget scale.
    pub fn try_generate_sparse_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let circuit_parameters = self.prepare_circuit_bootstrap(circuit_bootstrap)?;
        let prepared = self.prepare_sparse_map(client_key, copy_count, bucket_count, rng)?;
        let main = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        let bootstrapping_key =
            self.generate_sparse_bootstrapping_key_with_main(prepared, &main, rng);
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            Box::new(
                self.generate_circuit_bootstrap_key_with_main(client_key, &main, parameters, rng),
            )
        });
        drop(main);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        Ok(ServerKey {
            circuit_bootstrap,
            bootstrapping_key: BootstrappingKey::Sparse(bootstrapping_key),
            glwe_key_switching_key,
        })
    }

    /// The caller has checked the client key and prepared its matching main
    /// transform with this context's table. Taking ownership bounds its lifetime
    /// to BSK and optional CBS generation, before allocating key-switching material.
    fn generate_server_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: FourierGlweSecretKey,
        circuit_parameters: Option<CircuitBootstrapParameters<T>>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let blind_rotation_ggsw = parameters.blind_rotation_ggsw();
        self.gadget.resize(blind_rotation_ggsw.size());
        let bootstrapping_key = FourierGlweBootstrappingKey::generate_fourier(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main_glwe_secret_key,
            blind_rotation_ggsw,
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            Box::new(self.generate_circuit_bootstrap_key_with_main(
                client_key,
                &main_glwe_secret_key,
                parameters,
                rng,
            ))
        });
        drop(main_glwe_secret_key);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        ServerKey {
            circuit_bootstrap,
            bootstrapping_key: BootstrappingKey::Classic(bootstrapping_key),
            glwe_key_switching_key,
        }
    }

    fn generate_glwe_key_switching_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> FourierGlweKeySwitchingKey<T>
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

    /// Generates a fresh compatible pair with the selected evaluation capabilities.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    pub fn try_generate<R>(
        &mut self,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let circuit_parameters = self.prepare_circuit_bootstrap(circuit_bootstrap)?;
        let parameters = self.context.parameters();
        let small_lwe_secret_key = LweSecretKey::generate(parameters.small_lwe(), rng);
        let (glwe_secret_key, main_glwe_secret_key) =
            FourierGlweSecretKey::generate_pair(parameters.accumulator_glwe(), &mut self.fft, rng);
        let client_key = ClientKey::new(
            small_lwe_secret_key,
            glwe_secret_key,
            parameters.pbs_order(),
        );
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_with_main(
            &client_key,
            main_glwe_secret_key,
            circuit_parameters,
            rng,
        );
        Ok((client_key, server_key))
    }

    fn prepare_circuit_bootstrap(
        &self,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
    ) -> Result<Option<CircuitBootstrapParameters<T>>, KeyGenerationError> {
        circuit_bootstrap
            .map(|config| {
                CircuitBootstrapParameters::try_from_config(self.context.parameters(), config)
            })
            .transpose()
            .map_err(Into::into)
    }
}
