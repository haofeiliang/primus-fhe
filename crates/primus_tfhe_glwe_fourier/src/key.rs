//! Server evaluation material and paired or component key generation.

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweGadgetEncryptWorkspace, FourierGlweKeySwitchingKey, FourierGlweSecretKey,
    SecretKeyDistr,
};
use primus_lwe::LweSecretKey;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters,
    FourierGlweBootstrappingKey, KeyGenerationError, SparseGlweBootstrappingKey, TfheContext,
    TfheParameters,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store Fourier GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BlindRotationKey<T: TorusFftValue> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(FourierGlweBootstrappingKey<T, NativeModulus<T>>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T>),
}

impl<T: TorusFftValue> BlindRotationKey<T> {
    /// Validate the selected BR layout and input domain, independently of ring KS/CBS.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
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
        dimension == (parameters.small_lwe().dimension())
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
    blind_rotation_key: BlindRotationKey<T>,
    glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Combines independently generated material by moving its owned buffers.
    /// Evaluator construction checks compatibility; this does not prove secret
    /// or transform identity. Both PBS orders use the same ring KS direction.
    #[must_use]
    pub fn new(
        blind_rotation_key: BlindRotationKey<T>,
        glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
        circuit_bootstrap: Option<CircuitBootstrapKey<T>>,
    ) -> Self {
        Self {
            blind_rotation_key,
            glwe_key_switching_key,
            circuit_bootstrap: circuit_bootstrap.map(Box::new),
        }
    }

    /// Returns the bound CBS parameters and keys, if requested during generation.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> Option<&CircuitBootstrapKey<T>> {
        self.circuit_bootstrap.as_deref()
    }

    /// Returns the selected classic or sparse blind-rotation key.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation_key
    }

    /// Returns the Fourier GLWE key-switching key.
    #[must_use]
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
        BlindRotationKey<T>,
        FourierGlweKeySwitchingKey<T>,
        Option<CircuitBootstrapKey<T>>,
    ) {
        (
            self.blind_rotation_key,
            self.glwe_key_switching_key,
            self.circuit_bootstrap.map(|key| *key),
        )
    }
}

/// Checks the ring KS layout and basis once, before allocating evaluation scratch.
/// Fourier uses `NativeModulus<T>` throughout this backend.
pub(crate) fn check_glwe_key_switching_key<T: TorusFftValue>(
    parameters: &TfheParameters<T>,
    key: &FourierGlweKeySwitchingKey<T>,
) -> Result<(), crate::TfheEvaluationError> {
    let expected = parameters.glwe_key_switching();
    if key.input_dimension() != expected.input_dimension()
        || key.output_size() != expected.output_size()
        || key.basis() != expected.output().basis()
    {
        return Err(crate::TfheEvaluationError::IncompatibleGlweKeySwitchingKey);
    }
    Ok(())
}

/// Generates client and classic or sparse server keys for one Fourier context.
pub struct KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) fft: FftEngine<'a, Table>,
    pub(crate) gadget: FourierGlweGadgetEncryptWorkspace<T>,
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
            gadget: FourierGlweGadgetEncryptWorkspace::new(blind_rotation_ggsw.size()),
        }
    }

    /// Generates classic binary/ternary BR material without ring KS or CBS keys.
    /// Both client secrets are needed; the small secret controls rotation and the
    /// accumulator secret encrypts those controls.
    ///
    /// # Correctness
    /// Use the same paired secrets and this context's transform representation
    /// when combining independently generated materials.
    pub fn try_generate_classic_blind_rotation_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<FourierGlweBootstrappingKey<T, NativeModulus<T>>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;
        let main = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        self.gadget.resize(parameters.blind_rotation_ggsw().size());
        Ok(FourierGlweBootstrappingKey::generate_fourier(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main,
            parameters.blind_rotation_ggsw(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        ))
    }

    /// Generates ring KS material from the accumulator to the padded small secret.
    /// PBS order determines whether it is used before BR or when returning its result.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_classic_blind_rotation_key`]'s secret and transform requirements.
    pub fn try_generate_glwe_key_switching_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<FourierGlweKeySwitchingKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        client_key.check_compatible(self.context.parameters())?;
        Ok(self.generate_glwe_key_switching_key(client_key, rng))
    }

    /// Generates BR, ring KS and optional CBS material for one existing client.
    /// PBS order places ring KS before BR or in the ordinary return stage.
    /// `blind_rotation` selects the algorithm independently of the client's distribution.
    /// Sparse generation requires a fixed-weight binary secret with `0 < h < n` and
    /// valid bucket counts. It retries only the public map (at most eight attempts),
    /// never the client secret, and never falls back to classic. Invalid CBS configuration
    /// is rejected before sampling; a failed matching returns no partial server key.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_classic_blind_rotation_key`] and
    /// [`Self::try_generate_sparse_blind_rotation_key`]'s secret, transform and noise
    /// requirements for the selected algorithm. CBS additionally inherits
    /// [`Self::try_generate_circuit_bootstrap_key`]'s requirements; PBS correctness
    /// alone does not establish a margin at the smallest CBS gadget scale. Budget
    /// sparse aggregation noise and the coarser rotations of interleaved LUTs.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        blind_rotation: BlindRotationConfig,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match blind_rotation {
            BlindRotationConfig::Classic => {
                self.try_generate_classic_server_key(client_key, circuit_bootstrap, rng)
            }
            BlindRotationConfig::Sparse {
                copy_count,
                bucket_count,
            } => self.try_generate_sparse_server_key(
                client_key,
                copy_count,
                bucket_count,
                circuit_bootstrap,
                rng,
            ),
        }
    }

    // Keep algorithm-specific preparation and sampling order in their existing paths.
    fn try_generate_classic_server_key<R>(
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

    // Sparse map generation retains the client secret and prepares optional CBS before sampling.
    fn try_generate_sparse_server_key<R>(
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
        let blind_rotation_key =
            self.generate_sparse_bootstrapping_key_with_main(prepared, &main, rng);
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            Box::new(self.generate_circuit_bootstrap_key_with_main(
                client_key.glwe_secret_key(),
                &main,
                parameters,
                rng,
            ))
        });
        drop(main);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        Ok(ServerKey {
            circuit_bootstrap,
            blind_rotation_key: BlindRotationKey::Sparse(blind_rotation_key),
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
        let blind_rotation_key = FourierGlweBootstrappingKey::generate_fourier(
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
                client_key.glwe_secret_key(),
                &main_glwe_secret_key,
                parameters,
                rng,
            ))
        });
        drop(main_glwe_secret_key);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        ServerKey {
            circuit_bootstrap,
            blind_rotation_key: BlindRotationKey::Classic(blind_rotation_key),
            glwe_key_switching_key,
        }
    }

    /// Generates after the setup bundle has passed compatibility checks.
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

    /// Generates a fresh classic pair with the selected evaluation capabilities.
    /// For sparse BR, generate a fixed-weight client first and use [`Self::try_generate_server_key`].
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    ///
    /// CBS configuration errors are returned before sampling any keys.
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
        let accumulator = parameters.blind_rotation_ggsw();
        let (glwe_secret_key, main_glwe_secret_key) = FourierGlweSecretKey::generate_pair(
            accumulator.glwe_size(),
            accumulator.inner(),
            &mut self.fft,
            rng,
        );
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

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates a fresh classic client/server pair; `None` selects PBS only and
    /// `Some(config)` also generates the configured CBS material.
    /// Inherits [`KeyGenerator::try_generate`]'s CBS requirements.
    ///
    /// Distribution and fixed-weight validity is established by parameter construction.
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
}
