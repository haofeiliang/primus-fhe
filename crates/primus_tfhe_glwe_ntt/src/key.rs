//! Server evaluation material and paired or component key generation.

use primus_glwe::{
    NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_reduce::Modulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters,
    KeyGenerationError, NttGlweBootstrappingKey, SparseGlweBootstrappingKey, TfheContext,
    TfheParameters,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store NTT GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BlindRotationKey<T: FheUint> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(NttGlweBootstrappingKey<T, BarrettModulus<T>>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T, BarrettModulus<T>>),
}

impl<T: FheUint> BlindRotationKey<T> {
    /// Validate the selected BR layout and input domain, independently of ring KS/CBS.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        let (dimension, input_modulus, size, basis, cipher_modulus) = match self {
            Self::Classic(key) => {
                if key.input_distribution() != parameters.small_lwe().secret_key_distr() {
                    return false;
                }
                (
                    key.input_dimension(),
                    key.input_modulus().explicit_value(),
                    key.size(),
                    key.basis(),
                    key.cipher_modulus(),
                )
            }
            Self::Sparse(key) => {
                if parameters.small_lwe().secret_key_distr()
                    != (SecretKeyDistr::FixedHammingWeightBinary {
                        hamming_weight: key.hamming_weight(),
                    })
                {
                    return false;
                }
                (
                    key.input_dimension(),
                    key.input_modulus().explicit_value(),
                    key.size(),
                    key.basis(),
                    key.cipher_modulus(),
                )
            }
        };
        dimension == (parameters.small_lwe().dimension())
            && input_modulus == parameters.small_lwe().cipher_modulus_value()
            && size == parameters.blind_rotation_ggsw().size()
            && basis == parameters.blind_rotation_ggsw().basis()
            && cipher_modulus == parameters.cipher_modulus().explicit_value()
    }
}

/// Classic or sparse evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: FheUint> {
    blind_rotation_key: BlindRotationKey<T>,
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
    glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    /// Combines independently generated material by moving its owned buffers.
    /// Evaluator construction checks compatibility; this does not prove secret
    /// or transform identity. Both PBS orders use the same ring KS direction.
    #[must_use]
    pub fn new(
        blind_rotation_key: BlindRotationKey<T>,
        glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
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

    /// Returns the NTT GLWE key-switching key.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &NttGlweKeySwitchingKey<T> {
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
        NttGlweKeySwitchingKey<T>,
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
/// Basis equality also checks the NTT coefficient modulus.
pub(crate) fn check_glwe_key_switching_key<T: FheUint>(
    parameters: &TfheParameters<T>,
    key: &NttGlweKeySwitchingKey<T>,
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

/// Generates client and classic or sparse server keys for one NTT context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) gadget: NttGlweGadgetEncryptWorkspace<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates a key generator with reusable NTT gadget scratch.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        let parameters = context.parameters().blind_rotation_ggsw();
        Self {
            context,
            gadget: NttGlweGadgetEncryptWorkspace::new(parameters.size()),
        }
    }

    /// Generates only BR material, selecting classic or sparse from the config.
    /// No return or CBS key is generated. The client's secret distribution is
    /// unchanged; sparse matching never falls back to classic or resamples it.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_classic_blind_rotation_key`] or
    /// [`Self::try_generate_sparse_blind_rotation_key`]'s requirements for the
    /// selected algorithm. Independently generated components must share the
    /// actual secrets and transform representation.
    ///
    /// # Errors
    /// Propagates the selected generator's validation, conversion and matching errors.
    pub fn try_generate_blind_rotation_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        blind_rotation: BlindRotationConfig,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match blind_rotation {
            BlindRotationConfig::Classic => self
                .try_generate_classic_blind_rotation_key(client_key, rng)
                .map(BlindRotationKey::Classic),
            BlindRotationConfig::Sparse {
                copy_count,
                bucket_count,
            } => self
                .try_generate_sparse_blind_rotation_key(client_key, copy_count, bucket_count, rng)
                .map(BlindRotationKey::Sparse),
        }
    }

    /// Generates classic binary/ternary BR material without ring KS or CBS keys.
    /// Both client secrets are needed; the small secret controls rotation and the
    /// accumulator secret encrypts those controls.
    ///
    /// # Correctness
    /// Use the same paired secrets and this context's transform representation
    /// when combining independently generated materials.
    /// Imported coefficients inherit [`NttGlweSecretKey::from_coeff_secret_key`]'s
    /// unsigned-magnitude bound.
    pub fn try_generate_classic_blind_rotation_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<NttGlweBootstrappingKey<T, BarrettModulus<T>>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;
        let main = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        self.gadget.resize(parameters.blind_rotation_ggsw().size());
        Ok(NttGlweBootstrappingKey::generate_ntt(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main,
            parameters.blind_rotation_ggsw(),
            self.context.table(),
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
    ) -> Result<NttGlweKeySwitchingKey<T>, KeyGenerationError>
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
        let circuit_parameters = self.prepare_circuit_bootstrap(circuit_bootstrap)?;
        client_key.check_compatible(self.context.parameters())?;
        let sparse_layout = match blind_rotation {
            BlindRotationConfig::Classic => None,
            BlindRotationConfig::Sparse {
                copy_count,
                bucket_count,
            } => Some(self.prepare_sparse_layout(copy_count, bucket_count)?),
        };
        let transformed = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        self.generate_server_key_with_main(
            client_key,
            transformed,
            sparse_layout,
            circuit_parameters,
            rng,
        )
    }

    /// The caller established client compatibility by sampling or validation,
    /// and prepared its matching main transform with this context's table. Ownership
    /// bounds its lifetime to BR and CBS, before allocating key-switching material.
    fn generate_server_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: NttGlweSecretKey<T>,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        circuit_parameters: Option<CircuitBootstrapParameters<T>>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        self.gadget.resize(parameters.blind_rotation_ggsw().size());
        let blind_rotation_key = match sparse_layout {
            None => BlindRotationKey::Classic(NttGlweBootstrappingKey::generate_ntt(
                client_key.small_lwe_secret_key(),
                parameters.small_lwe(),
                &main_glwe_secret_key,
                parameters.blind_rotation_ggsw(),
                self.context.table(),
                rng,
                &mut self.gadget,
            )),
            Some(layout) => {
                BlindRotationKey::Sparse(self.generate_sparse_bootstrapping_key_with_main(
                    client_key,
                    layout,
                    &main_glwe_secret_key,
                    rng,
                )?)
            }
        };
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
        Ok(ServerKey {
            circuit_bootstrap,
            blind_rotation_key,
            glwe_key_switching_key,
        })
    }

    /// Generates after the setup bundle has passed compatibility checks.
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

    /// Generates a fresh classic or sparse pair with the selected evaluation capabilities.
    /// Reuses the sampled secrets and their accumulator transform for BR and optional CBS.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    ///
    /// CBS and sparse configuration errors are returned before sampling any keys.
    /// Sparse matching happens afterward and can fail without returning a partial pair.
    pub fn try_generate<R>(
        &mut self,
        blind_rotation: BlindRotationConfig,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let circuit_parameters = self.prepare_circuit_bootstrap(circuit_bootstrap)?;
        let sparse_layout = match blind_rotation {
            BlindRotationConfig::Classic => None,
            BlindRotationConfig::Sparse {
                copy_count,
                bucket_count,
            } => Some(self.prepare_sparse_layout(copy_count, bucket_count)?),
        };
        let client_key = ClientKey::generate(self.context.parameters(), rng);
        let transformed = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        let server_key = self.generate_server_key_with_main(
            &client_key,
            transformed,
            sparse_layout,
            circuit_parameters,
            rng,
        )?;
        Ok((client_key, server_key))
    }

    /// Prepares optional CBS bases before any secret or evaluation-key sampling.
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates a fresh classic or sparse client/server pair; `None` selects PBS only and
    /// `Some(config)` also generates the configured CBS material.
    /// Inherits [`KeyGenerator::try_generate`]'s configuration and CBS requirements.
    ///
    /// Distribution and fixed-weight validity is established by parameter construction.
    pub fn try_generate_keys<R>(
        &self,
        blind_rotation: BlindRotationConfig,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate(blind_rotation, circuit_bootstrap, rng)
    }
}
