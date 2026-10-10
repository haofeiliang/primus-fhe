//! Server evaluation material and paired or component key generation.

mod circuit;
pub use circuit::CircuitBootstrapServerKey;

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweGadgetEncryptWorkspace, FourierGlweKeySwitchingKey, FourierGlweSecretKey,
    SecretKeyDistr,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    BlindRotationMethod, GlweKeySwitchingParameters, KeyGenerationError, PbsParameters,
    TfheContext, bootstrapping_key::FourierGlweBootstrappingKey,
    sparse::SparseGlweBootstrappingKey,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store Fourier GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BlindRotationKey<T: TorusFftValue> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(FourierGlweBootstrappingKey<T, NativeModulus<T>>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T, NativeModulus<T>>),
}

impl<T: TorusFftValue> BlindRotationKey<T> {
    /// Validate the selected BR layout and input domain, independently of ring KS/CBS.
    pub(crate) fn is_compatible(&self, parameters: &PbsParameters<T>) -> bool {
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
            && size == parameters.blind_rotation_params().size()
            && basis == parameters.blind_rotation_params().basis()
    }
}

/// Classic or sparse evaluation keys used by a Fourier TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: TorusFftValue> {
    blind_rotation_key: BlindRotationKey<T>,
    glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Moves BR and KS material into one bundle without copying buffers.
    /// Evaluator binding checks layouts; actual secret and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation_key: BlindRotationKey<T>,
        glwe_key_switching_key: FourierGlweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            blind_rotation_key,
            glwe_key_switching_key,
        }
    }

    /// Borrows the selected classic or sparse blind-rotation material.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation_key
    }

    /// Borrows the required ring key-switching key.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &FourierGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Moves out BR and KS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, FourierGlweKeySwitchingKey<T>) {
        (self.blind_rotation_key, self.glwe_key_switching_key)
    }
}

/// Checks the ring KS layout and basis once, before allocating evaluation scratch.
/// Fourier uses `NativeModulus<T>` throughout this backend.
pub(crate) fn check_glwe_key_switching_key<T: TorusFftValue>(
    parameters: &PbsParameters<T>,
    expected: &GlweKeySwitchingParameters<T>,
    key: &FourierGlweKeySwitchingKey<T>,
) -> Result<(), crate::TfheEvaluationError> {
    parameters
        .check_key_switching_parameters(expected)
        .map_err(|_| crate::TfheEvaluationError::IncompatibleGlweKeySwitchingKey)?;
    check_bound_glwe_key_switching_key(expected, key)
}

/// Checks imported KS rows against parameters already paired with their BR domain.
/// Context setup and evaluator rebinding retain that pairing independently of the key.
pub(crate) fn check_bound_glwe_key_switching_key<T: TorusFftValue>(
    expected: &GlweKeySwitchingParameters<T>,
    key: &FourierGlweKeySwitchingKey<T>,
) -> Result<(), crate::TfheEvaluationError> {
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
        let blind_rotation_ggsw = context.parameters().blind_rotation_params();
        Self {
            context,
            fft: context.new_fft_engine(),
            gadget: FourierGlweGadgetEncryptWorkspace::new(blind_rotation_ggsw.size()),
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
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match blind_rotation {
            BlindRotationMethod::Classic => self
                .try_generate_classic_blind_rotation_key(client_key, rng)
                .map(BlindRotationKey::Classic),
            BlindRotationMethod::Sparse {
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
        self.gadget
            .resize(parameters.blind_rotation_params().size());
        Ok(FourierGlweBootstrappingKey::generate_fourier(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main,
            parameters.blind_rotation_params(),
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
        key_switching: &GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<FourierGlweKeySwitchingKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.context
            .parameters()
            .check_key_switching_parameters(key_switching)?;
        client_key.check_compatible(self.context.parameters())?;
        Ok(self.generate_glwe_key_switching_key(key_switching, client_key, rng))
    }

    /// Generates configured BR and KS material for an existing client.
    /// Checks the imported secrets before conversion or sampling; retains its input distribution.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_blind_rotation_key`]'s secret and transform contracts.
    /// BR and KS errors must fit the complete PBS noise budget.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let context = self.context;
        let parameters = context.parameters();
        self.generate_for_client(
            parameters.glwe_key_switching(),
            client_key,
            context.parameters().blind_rotation_method(),
            rng,
        )
    }

    /// Validates imported secrets and prepares sparse matching before transforming
    /// one accepted accumulator representation for BR generation.
    // Inlining this setup boundary avoids a measured Fourier server-keygen regression;
    // the large material-generation kernel remains shared by the entry points.
    #[inline(always)]
    fn generate_for_client<R>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        client_key.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let transformed = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        self.generate_server_key_with_main(
            key_switching,
            client_key,
            transformed,
            sparse_layout,
            rng,
        )
    }

    /// Encrypts selected BR controls after key compatibility and layout preparation.
    /// The borrowed accumulator representation can also be reused by paired CBS generation.
    fn generate_blind_rotation_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: &FourierGlweSecretKey,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let blind_rotation_ggsw = parameters.blind_rotation_params();
        self.gadget.resize(blind_rotation_ggsw.size());
        Ok(match sparse_layout {
            None => BlindRotationKey::Classic(FourierGlweBootstrappingKey::generate_fourier(
                client_key.small_lwe_secret_key(),
                parameters.small_lwe(),
                main_glwe_secret_key,
                blind_rotation_ggsw,
                &mut self.fft,
                rng,
                &mut self.gadget,
            )),
            Some(layout) => BlindRotationKey::Sparse({
                let prepared = self.prepare_sparse_map(client_key, layout, rng)?;
                self.generate_sparse_bootstrapping_key_with_main(
                    prepared,
                    main_glwe_secret_key,
                    rng,
                )
            }),
        })
    }

    /// Consumes the accepted accumulator transform for BR, then releases it before
    /// allocating KS rows. The caller established client compatibility by sampling or
    /// validation and prepared this transform with the context's table.
    fn generate_server_key_with_main<R>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: FourierGlweSecretKey,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let blind_rotation_key = self.generate_blind_rotation_key_with_main(
            client_key,
            &main_glwe_secret_key,
            sparse_layout,
            rng,
        )?;
        drop(main_glwe_secret_key);
        let glwe_key_switching_key =
            self.generate_glwe_key_switching_key(key_switching, client_key, rng);
        Ok(ServerKey {
            blind_rotation_key,
            glwe_key_switching_key,
        })
    }

    /// Generates after the setup bundle has passed compatibility checks.
    fn generate_glwe_key_switching_key<R>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
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
        let key_switching = key_switching.output();
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

    /// Generates the configured BR and KS pair.
    /// Reuses the prepared KS state and retries only sparse public maps.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key`]'s noise and representation contracts.
    pub fn try_generate<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let context = self.context;
        let parameters = context.parameters();
        self.generate_pair(
            parameters.glwe_key_switching(),
            context.parameters().blind_rotation_method(),
            rng,
        )
    }

    /// Samples secrets after the owning boundary paired BR and KS parameters.
    /// Sparse preflight happens before sampling; BR consumes the accepted ring transform.
    fn generate_pair<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &GlweKeySwitchingParameters<T>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let client_key = ClientKey::generate(self.context.parameters(), rng);
        let transformed = FourierGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            &mut self.fft,
        );
        let server_key = self.generate_server_key_with_main(
            key_switching,
            &client_key,
            transformed,
            sparse_layout,
            rng,
        )?;
        Ok((client_key, server_key))
    }

    /// Prepares the selected BR layout before sampling: `None` denotes classic.
    fn prepare_blind_rotation(
        &self,
        blind_rotation: BlindRotationMethod,
    ) -> Result<Option<crate::sparse::SparseKeyLayout>, KeyGenerationError> {
        Ok(match blind_rotation {
            BlindRotationMethod::Classic => None,
            BlindRotationMethod::Sparse {
                copy_count,
                bucket_count,
            } => Some(self.prepare_sparse_layout(copy_count, bucket_count)?),
        })
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates paired client and BR/KS server keys using this context's choices.
    /// Inherits [`KeyGenerator::try_generate`]'s contracts.
    pub fn try_generate_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate(rng)
    }

    /// Generates configured server material for independently generated client secrets.
    /// Inherits [`KeyGenerator::try_generate_server_key`]'s contracts.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_server_key(client_key, rng)
    }
}
