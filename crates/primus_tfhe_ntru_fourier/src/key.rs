//! Server evaluation material and paired or component key generation.

mod circuit;
pub use circuit::CircuitBootstrapServerKey;

mod blind_rotation;
mod classic;
pub use blind_rotation::BlindRotationKey;
pub(crate) use blind_rotation::BootstrappingControls;
use blind_rotation::Controls;
pub use classic::ClassicControls;

use num_traits::{ConstOne, ConstZero};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::nlev::FourierNlev;
use primus_ntru::{
    FourierNtruGadgetEncryptWorkspace, FourierNtruSecretKey, NtruLweKeySwitchingKey,
};
use zeroize::Zeroizing;

use crate::{BlindRotationMethod, ClientKey, KeyGenerationError, TfheContext};

/// Owning PBS bundle: blind rotation and required LWE return material.
/// Components can be generated independently and moved in or out without copying
/// ciphertext buffers. Evaluator binding validates the required components only.
pub struct ServerKey<T: TorusFftValue> {
    blind_rotation: BlindRotationKey<T>,
    key_switching_key: NtruLweKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Moves BR and KS material into one bundle without copying buffers.
    /// Evaluator binding checks layouts; actual secret and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation: BlindRotationKey<T>,
        key_switching_key: NtruLweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            blind_rotation,
            key_switching_key,
        }
    }

    /// Borrows the selected classic or sparse blind-rotation material.
    #[must_use]
    #[inline]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation
    }

    /// Borrows the required Q→q, f→s return key.
    #[must_use]
    #[inline]
    pub fn key_switching_key(&self) -> &NtruLweKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Moves out BR and KS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, NtruLweKeySwitchingKey<T>) {
        (self.blind_rotation, self.key_switching_key)
    }
}

/// Generates coefficient and Fourier keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) context: &'a TfheContext<T, Table, LM>,
    pub(crate) fft: FftEngine<'a, Table>,
    pub(crate) gadget: FourierNtruGadgetEncryptWorkspace<T>,
}

impl<'a, T, Table, LM> KeyGenerator<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates a key generator with reusable FFT and encryption workspaces.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table, LM>) -> Self {
        Self {
            fft: context.new_fft_engine(),
            gadget: FourierNtruGadgetEncryptWorkspace::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates coefficient-domain client and accumulator secrets accepted by this backend.
    ///
    /// Only the accumulator undergoes native-ring invertibility and Fourier stability rejection.
    /// Return-key magnitude bounds are checked only when generating return material.
    /// The transformed secrets are discarded; use [`Self::try_generate`] when
    /// generating a paired server key so those representations can be reused.
    /// Returns a key-generation error when the bounded search is exhausted.
    ///
    /// Distribution and fixed-weight validity is established by parameter construction.
    pub fn try_generate_client_key<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<ClientKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.generate_client_key_with_main(rng)
            .map(|(client, _)| client)
    }

    /// Samples the external secret once, retaining the accepted ring transform and inverse.
    /// Standalone clients discard that temporary; paired setup consumes it without reconversion.
    fn generate_client_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, FourierNtruSecretKey), KeyGenerationError> {
        let parameters = self.context.parameters();
        let client = primus_lwe::LweSecretKey::generate(parameters.external_lwe(), rng);
        let (accumulator, transformed) = FourierNtruSecretKey::generate_padded_pair(
            parameters.accumulator_ntru(),
            parameters.poly_length().get(),
            &mut self.fft,
            rng,
        )?;
        let client_key = ClientKey::new(client, accumulator);
        // Sampling proves the usual q bound. For unusually small q, check the
        // accepted sample rather than rejecting every key from this distribution.
        if parameters
            .accumulator_ntru()
            .secret_key_sampler()
            .maximum_magnitude()
            > parameters.external_lwe().cipher_modulus_minus_one()
        {
            client_key
                .check_accumulator_return_modulus(parameters.external_lwe().cipher_modulus())?;
        }
        Ok((client_key, transformed))
    }

    /// Generates BR and required NTRU-to-LWE return KS material for an existing client.
    /// `blind_rotation` selects the algorithm independently of the client's distribution.
    /// Checks imported secrets and the independently supplied KS domain before sampling.
    /// Sparse generation retries only the public map (at most eight attempts), never
    /// resamples the client secret or falls back to classic, and returns no partial key.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_classic_blind_rotation_key`] and
    /// [`Self::try_generate_sparse_blind_rotation_key`]'s secret and transform
    /// requirements for the selected algorithm. Budget Q-to-q modulus-switch and return-KS noise separately from BR noise.
    pub fn try_generate_server_key_with_parameters<R>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client_key: &ClientKey<T>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.context
            .parameters()
            .check_lwe_return_parameters(key_switching)?;
        self.generate_for_client(key_switching, client_key, blind_rotation, rng)
    }

    /// Generates configured BR and KS material for an existing client.
    /// Checks the imported secrets before conversion or sampling; retains its input distribution.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key_with_parameters`]'s noise and transform contracts.
    pub fn try_generate_server_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        let context = self.context;
        let parameters = context.parameters();
        self.generate_for_client(
            parameters.key_switching(),
            client_key,
            context.parameters().algorithm(),
            rng,
        )
    }

    /// Validates imported secrets and prepares sparse matching before transforming
    /// one accepted accumulator representation for BR generation.
    fn generate_for_client<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client_key: &ClientKey<T>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        client_key.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;
        self.generate_server_key_from_transformed(
            key_switching,
            client_key,
            transformed,
            sparse_layout,
            rng,
        )
    }

    /// Encrypts selected BR controls after key compatibility and layout preparation.
    /// The borrowed accumulator representation can also be reused by paired CBS generation.
    fn generate_blind_rotation_key_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_fourier: &FourierNtruSecretKey,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        Ok(match sparse_layout {
            None => self.generate_classic_blind_rotation_key_from_transformed(
                client_key,
                accumulator_fourier,
                rng,
            ),
            Some(layout) => self.generate_sparse_blind_rotation_key_with_main(
                client_key,
                accumulator_fourier,
                layout,
                rng,
            )?,
        })
    }

    /// Consumes the accepted accumulator transform for BR, then releases it before
    /// allocating return-KS rows. Sampling or validation established client
    /// compatibility and the external-q secret-magnitude bound.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client_key: &ClientKey<T>,
        accumulator_fourier: FourierNtruSecretKey,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let blind_rotation = self.generate_blind_rotation_key_with_main(
            client_key,
            &accumulator_fourier,
            sparse_layout,
            rng,
        )?;
        drop(accumulator_fourier);
        let key_switching_key = NtruLweKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            client_key.external_lwe_secret_key(),
            key_switching.lwe(),
            key_switching.basis().clone(),
            rng,
        );
        Ok(ServerKey::new(blind_rotation, key_switching_key))
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
            BlindRotationMethod::Classic => {
                self.try_generate_classic_blind_rotation_key(client_key, rng)
            }
            BlindRotationMethod::Sparse {
                copy_count,
                bucket_count,
            } => self.try_generate_sparse_blind_rotation_key(
                client_key,
                copy_count,
                bucket_count,
                rng,
            ),
        }
    }

    /// Generates classic BR material without constructing a return or CBS key.
    /// Checks both secret roles but does not require f to fit external q.
    ///
    /// # Correctness
    /// The accumulator inherits [`FourierNtruSecretKey::try_from_coeff_secret_key`]'s representation
    /// and magnitude requirements. Independently generated components must share
    /// the same actual secrets and transform representation.
    ///
    /// # Errors
    /// Rejects incompatible secrets and propagates backend conversion failures.
    pub fn try_generate_classic_blind_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        client_key.check_blind_rotation_compatible(self.context.parameters())?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;
        Ok(
            self.generate_classic_blind_rotation_key_from_transformed(
                client_key,
                &transformed,
                rng,
            ),
        )
    }

    /// Generates independent `NLEV_f[1]` for public polynomial lifting.
    /// Call only when the compiled lookup table needs a public lift. The supplied
    /// parameters select this material's own decomposition basis and row noise;
    /// no BR, CBS or return material is generated or modified.
    ///
    /// # Errors
    /// Rejects another accumulator ring or an incompatible secret before sampling,
    /// and propagates secret conversion failures.
    ///
    /// # Correctness
    /// The secret must be the actual accumulator secret used by the other keys.
    /// Inherits [`FourierNtruSecretKey::try_from_coeff_secret_key`]'s numerical
    /// requirements. Budget decomposition and encryption error for the public
    /// polynomial products; compatible parameters do not prove a decoding margin.
    pub fn try_generate_public_lift_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::NativeModulus<T>>,
        rng: &mut R,
    ) -> Result<FourierNlev<Vec<Complex64>>, KeyGenerationError> {
        self.check_public_lift_parameters(parameters)?;
        self.context
            .parameters()
            .check_accumulator_secret_key(secret)?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut self.fft)?;
        Ok(self.generate_public_lift_from_transformed(&transformed, parameters, rng))
    }

    /// Reuses the checked accumulator transform in paired generation.
    fn generate_classic_blind_rotation_key_from_transformed<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        transformed: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> BlindRotationKey<T> {
        let initializer = self.generate_public_lift_from_transformed(
            transformed,
            self.context.parameters().blind_rotation(),
            rng,
        );
        let data = self.generate_controls(client_key, transformed, rng);
        BlindRotationKey {
            blind_rotation_basis: self.context.parameters().blind_rotation().basis().clone(),
            input_distribution: self.context.parameters().external_lwe().secret_key_distr(),
            controls: Controls::Classic { initializer, data },
        }
    }

    /// Validates independently supplied lift metadata before sampling any key rows.
    pub(crate) fn check_public_lift_parameters(
        &self,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::NativeModulus<T>>,
    ) -> Result<(), KeyGenerationError> {
        if parameters.poly_length() != self.context.parameters().poly_length() {
            return Err(KeyGenerationError::IncompatiblePublicLiftParameters);
        }
        Ok(())
    }

    /// Shares direct encryption of one with classic initialization, reusing its transform.
    pub(crate) fn generate_public_lift_from_transformed<R>(
        &mut self,
        accumulator_fourier: &FourierNtruSecretKey,
        parameters: &primus_ntru::NlevParameters<T, primus_modulus::NativeModulus<T>>,
        rng: &mut R,
    ) -> FourierNlev<Vec<Complex64>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let mut initializer = FourierNlev::zero(parameters.fourier_nlev_len());
        accumulator_fourier.encrypt_nlev_constant_to(
            T::ONE,
            &mut initializer,
            parameters,
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        initializer
    }

    /// Encrypts the first binary bit or ternary pair as NLEV; later bits as NGSW.
    fn generate_controls<R>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_fourier: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> Vec<Complex64>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let nlev_len = parameters.blind_rotation().fourier_nlev_len();
        let coefficients = client_key.external_lwe_secret_key().as_ref();
        let binary = parameters.external_lwe().secret_key_distr().is_binary();
        let count = coefficients
            .len()
            .checked_mul(if binary { 1 } else { 2 })
            .expect("blind-rotation control count overflow");
        // Controls are signed bit plaintexts, whereas the LWE secret uses residues at q.
        let mut selectors = Zeroizing::new(vec![T::SignedInteger::ZERO; count]);
        if binary {
            for (&coefficient, bit) in coefficients.iter().zip(selectors.iter_mut()) {
                *bit = if coefficient == T::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
            }
        } else {
            let minus_one = parameters.external_lwe().cipher_modulus_minus_one();
            for (&coefficient, pair) in coefficients.iter().zip(selectors.as_chunks_mut::<2>().0) {
                pair[0] = if coefficient == T::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                pair[1] = if coefficient == minus_one {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
            }
        }
        let plaintexts = selectors.as_slice();
        let total_len = plaintexts
            .len()
            .checked_mul(nlev_len)
            .expect("blind-rotation control batch length overflow");
        let mut controls = vec![Complex64::default(); total_len];
        let first_count = if parameters.external_lwe().secret_key_distr().is_binary() {
            1
        } else {
            2
        };
        let (first, remaining) = controls.split_at_mut(first_count * nlev_len);
        for (&bit, output) in plaintexts[..first_count]
            .iter()
            .zip(first.chunks_exact_mut(nlev_len))
        {
            accumulator_fourier.encrypt_nlev_constant_to(
                if bit == T::SignedInteger::ONE {
                    T::ONE
                } else {
                    T::ZERO
                },
                &mut FourierNlev::new(output),
                parameters.blind_rotation(),
                &mut self.fft,
                rng,
                &mut self.gadget,
            );
        }
        accumulator_fourier.encrypt_ngsw_signed_constant_batch_to(
            &plaintexts[first_count..],
            remaining,
            parameters.blind_rotation(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        controls
    }

    /// Generates a fresh classic or sparse pair with BR and required NTRU-to-LWE return KS.
    /// Checks the independently supplied KS domain and sparse choices before sampling.
    /// Sparse matching retries only the public map and returns no partial pair.
    /// Propagates bounded NTRU rejection/conversion failures; the accepted secret
    /// must also have coefficient magnitudes below an explicit return modulus q.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_server_key_with_parameters`]'s numerical contracts.
    pub fn try_generate_with_parameters<R>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.context
            .parameters()
            .check_lwe_return_parameters(key_switching)?;
        self.generate_pair(key_switching, blind_rotation, rng)
    }

    /// Generates the configured BR and KS pair.
    /// Reuses the prepared KS state and retries only sparse public maps.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate_with_parameters`]'s noise and representation contracts.
    pub fn try_generate<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        let context = self.context;
        let parameters = context.parameters();
        self.generate_pair(
            parameters.key_switching(),
            context.parameters().algorithm(),
            rng,
        )
    }

    /// Samples secrets after the owning boundary paired BR and KS parameters.
    /// Sparse preflight happens before sampling; BR consumes the accepted ring transform.
    fn generate_pair<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError> {
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let (client_key, transformed) = self.generate_client_key_with_main(rng)?;
        let server_key = self.generate_server_key_from_transformed(
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

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
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

    /// Generates a fresh BR/KS pair with independently supplied KS and BR choices.
    /// Inherits [`KeyGenerator::try_generate_with_parameters`]'s contracts.
    pub fn try_generate_keys_with_parameters<R>(
        &self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: BlindRotationMethod,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate_with_parameters(key_switching, blind_rotation, rng)
    }
}
