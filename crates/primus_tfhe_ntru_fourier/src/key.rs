//! Server evaluation material and paired or component key generation.

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

use crate::{
    CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters, ClientKey,
    KeyGenerationError, TfheContext,
};

/// Owning PBS bundle: blind rotation, LWE return, and optional CBS material.
/// Components can be generated independently and moved in or out without copying
/// ciphertext buffers. Evaluator binding validates the required components only.
pub struct ServerKey<T: TorusFftValue> {
    blind_rotation: BlindRotationKey<T>,
    key_switching_key: NtruLweKeySwitchingKey<T>,
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Combines independently owned components without copying or checking them.
    /// Bind an evaluator to check layouts/moduli; shared secret and transform
    /// identity remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation: BlindRotationKey<T>,
        key_switching_key: NtruLweKeySwitchingKey<T>,
        circuit_bootstrap: Option<CircuitBootstrapKey<T>>,
    ) -> Self {
        Self {
            blind_rotation,
            key_switching_key,
            circuit_bootstrap: circuit_bootstrap.map(Box::new),
        }
    }

    /// Borrows the independently owned blind-rotation material.
    #[must_use]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation
    }

    /// Borrows the Q→q, f→s return key.
    #[must_use]
    pub fn key_switching_key(&self) -> &NtruLweKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Borrows the optional trace and scheme-switch material.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> Option<&CircuitBootstrapKey<T>> {
        self.circuit_bootstrap.as_deref()
    }

    /// Moves out BR, return and optional CBS material without copying buffers.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlindRotationKey<T>,
        NtruLweKeySwitchingKey<T>,
        Option<CircuitBootstrapKey<T>>,
    ) {
        (
            self.blind_rotation,
            self.key_switching_key,
            self.circuit_bootstrap.map(|key| *key),
        )
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
        let parameters = self.context.parameters();
        let client = primus_lwe::LweSecretKey::generate(parameters.external_lwe(), rng);
        let (accumulator, _) =
            FourierNtruSecretKey::generate_pair(parameters.accumulator_ntru(), &mut self.fft, rng)?;
        let client_key = ClientKey::new(client, accumulator);
        client_key.check_blind_rotation_compatible(parameters)?;
        Ok(client_key)
    }

    /// Generates the selected capabilities from one compatible client key.
    /// Invalid CBS configuration is rejected before sampling evaluation material.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    /// Returns an error for incompatible parameters, a noninvertible secret,
    /// or an unstable Fourier inverse.
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
        let accumulator_fourier = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;

        Ok(self.generate_server_key_from_transformed(
            client_key,
            &accumulator_fourier,
            circuit_parameters,
            rng,
        ))
    }

    /// Generates evaluation material from already converted NTRU keys.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_fourier: &FourierNtruSecretKey,
        circuit_parameters: Option<CircuitBootstrapParameters<T>>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let blind_rotation =
            self.generate_blind_rotation_key_from_transformed(client_key, accumulator_fourier, rng);
        let key_switching_key = NtruLweKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            client_key.external_lwe_secret_key(),
            parameters.key_switching_lwe(),
            parameters.key_switching_basis().clone(),
            rng,
        );
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            self.generate_circuit_bootstrap_key_with_main(
                client_key.accumulator_ntru_secret_key(),
                accumulator_fourier,
                parameters,
                rng,
            )
        });
        ServerKey::new(blind_rotation, key_switching_key, circuit_bootstrap)
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
    pub fn try_generate_blind_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<BlindRotationKey<T>, KeyGenerationError> {
        client_key.check_blind_rotation_compatible(self.context.parameters())?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;
        Ok(self.generate_blind_rotation_key_from_transformed(client_key, &transformed, rng))
    }

    /// Reuses the checked accumulator transform in paired generation.
    fn generate_blind_rotation_key_from_transformed<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client_key: &ClientKey<T>,
        transformed: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> BlindRotationKey<T> {
        let initializer = self.generate_initializer(transformed, rng);
        let data = self.generate_controls(client_key, transformed, rng);
        BlindRotationKey {
            blind_rotation_basis: self.context.parameters().blind_rotation().basis().clone(),
            input_distribution: self.context.parameters().external_lwe().secret_key_distr(),
            controls: Controls::Classic { initializer, data },
        }
    }

    /// Generates `NLEV_f_acc[1]` directly for accumulator initialization.
    fn generate_initializer<R>(
        &mut self,
        accumulator_fourier: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> FourierNlev<Vec<Complex64>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let mut initializer = FourierNlev::zero(parameters.blind_rotation().fourier_nlev_len());
        accumulator_fourier.encrypt_nlev_constant_to(
            T::ONE,
            &mut initializer,
            parameters.blind_rotation(),
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

    /// Generates a fresh pair with the selected capabilities, reusing transformed secrets.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    /// Returns a key-generation error when the bounded rejection search is exhausted.
    ///
    /// Distribution and fixed-weight validity is established by parameter construction.
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
        let client = primus_lwe::LweSecretKey::generate(parameters.external_lwe(), rng);
        let (accumulator, accumulator_fourier) =
            FourierNtruSecretKey::generate_pair(parameters.accumulator_ntru(), &mut self.fft, rng)?;
        let client_key = ClientKey::new(client, accumulator);
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_from_transformed(
            &client_key,
            &accumulator_fourier,
            circuit_parameters,
            rng,
        );
        Ok((client_key, server_key))
    }

    pub(crate) fn prepare_circuit_bootstrap(
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

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates a fresh client/server pair; `None` selects PBS only and
    /// `Some(config)` also generates the configured CBS material.
    /// Inherits [`KeyGenerator::try_generate`]'s rejection-sampling errors and CBS requirements.
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
