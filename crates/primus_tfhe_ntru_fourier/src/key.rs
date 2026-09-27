//! Server evaluation material and paired or component key generation.

use num_traits::{ConstOne, ConstZero};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::nlev::FourierNlev;
use primus_ntru::SecretKeyDistr;
use primus_ntru::{FourierNtruGadgetEncryptContext, FourierNtruSecretKey, NtruLweKeySwitchingKey};
use zeroize::Zeroizing;

use crate::{
    CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters, ClientKey,
    KeyGenerationError, TfheContext, TfheParameters,
};

/// Fourier evaluation keys for NTRU TFHE.
/// The classic initializer and controls share the stored blind-rotation basis.
/// Classic coordinate zero holds NLEV bit controls for fused lifting; later
/// coordinates hold NGSW controls (positive/negative pairs for ternary).
/// Sparse keys instead lift with their first bucket and carry no initializer.
pub struct ServerKey<T: TorusFftValue> {
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
    blind_rotation_basis: ApproxSignedBasis<T>,
    controls: Controls<T>,
    input_distribution: SecretKeyDistr,
    key_switching_key: NtruLweKeySwitchingKey<T>,
}

enum Controls<T: TorusFftValue> {
    // First coordinate: NLEV bit(s); remaining coordinates: NGSW bit(s).
    Classic {
        initializer: FourierNlev<Vec<Complex64>>,
        data: Vec<Complex64>,
    },
    Sparse(crate::SparseNtruBootstrappingKey<T>),
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Returns coefficient-domain bucket selections when this is a sparse server key.
    #[must_use]
    pub fn sparse_bootstrapping_key(&self) -> Option<&crate::SparseNtruBootstrappingKey<T>> {
        match &self.controls {
            Controls::Classic { .. } => None,
            Controls::Sparse(key) => Some(key),
        }
    }

    /// Borrows first-coordinate NLEV bits and the remaining NGSW bits.
    pub(crate) fn classic_controls(&self) -> (&[Complex64], &[Complex64]) {
        match &self.controls {
            Controls::Classic { initializer, data } => {
                let first_len = initializer.as_ref().len()
                    * if self.input_distribution.is_binary() {
                        1
                    } else {
                        2
                    };
                data.split_at(first_len)
            }
            Controls::Sparse(_) => panic!("classic control iterator requires a classic key"),
        }
    }

    pub(crate) fn from_sparse<LM: primus_reduce::RingContext<T>>(
        parameters: &TfheParameters<T, LM>,
        controls: crate::SparseNtruBootstrappingKey<T>,
        key_switching_key: NtruLweKeySwitchingKey<T>,
    ) -> Self {
        Self {
            circuit_bootstrap: None,
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls: Controls::Sparse(controls),
            input_distribution: parameters.external_lwe().secret_key_distr(),
            key_switching_key,
        }
    }

    /// Returns the declared client secret distribution.
    #[must_use]
    pub fn input_distribution(&self) -> SecretKeyDistr {
        self.input_distribution
    }

    /// Returns the bound CBS parameters and keys, if requested during generation.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> Option<&CircuitBootstrapKey<T>> {
        self.circuit_bootstrap.as_deref()
    }

    /// Returns the classic Fourier NLEV encryption of one; panics for sparse keys.
    #[inline]
    pub(crate) fn initializer(&self) -> &FourierNlev<Vec<Complex64>> {
        match &self.controls {
            Controls::Classic { initializer, .. } => initializer,
            Controls::Sparse(_) => panic!("classic initializer requires a classic key"),
        }
    }

    /// Returns the common initializer/control decomposition basis.
    pub(crate) fn blind_rotation_basis(&self) -> &ApproxSignedBasis<T> {
        &self.blind_rotation_basis
    }

    /// Returns the post-bootstrap `f -> s` key-switching key.
    #[inline]
    pub(crate) fn key_switching_key(&self) -> &NtruLweKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Checks the generated ring and decomposition parameters before evaluation.
    pub(crate) fn is_compatible<LM: primus_reduce::RingContext<T>>(
        &self,
        parameters: &TfheParameters<T, LM>,
    ) -> bool {
        self.input_distribution == parameters.external_lwe().secret_key_distr()
            && &self.blind_rotation_basis == parameters.blind_rotation().basis()
            && self.key_switching_key.poly_length() == parameters.poly_length()
            && self.key_switching_key.input_modulus()
                == parameters.accumulator_ntru().cipher_modulus_value()
            && self.key_switching_key.output_dimension() == parameters.external_lwe_dimension()
            && self.key_switching_key.basis() == parameters.key_switching_basis()
            && match &self.controls {
                Controls::Classic { initializer, data } => {
                    initializer.as_ref().len() == parameters.blind_rotation().fourier_nlev_len()
                        && data.len()
                            == parameters.external_lwe_dimension()
                                * if self.input_distribution.is_binary() {
                                    1
                                } else {
                                    2
                                }
                                * initializer.as_ref().len()
                }
                Controls::Sparse(key) => {
                    key.input_dimension() == parameters.external_lwe_dimension()
                        && key.control_len == parameters.blind_rotation().nlev_len()
                }
            }
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
    pub(crate) gadget: FourierNtruGadgetEncryptContext<T>,
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
            gadget: FourierNtruGadgetEncryptContext::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates coefficient-domain client and accumulator secrets accepted by this backend.
    ///
    /// Only the accumulator undergoes native-ring invertibility and Fourier stability rejection.
    /// The transformed secrets are discarded; use [`Self::try_generate`] when
    /// generating a paired server key so those representations can be reused.
    /// Returns a key-generation error when the bounded search is exhausted.
    ///
    /// # Panics
    ///
    /// Inherits [`primus_lwe::LweSecretKey::generate`] and
    /// [`FourierNtruSecretKey::generate_pair`]'s sampling requirements. Fixed weights
    /// must fit the external LWE dimension or accumulator polynomial length.
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
        client_key.check_compatible(parameters)?;
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
        let initializer = self.generate_initializer(accumulator_fourier, rng);
        let controls = self.generate_controls(client_key, accumulator_fourier, rng);
        let key_switching_key = NtruLweKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            client_key.external_lwe_secret_key(),
            parameters.key_switching_lwe(),
            parameters.key_switching_basis().clone(),
            rng,
        );
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            Box::new(self.generate_circuit_bootstrap_key_with_main(
                client_key,
                accumulator_fourier,
                parameters,
                rng,
            ))
        });
        ServerKey {
            circuit_bootstrap,
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls: Controls::Classic {
                initializer,
                data: controls,
            },
            input_distribution: parameters.external_lwe().secret_key_distr(),
            key_switching_key,
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
    /// # Panics
    ///
    /// Inherits [`primus_lwe::LweSecretKey::generate`] and
    /// [`FourierNtruSecretKey::generate_pair`]'s sampling requirements. Fixed weights
    /// must fit the external LWE dimension or accumulator polynomial length.
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
