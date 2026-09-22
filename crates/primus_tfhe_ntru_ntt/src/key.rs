//! Server evaluation material and paired or component key generation.

use num_traits::{ConstOne, ConstZero};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::SecretKeyDistr;
use primus_ntru::{NttNtruGadgetEncryptContext, NttNtruKeySwitchingKey, NttNtruSecretKey};
use primus_ntt::MonomialNttTable;
use zeroize::Zeroizing;

use crate::{
    CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters, ClientKey,
    KeyGenerationError, TfheContext, TfheParameters,
};

/// Exact NTT evaluation keys for NTRU TFHE.
/// The initializer and controls share the stored blind-rotation basis.
pub struct ServerKey<T: FheUint> {
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
    initializer: NttNlev<Vec<T>>,
    blind_rotation_basis: ApproxSignedBasis<T>,
    controls: Controls<T>,
    input_distribution: SecretKeyDistr,
    key_switching_key: NttNtruKeySwitchingKey<T>,
}

enum Controls<T: FheUint> {
    Classic(Vec<T>),
    Sparse(crate::SparseNtruBootstrappingKey<T>),
}

impl<T: FheUint> ServerKey<T> {
    /// Returns coefficient-domain bucket selections when this is a sparse server key.
    #[must_use]
    pub fn sparse_bootstrapping_key(&self) -> Option<&crate::SparseNtruBootstrappingKey<T>> {
        match &self.controls {
            Controls::Classic(_) => None,
            Controls::Sparse(key) => Some(key),
        }
    }

    pub(crate) fn classic_controls(&self) -> &[T] {
        match &self.controls {
            Controls::Classic(data) => data,
            Controls::Sparse(_) => panic!("classic control iterator requires a classic key"),
        }
    }

    pub(crate) fn from_sparse(
        parameters: &TfheParameters<T>,
        initializer: NttNlev<Vec<T>>,
        controls: crate::SparseNtruBootstrappingKey<T>,
        key_switching_key: NttNtruKeySwitchingKey<T>,
    ) -> Self {
        Self {
            circuit_bootstrap: None,
            initializer,
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

    /// Returns the NLev encryption of one used to initialize the accumulator.
    #[inline]
    pub(crate) fn initializer(&self) -> &NttNlev<Vec<T>> {
        &self.initializer
    }

    /// Returns the common initializer/control decomposition basis.
    pub(crate) fn blind_rotation_basis(&self) -> &ApproxSignedBasis<T> {
        &self.blind_rotation_basis
    }

    /// Returns the post-bootstrap `f_acc -> f_client` key-switching key.
    #[inline]
    pub(crate) fn key_switching_key(&self) -> &NttNtruKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Checks the generated ring and decomposition parameters before evaluation.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        self.input_distribution == parameters.external_lwe().secret_key_distr()
            && self.initializer.as_ref().len() == parameters.blind_rotation().nlev_len()
            && &self.blind_rotation_basis == parameters.blind_rotation().basis()
            && self.key_switching_key.poly_length() == parameters.poly_length()
            && self.key_switching_key.basis() == parameters.ntru_key_switching().basis()
            && match &self.controls {
                Controls::Classic(data) => {
                    data.len()
                        == parameters.external_lwe_dimension()
                            * if self.input_distribution.is_binary() {
                                1
                            } else {
                                2
                            }
                            * self.initializer.as_ref().len()
                }
                Controls::Sparse(key) => {
                    key.input_dimension() == parameters.external_lwe_dimension()
                        && key.ngsw_len == self.initializer.as_ref().len()
                }
            }
    }
}

/// Generates coefficient and exact-NTT keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) gadget: NttNtruGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates a key generator with reusable gadget-encryption workspace.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        Self {
            gadget: NttNtruGadgetEncryptContext::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates coefficient-domain client and accumulator secrets accepted by this backend.
    ///
    /// Rejection sampling checks invertibility in this context's NTT ring.
    /// The transformed secrets are discarded; use [`Self::try_generate`] when
    /// generating a paired server key so those representations can be reused.
    /// Returns a key-generation error when the bounded search is exhausted.
    ///
    /// # Panics
    ///
    /// Inherits [`NttNtruSecretKey::generate_padded_pair`] and
    /// [`NttNtruSecretKey::generate_pair`]'s sampling requirements. Fixed weights
    /// must fit the active client prefix or accumulator polynomial length.
    pub fn try_generate_client_key<R>(
        &self,
        rng: &mut R,
    ) -> Result<ClientKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe_dimension();
        let (client, _) = NttNtruSecretKey::generate_padded_pair(
            parameters.ntru_key_switching().ntru(),
            lwe_dimension,
            self.context.table(),
            rng,
        )?;
        let (accumulator, _) = NttNtruSecretKey::generate_pair(
            parameters.accumulator_ntru(),
            self.context.table(),
            rng,
        )?;
        Ok(ClientKey::new(client, accumulator, lwe_dimension))
    }

    /// Generates the selected capabilities from one compatible client key.
    /// Invalid CBS configuration is rejected before sampling evaluation material.
    /// Enabling CBS inherits [`Self::try_generate_circuit_bootstrap_key`]'s
    /// mathematical and security requirements.
    ///
    /// # Correctness
    /// Accumulator coefficients must satisfy
    /// [`NttNtruSecretKey::try_from_coeff_secret_key`]'s magnitude bound.
    ///
    /// # Errors
    /// Returns an error for incompatible parameters or a noninvertible secret.
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
        let table = self.context.table();
        let client_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.client_ntru_secret_key(),
            parameters.ntru_key_switching().ntru().cipher_modulus(),
            table,
        )?;
        let accumulator_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            parameters.accumulator_ntru().cipher_modulus(),
            table,
        )?;

        Ok(self.generate_server_key_from_transformed(
            client_key,
            &client_ntt,
            &accumulator_ntt,
            circuit_parameters,
            rng,
        ))
    }

    /// Generates evaluation material from already converted NTRU keys.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        client_ntt: &NttNtruSecretKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        circuit_parameters: Option<CircuitBootstrapParameters<T>>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let initializer = self.generate_initializer(accumulator_ntt, rng);
        let controls = self.generate_controls(client_key, accumulator_ntt, rng);
        let key_switching_key = NttNtruKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            client_ntt,
            parameters.ntru_key_switching(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        let circuit_bootstrap = circuit_parameters.map(|parameters| {
            Box::new(self.generate_circuit_bootstrap_key_with_main(
                client_key,
                accumulator_ntt,
                parameters,
                rng,
            ))
        });
        ServerKey {
            circuit_bootstrap,
            initializer,
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls: Controls::Classic(controls),
            input_distribution: parameters.external_lwe().secret_key_distr(),
            key_switching_key,
        }
    }

    /// Generates `NLEV_f_acc[1]` directly for accumulator initialization.
    pub(crate) fn generate_initializer<R>(
        &mut self,
        accumulator_ntt: &NttNtruSecretKey<T>,
        rng: &mut R,
    ) -> NttNlev<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let mut initializer = NttNlev::zero(parameters.blind_rotation().nlev_len());
        accumulator_ntt.encrypt_nlev_constant_to(
            T::ONE,
            &mut initializer,
            parameters.blind_rotation(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        initializer
    }

    /// Encrypts binary coefficients or adjacent ternary selector pairs as NTT NGSWs.
    fn generate_controls<R>(
        &mut self,
        client_key: &ClientKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
        rng: &mut R,
    ) -> Vec<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let nlev_len = parameters.blind_rotation().nlev_len();
        let coefficients = client_key.external_lwe_secret_coefficients();
        // Only ternary generation allocates temporary selectors; erase them on drop.
        let mut selectors = Zeroizing::new(Vec::new());
        let plaintexts = if parameters.external_lwe().secret_key_distr().is_binary() {
            coefficients
        } else {
            let count = coefficients
                .len()
                .checked_mul(2)
                .expect("NGSW control count overflow");
            selectors.resize(count, T::SignedInteger::ZERO);
            for (&coefficient, pair) in coefficients.iter().zip(selectors.as_chunks_mut::<2>().0) {
                pair[0] = if coefficient == T::SignedInteger::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
                pair[1] = if coefficient == -T::SignedInteger::ONE {
                    T::SignedInteger::ONE
                } else {
                    T::SignedInteger::ZERO
                };
            }
            selectors.as_slice()
        };
        let total_len = plaintexts
            .len()
            .checked_mul(nlev_len)
            .expect("NGSW control batch length overflow");
        let mut controls = vec![T::ZERO; total_len];
        accumulator_ntt.encrypt_ngsw_signed_constant_batch_to(
            plaintexts,
            &mut controls,
            parameters.blind_rotation(),
            self.context.table(),
            rng,
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
    /// Inherits [`NttNtruSecretKey::generate_padded_pair`] and
    /// [`NttNtruSecretKey::generate_pair`]'s sampling requirements. Fixed weights
    /// must fit the active client prefix or accumulator polynomial length.
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
        let lwe_dimension = parameters.external_lwe_dimension();
        let (client, client_ntt) = NttNtruSecretKey::generate_padded_pair(
            parameters.ntru_key_switching().ntru(),
            lwe_dimension,
            self.context.table(),
            rng,
        )?;
        let (accumulator, accumulator_ntt) = NttNtruSecretKey::generate_pair(
            parameters.accumulator_ntru(),
            self.context.table(),
            rng,
        )?;
        let client_key = ClientKey::new(client, accumulator, lwe_dimension);
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_from_transformed(
            &client_key,
            &client_ntt,
            &accumulator_ntt,
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
