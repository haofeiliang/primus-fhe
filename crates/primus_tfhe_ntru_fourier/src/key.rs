use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::ngsw::FourierNgsw;
use primus_lattice::nlev::FourierNlev;
use primus_ntru::{
    FourierNtruGadgetEncryptContext, FourierNtruKeySwitchingKey, FourierNtruSecretKey,
};

use crate::{
    CircuitBootstrapConfig, CircuitBootstrapKey, CircuitBootstrapParameters, ClientKey,
    KeyGenerationError, TfheContext, TfheParameters,
};

/// Fourier evaluation keys for NTRU TFHE.
/// The initializer and controls share the stored blind-rotation basis.
pub struct ServerKey<T: TorusFftValue> {
    circuit_bootstrap: Option<Box<CircuitBootstrapKey<T>>>,
    initializer: FourierNlev<Vec<Complex64>>,
    blind_rotation_basis: ApproxSignedBasis<T>,
    controls: Vec<Complex64>,
    key_switching_key: FourierNtruKeySwitchingKey<T>,
}

impl<T: TorusFftValue> ServerKey<T> {
    /// Returns the bound CBS parameters and keys, if requested during generation.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> Option<&CircuitBootstrapKey<T>> {
        self.circuit_bootstrap.as_deref()
    }

    /// Returns the Fourier NLev encryption of one used for initialization.
    #[inline]
    pub(crate) fn initializer(&self) -> &FourierNlev<Vec<Complex64>> {
        &self.initializer
    }

    /// Returns the common initializer/control decomposition basis.
    pub(crate) fn blind_rotation_basis(&self) -> &ApproxSignedBasis<T> {
        &self.blind_rotation_basis
    }

    /// Returns the post-bootstrap `f_acc -> f_client` key-switching key.
    #[inline]
    pub(crate) fn key_switching_key(&self) -> &FourierNtruKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Iterates over contiguous Fourier NGSW controls without allocation.
    pub(crate) fn iter_controls(&self) -> impl ExactSizeIterator<Item = FourierNgsw<&[Complex64]>> {
        self.controls
            .chunks_exact(self.initializer.as_ref().len())
            .map(FourierNgsw::new)
    }

    /// Checks the generated ring and decomposition parameters before evaluation.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        self.initializer.as_ref().len() == parameters.blind_rotation().fourier_nlev_len()
            && &self.blind_rotation_basis == parameters.blind_rotation().basis()
            && self.key_switching_key.poly_length() == parameters.poly_length()
            && self.key_switching_key.basis() == parameters.ntru_key_switching().basis()
            && self.controls.len()
                == parameters.external_lwe_dimension() * self.initializer.as_ref().len()
    }
}

/// Generates coefficient and Fourier keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) fft: FftEngine<'a, Table>,
    pub(crate) gadget: FourierNtruGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a key generator with reusable FFT and encryption workspaces.
    #[must_use]
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        Self {
            fft: context.new_fft_engine(),
            gadget: FourierNtruGadgetEncryptContext::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates coefficient-domain client and accumulator secrets accepted by this backend.
    ///
    /// Rejection sampling checks native-ring invertibility and Fourier inverse stability.
    /// The transformed secrets are discarded; use [`Self::try_generate`] when
    /// generating a paired server key so those representations can be reused.
    /// Returns a key-generation error when the bounded search is exhausted.
    pub fn try_generate_client_key<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<ClientKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe_dimension();
        let (client, _) = FourierNtruSecretKey::generate_padded_pair(
            parameters.ntru_key_switching().ntru(),
            lwe_dimension,
            &mut self.fft,
            rng,
        )?;
        let (accumulator, _) =
            FourierNtruSecretKey::generate_pair(parameters.accumulator_ntru(), &mut self.fft, rng)?;
        Ok(ClientKey::new(client, accumulator, lwe_dimension))
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
        let client_fourier = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.client_ntru_secret_key(),
            &mut self.fft,
        )?;
        let accumulator_fourier = FourierNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;

        Ok(self.generate_server_key_from_transformed(
            client_key,
            &client_fourier,
            &accumulator_fourier,
            circuit_parameters,
            rng,
        ))
    }

    /// Generates evaluation material from already converted NTRU keys.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        client_fourier: &FourierNtruSecretKey,
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
        let key_switching_key = FourierNtruKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            client_fourier,
            parameters.ntru_key_switching(),
            &mut self.fft,
            rng,
            &mut self.gadget,
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
            initializer,
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls,
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

    /// Encrypts every binary client coefficient as one contiguous Fourier NGSW.
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
        let total_len = parameters
            .external_lwe_dimension()
            .checked_mul(nlev_len)
            .expect("Fourier NGSW control batch length overflow");
        let mut controls = vec![Complex64::default(); total_len];
        accumulator_fourier.encrypt_ngsw_signed_constant_batch_to(
            client_key.external_lwe_secret_coefficients(),
            &mut controls,
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
        let (client, client_fourier) = FourierNtruSecretKey::generate_padded_pair(
            parameters.ntru_key_switching().ntru(),
            lwe_dimension,
            &mut self.fft,
            rng,
        )?;
        let (accumulator, accumulator_fourier) =
            FourierNtruSecretKey::generate_pair(parameters.accumulator_ntru(), &mut self.fft, rng)?;
        let client_key = ClientKey::new(client, accumulator, lwe_dimension);
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_from_transformed(
            &client_key,
            &client_fourier,
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
