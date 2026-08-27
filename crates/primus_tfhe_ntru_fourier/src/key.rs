use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::SignedInteger;
use primus_lattice::ngsw::FourierNgsw;
use primus_ntru::{
    FourierNtruGadgetEncryptContext, FourierNtruKeySwitchingKey, FourierNtruSecretKey,
    NtruSecretKey, SecretKeyDistr,
};
use primus_poly::PolynomialOwned;

use crate::{ClientKey, TfheContext, TfheKeyError, TfheParameters};

/// Fourier evaluation keys for NTRU TFHE.
pub struct ServerKey {
    initializer: FourierNtruKeySwitchingKey,
    controls: Vec<Complex64>,
    key_switching_key: FourierNtruKeySwitchingKey,
    poly_length: usize,
    bootstrapping_fourier_nlev_len: usize,
}

impl ServerKey {
    /// Returns the Fourier NLev encryption of one used for initialization.
    #[inline]
    pub(crate) fn initializer(&self) -> &FourierNtruKeySwitchingKey {
        &self.initializer
    }

    /// Returns the post-bootstrap `f_acc -> f_client` key-switching key.
    #[inline]
    pub(crate) fn key_switching_key(&self) -> &FourierNtruKeySwitchingKey {
        &self.key_switching_key
    }

    /// Iterates over contiguous Fourier NGSW controls without allocation.
    pub(crate) fn iter_controls(&self) -> impl ExactSizeIterator<Item = FourierNgsw<&[Complex64]>> {
        self.controls
            .chunks_exact(self.bootstrapping_fourier_nlev_len)
            .map(FourierNgsw::new)
    }

    /// Checks the stored layout against one parameter set.
    pub(crate) fn is_compatible<T: TorusFftValue>(&self, parameters: &TfheParameters<T>) -> bool {
        self.poly_length == parameters.poly_length()
            && self.bootstrapping_fourier_nlev_len == parameters.bootstrapping().fourier_nlev_len()
            && self.controls.len()
                == parameters.external_lwe().dimension()
                    * parameters.bootstrapping().fourier_nlev_len()
            && self.initializer.as_slice().len() == parameters.bootstrapping().fourier_nlev_len()
            && self.key_switching_key.as_slice().len()
                == parameters.key_switching().fourier_nlev_len()
    }
}

/// Generates coefficient and Fourier keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    fft: FftEngine<'a, Table>,
    gadget: FourierNtruGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a key generator with reusable FFT and encryption workspaces.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        Self {
            fft: context.new_fft_engine(),
            gadget: FourierNtruGadgetEncryptContext::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates fresh coefficient-domain client and accumulator secrets.
    pub fn generate_client_key<R>(&mut self, rng: &mut R) -> Result<ClientKey<T>, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe().dimension();
        let (client, _) = FourierNtruSecretKey::generate_padded_binary_pair(
            parameters.key_switching().ntru(),
            lwe_dimension,
            &mut self.fft,
            rng,
        )?;
        let (accumulator, _) = FourierNtruSecretKey::generate_pair(
            parameters.bootstrapping().ntru(),
            &mut self.fft,
            rng,
        )?;
        Ok(ClientKey::new(client, accumulator, lwe_dimension))
    }

    /// Generates a server key from an existing compatible client key.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
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
            rng,
        ))
    }

    /// Generates evaluation material from already converted NTRU keys.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        client_fourier: &FourierNtruSecretKey,
        accumulator_fourier: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> ServerKey
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let initializer = self.generate_initializer(accumulator_fourier, rng);
        let controls = self.generate_controls(client_key, accumulator_fourier, rng);
        let key_switching_key = FourierNtruKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            client_fourier,
            parameters.key_switching(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        ServerKey {
            initializer,
            controls,
            key_switching_key,
            poly_length: parameters.poly_length(),
            bootstrapping_fourier_nlev_len: parameters.bootstrapping().fourier_nlev_len(),
        }
    }

    /// Generates `NLEV_f_acc[1]` using the NTRU key-switch primitive.
    fn generate_initializer<R>(
        &mut self,
        accumulator_fourier: &FourierNtruSecretKey,
        rng: &mut R,
    ) -> FourierNtruKeySwitchingKey
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let mut coefficients = vec![T::ZERO.cast_to_signed(); parameters.poly_length()];
        coefficients[0] = T::ONE.cast_to_signed();
        let unit = NtruSecretKey::new(
            coefficients,
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 1 },
        );
        FourierNtruKeySwitchingKey::generate(
            &unit,
            accumulator_fourier,
            parameters.bootstrapping(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        )
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
        let nlev_len = parameters.bootstrapping().fourier_nlev_len();
        let mut controls =
            vec![Complex64::default(); parameters.external_lwe().dimension() * nlev_len];
        let mut message = PolynomialOwned::zero(parameters.poly_length());
        for (&coefficient, chunk) in client_key
            .external_lwe_secret_key()
            .iter()
            .zip(controls.chunks_exact_mut(nlev_len))
        {
            message.as_mut()[0] = coefficient.cast_to_unsigned();
            accumulator_fourier.encrypt_ngsw_to(
                &message,
                &mut FourierNgsw::new(chunk),
                parameters.bootstrapping(),
                &mut self.fft,
                rng,
                &mut self.gadget,
            );
        }
        controls
    }

    /// Generates a fresh compatible client/server key pair.
    pub fn generate<R>(&mut self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe().dimension();
        let (client, client_fourier) = FourierNtruSecretKey::generate_padded_binary_pair(
            parameters.key_switching().ntru(),
            lwe_dimension,
            &mut self.fft,
            rng,
        )?;
        let (accumulator, accumulator_fourier) = FourierNtruSecretKey::generate_pair(
            parameters.bootstrapping().ntru(),
            &mut self.fft,
            rng,
        )?;
        let client_key = ClientKey::new(client, accumulator, lwe_dimension);
        let server_key = self.generate_server_key_from_transformed(
            &client_key,
            &client_fourier,
            &accumulator_fourier,
            rng,
        );
        Ok((client_key, server_key))
    }
}
