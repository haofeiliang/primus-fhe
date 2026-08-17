use primus_integer::FheUint;
use primus_lattice::ngsw::NttNgsw;
use primus_ntru::{
    NtruSecretKey, NttNtruGadgetEncryptContext, NttNtruKeySwitchingKey, NttNtruSecretKey,
};
use primus_ntt::NttTable;
use primus_poly::PolynomialOwned;

use crate::{ClientKey, TfheContext, TfheKeyError, TfheParameters};

/// Exact NTT evaluation keys for NTRU TFHE.
pub struct ServerKey<T: FheUint> {
    initializer: NttNtruKeySwitchingKey<T>,
    controls: Vec<T>,
    key_switching_key: NttNtruKeySwitchingKey<T>,
    poly_length: usize,
    bootstrapping_nlev_len: usize,
}

impl<T: FheUint> ServerKey<T> {
    /// Returns the NLev encryption of one used to initialize the accumulator.
    #[inline]
    pub(crate) fn initializer(&self) -> &NttNtruKeySwitchingKey<T> {
        &self.initializer
    }

    /// Returns the post-bootstrap `f_acc -> f_client` key-switching key.
    #[inline]
    pub(crate) fn key_switching_key(&self) -> &NttNtruKeySwitchingKey<T> {
        &self.key_switching_key
    }

    /// Iterates over the contiguous NGSW controls without allocation.
    pub(crate) fn iter_controls(&self) -> impl ExactSizeIterator<Item = NttNgsw<&[T]>> {
        self.controls
            .chunks_exact(self.bootstrapping_nlev_len)
            .map(NttNgsw::new)
    }

    /// Checks the stored layout against one parameter set.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        self.poly_length == parameters.poly_length()
            && self.bootstrapping_nlev_len == parameters.bootstrapping().nlev_len()
            && self.controls.len()
                == parameters.external_lwe().dimension() * parameters.bootstrapping().nlev_len()
            && self.initializer.as_slice().len() == parameters.bootstrapping().nlev_len()
            && self.key_switching_key.as_slice().len() == parameters.key_switching().nlev_len()
    }
}

/// Generates coefficient and exact-NTT keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    gadget: NttNtruGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Creates a key generator with reusable gadget-encryption workspace.
    pub fn new(context: &'a TfheContext<T, Table>) -> Self {
        Self {
            gadget: NttNtruGadgetEncryptContext::new(context.parameters().poly_length()),
            context,
        }
    }

    /// Generates fresh coefficient-domain client and accumulator secrets.
    pub fn generate_client_key<R>(&self, rng: &mut R) -> Result<ClientKey<T>, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe().dimension();
        let (client, _) = NttNtruSecretKey::generate_padded_binary_pair(
            parameters.key_switching().ntru(),
            lwe_dimension,
            self.context.table(),
            rng,
        )?;
        let (accumulator, _) = NttNtruSecretKey::generate_pair(
            parameters.bootstrapping().ntru(),
            self.context.table(),
            rng,
        )?;
        Ok(ClientKey::new(client, accumulator, lwe_dimension))
    }

    /// Generates a server key from an existing compatible client key.
    pub fn try_generate_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<ServerKey<T>, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        client_key.check_compatible(parameters)?;
        let table = self.context.table();
        let client_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.client_ntru_secret_key(),
            parameters.key_switching().ntru().cipher_modulus(),
            table,
        )?;
        let accumulator_ntt = NttNtruSecretKey::try_from_coeff_secret_key(
            client_key.accumulator_ntru_secret_key(),
            parameters.bootstrapping().ntru().cipher_modulus(),
            table,
        )?;

        Ok(self.generate_server_key_from_transformed(
            client_key,
            &client_ntt,
            &accumulator_ntt,
            rng,
        ))
    }

    /// Generates evaluation material from already converted NTRU keys.
    fn generate_server_key_from_transformed<R>(
        &mut self,
        client_key: &ClientKey<T>,
        client_ntt: &NttNtruSecretKey<T>,
        accumulator_ntt: &NttNtruSecretKey<T>,
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
            parameters.key_switching(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        ServerKey {
            initializer,
            controls,
            key_switching_key,
            poly_length: parameters.poly_length(),
            bootstrapping_nlev_len: parameters.bootstrapping().nlev_len(),
        }
    }

    /// Generates `NLEV_f_acc[1]` using the existing NTRU key-switch primitive.
    fn generate_initializer<R>(
        &mut self,
        accumulator_ntt: &NttNtruSecretKey<T>,
        rng: &mut R,
    ) -> NttNtruKeySwitchingKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let mut coefficients = vec![T::ZERO.cast_to_signed(); parameters.poly_length()];
        coefficients[0] = T::ONE.cast_to_signed();
        let unit = NtruSecretKey::new(
            coefficients,
            primus_ntru::SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 1 },
        );
        NttNtruKeySwitchingKey::generate(
            &unit,
            accumulator_ntt,
            parameters.bootstrapping(),
            self.context.table(),
            rng,
            &mut self.gadget,
        )
    }

    /// Encrypts every binary client coefficient as one contiguous NTT NGSW.
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
        let nlev_len = parameters.bootstrapping().nlev_len();
        let mut controls = vec![T::ZERO; parameters.external_lwe().dimension() * nlev_len];
        let mut message = PolynomialOwned::zero(parameters.poly_length());
        for (&coefficient, chunk) in client_key
            .external_lwe_secret_key()
            .iter()
            .zip(controls.chunks_exact_mut(nlev_len))
        {
            message.as_mut()[0] = T::cast_from_signed(coefficient);
            accumulator_ntt.encrypt_ngsw_to(
                &message,
                &mut NttNgsw::new(chunk),
                parameters.bootstrapping(),
                self.context.table(),
                rng,
                &mut self.gadget,
            );
        }
        controls
    }

    /// Generates a fresh compatible client/server key pair.
    pub fn generate<R>(&mut self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe().dimension();
        let (client, client_ntt) = NttNtruSecretKey::generate_padded_binary_pair(
            parameters.key_switching().ntru(),
            lwe_dimension,
            self.context.table(),
            rng,
        )?;
        let (accumulator, accumulator_ntt) = NttNtruSecretKey::generate_pair(
            parameters.bootstrapping().ntru(),
            self.context.table(),
            rng,
        )?;
        let client_key = ClientKey::new(client, accumulator, lwe_dimension);
        let server_key = self.generate_server_key_from_transformed(
            &client_key,
            &client_ntt,
            &accumulator_ntt,
            rng,
        );
        Ok((client_key, server_key))
    }
}
