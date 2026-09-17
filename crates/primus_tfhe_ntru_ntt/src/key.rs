use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::ngsw::NttNgsw;
use primus_lattice::nlev::NttNlev;
use primus_ntru::{NttNtruGadgetEncryptContext, NttNtruKeySwitchingKey, NttNtruSecretKey};
use primus_ntt::NttTable;

use crate::{ClientKey, TfheContext, TfheKeyError, TfheParameters};

/// Exact NTT evaluation keys for NTRU TFHE.
/// The initializer and controls share the stored blind-rotation basis.
pub struct ServerKey<T: FheUint> {
    initializer: NttNlev<Vec<T>>,
    blind_rotation_basis: ApproxSignedBasis<T>,
    controls: Vec<T>,
    key_switching_key: NttNtruKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
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

    /// Iterates over the contiguous NGSW controls without allocation.
    pub(crate) fn iter_controls(&self) -> impl ExactSizeIterator<Item = NttNgsw<&[T]>> {
        self.controls
            .chunks_exact(self.initializer.as_ref().len())
            .map(NttNgsw::new)
    }

    /// Checks the generated ring and decomposition parameters before evaluation.
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        self.initializer.as_ref().len() == parameters.blind_rotation().nlev_len()
            && &self.blind_rotation_basis == parameters.blind_rotation().basis()
            && self.key_switching_key.poly_length() == parameters.poly_length()
            && self.key_switching_key.basis() == parameters.ntru_key_switching().basis()
            && self.controls.len()
                == parameters.external_lwe_dimension() * self.initializer.as_ref().len()
    }
}

/// Generates coefficient and exact-NTT keys for one NTRU TFHE context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) gadget: NttNtruGadgetEncryptContext<T>,
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
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
    pub fn try_generate_client_key<R>(&self, rng: &mut R) -> Result<ClientKey<T>, TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe_dimension();
        let (client, _) = NttNtruSecretKey::generate_padded_binary_pair(
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

    /// Generates a server key from an existing compatible client key.
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
            parameters.ntru_key_switching(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        ServerKey {
            initializer,
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls,
            key_switching_key,
        }
    }

    /// Generates `NLEV_f_acc[1]` directly for accumulator initialization.
    fn generate_initializer<R>(
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
        let nlev_len = parameters.blind_rotation().nlev_len();
        let total_len = parameters
            .external_lwe_dimension()
            .checked_mul(nlev_len)
            .expect("NGSW control batch length overflow");
        let mut controls = vec![T::ZERO; total_len];
        accumulator_ntt.encrypt_ngsw_signed_constant_batch_to(
            client_key.external_lwe_secret_coefficients(),
            &mut controls,
            parameters.blind_rotation(),
            self.context.table(),
            rng,
        );
        controls
    }

    /// Generates a fresh compatible client/server key pair, reusing transformed secrets.
    /// Returns a key-generation error when the bounded rejection search is exhausted.
    pub fn try_generate<R>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe_dimension();
        let (client, client_ntt) = NttNtruSecretKey::generate_padded_binary_pair(
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
            rng,
        );
        Ok((client_key, server_key))
    }
}
