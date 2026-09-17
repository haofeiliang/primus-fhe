use primus_glwe::{
    NttGadgetEncryptContext, NttGlweKeySwitchingKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_reduce::Modulus;
use primus_tfhe_glwe::ClientKey;

use crate::{
    NttGlweBootstrappingKey, SparseBootstrappingKeyError, SparseGlweBootstrappingKey, TfheContext,
    TfheParameters, error::TfheKeyError,
};

/// Blind-rotation key selected when generating a server key.
///
/// Classic keys store NTT GGSWs; sparse keys store coefficient GGSWs and public
/// buckets. Both target the same accumulator secret and use the small-LWE input.
pub enum BootstrappingKey<T: FheUint> {
    /// One binary control or a ternary control pair per input coefficient.
    Classic(NttGlweBootstrappingKey<T, BarrettModulus<T>>),
    /// Bucketed selections for a fixed-weight binary input secret.
    Sparse(SparseGlweBootstrappingKey<T>),
}

impl<T: FheUint> BootstrappingKey<T> {
    fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
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
        dimension == parameters.small_lwe().dimension()
            && input_modulus == parameters.small_lwe().cipher_modulus_value()
            && size == parameters.blind_rotation_ggsw().size()
            && basis == parameters.blind_rotation_ggsw().basis()
            && cipher_modulus == parameters.accumulator_glwe().cipher_modulus_value()
    }
}

/// Classic or sparse evaluation keys used by a TFHE server.
///
/// Both PBS orders share these key materials. [`crate::PbsOrder`] only changes
/// the order in which the evaluator applies them.
pub struct ServerKey<T: FheUint> {
    bootstrapping_key: BootstrappingKey<T>,
    glwe_key_switching_key: NttGlweKeySwitchingKey<T>,
}

impl<T: FheUint> ServerKey<T> {
    pub(crate) fn is_compatible(&self, parameters: &TfheParameters<T>) -> bool {
        let key_switching = parameters.glwe_key_switching();
        self.bootstrapping_key.is_compatible(parameters)
            && self.glwe_key_switching_key.input_dimension() == key_switching.input_dimension()
            && self.glwe_key_switching_key.output_dimension() == key_switching.output_dimension()
            && self.glwe_key_switching_key.poly_length() == key_switching.poly_length()
            && self.glwe_key_switching_key.output_size() == key_switching.output_size()
            && self.glwe_key_switching_key.basis() == key_switching.output().basis()
    }

    /// Returns the selected classic or sparse blind-rotation key.
    #[must_use]
    #[inline]
    pub fn bootstrapping_key(&self) -> &BootstrappingKey<T> {
        &self.bootstrapping_key
    }

    /// Returns the NTT GLWE key-switching key.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching_key(&self) -> &NttGlweKeySwitchingKey<T> {
        &self.glwe_key_switching_key
    }

    /// Decomposes this server key into its bootstrapping and key-switching
    /// keys.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (BootstrappingKey<T>, NttGlweKeySwitchingKey<T>) {
        (self.bootstrapping_key, self.glwe_key_switching_key)
    }
}

/// Generates client and classic or sparse server keys for one NTT context.
pub struct KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) gadget: NttGadgetEncryptContext<T>,
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
            gadget: NttGadgetEncryptContext::new(parameters.size()),
        }
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

        let main_glwe_secret_key = NttGlweSecretKey::from_coeff_secret_key(
            client_key.glwe_secret_key(),
            self.context.table(),
        );
        Ok(self.generate_server_key_with_main(client_key, main_glwe_secret_key, rng))
    }

    /// Generates a complete sparse PBS server key for an existing client.
    ///
    /// Uses the client's fixed-weight binary small-LWE secret in both PBS orders.
    /// The GLWE key-switching key has the same domains as in classic PBS. Sparse
    /// generation checks parameters and privately retries matching before KSK
    /// allocation; a failure returns no partial server key.
    ///
    /// # Errors
    /// Inherits [`Self::try_generate_sparse_bootstrapping_key`]'s errors.
    ///
    /// # Correctness
    /// Inherits that method's secret and security requirements. The caller must
    /// budget sparse aggregation noise and, for interleaved LUTs, coarser rotations.
    pub fn try_generate_sparse_server_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        rng: &mut R,
    ) -> Result<ServerKey<T>, SparseBootstrappingKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let bootstrapping_key =
            self.try_generate_sparse_bootstrapping_key(client_key, copy_count, bucket_count, rng)?;
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        Ok(ServerKey {
            bootstrapping_key: BootstrappingKey::Sparse(bootstrapping_key),
            glwe_key_switching_key,
        })
    }

    /// The caller has checked the client key and prepared its matching main
    /// transform with this context's table. Taking ownership bounds its lifetime
    /// to BSK generation, before allocating the key-switching material.
    fn generate_server_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        main_glwe_secret_key: NttGlweSecretKey<T>,
        rng: &mut R,
    ) -> ServerKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        self.gadget.resize(parameters.blind_rotation_ggsw().size());
        let bootstrapping_key = NttGlweBootstrappingKey::generate_ntt(
            client_key.small_lwe_secret_key(),
            parameters.small_lwe(),
            &main_glwe_secret_key,
            parameters.blind_rotation_ggsw(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        drop(main_glwe_secret_key);
        let glwe_key_switching_key = self.generate_glwe_key_switching_key(client_key, rng);
        ServerKey {
            bootstrapping_key: BootstrappingKey::Classic(bootstrapping_key),
            glwe_key_switching_key,
        }
    }

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

    /// Generates a fresh compatible client/server key pair.
    pub fn generate<R>(&mut self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.context.parameters();
        let small_lwe_secret_key = LweSecretKey::generate(parameters.small_lwe(), rng);
        let (glwe_secret_key, main_glwe_secret_key) = NttGlweSecretKey::generate_pair(
            parameters.accumulator_glwe(),
            self.context.table(),
            rng,
        );
        let client_key = ClientKey::new(
            small_lwe_secret_key,
            glwe_secret_key,
            parameters.pbs_order(),
        );
        client_key.check_compatible(parameters)?;
        let server_key = self.generate_server_key_with_main(&client_key, main_glwe_secret_key, rng);
        Ok((client_key, server_key))
    }
}
