use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;

use super::TfheClientError;
use crate::{ClientKey, LweCiphertext, TfheParameters};

mod sealed {
    pub trait Sealed {}
    impl<T: primus_integer::FheUint> Sealed for super::ClientKey<T> {}
    impl<T: primus_integer::FheUint> Sealed for primus_lwe::LwePublicKey<T> {}
}

/// Supported secret and public keys for [`Encryptor`](super::Encryptor).
///
/// Implemented only for [`ClientKey`] and [`LwePublicKey`]. A public key
/// must come from the external client secret paired with the server key;
/// matching dimensions and moduli cannot establish that relationship.
/// Public encryption uses the external secret-encryption noise sampler for
/// each fresh error term. The combined noise must satisfy [`LwePublicKey`]'s
/// correctness requirements and the PBS/ManyLUT input noise budget.
/// Message checks and encoding belong to [`Encryptor`](super::Encryptor);
/// these methods operate on encoded ciphertext residues.
pub trait EncryptionKey<T, M>: sealed::Sealed
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Checks the structural compatibility needed by the encryptor constructor.
    fn check_compatible(&self, parameters: &TfheParameters<T, M>) -> Result<(), TfheClientError>;

    /// Encrypts an encoded residue using the configured external noise sampler.
    ///
    /// # Correctness
    ///
    /// `plaintext` must be canonical in `[0, q)`. Requires successful
    /// [`Self::check_compatible`] and the type's secret,
    /// public-key noise and key-identity contracts. Signed/encoded secret ranges
    /// follow [`primus_lwe::LweSecretKeyRef`].
    #[must_use]
    fn encrypt_encoded<R>(
        &self,
        plaintext: T,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng;

    /// Overwrites caller storage with an encryption of an encoded residue.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::encrypt_encoded`]'s residue, parameter and key contracts.
    ///
    /// # Panics
    ///
    /// Panics for an incompatible output length.
    /// RNG panics may leave partial output; see [`primus_lwe::LweSecretKeyRef::encrypt_encoded_to`]
    /// and [`LwePublicKey::encrypt_encoded_to`].
    fn encrypt_encoded_to<R>(
        &self,
        plaintext: T,
        output: &mut LweCiphertext<T>,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng;
}

impl<T, M> EncryptionKey<T, M> for ClientKey<T>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn check_compatible(&self, parameters: &TfheParameters<T, M>) -> Result<(), TfheClientError> {
        Ok(self.check_compatible(parameters)?)
    }

    fn encrypt_encoded<R>(
        &self,
        plaintext: T,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        self.external_lwe_secret_key().encrypt_encoded(
            plaintext,
            lwe.cipher_modulus(),
            lwe.cipher_modulus_uniform_distr(),
            lwe.noise_distribution(),
            rng,
        )
    }

    fn encrypt_encoded_to<R>(
        &self,
        plaintext: T,
        output: &mut LweCiphertext<T>,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        self.external_lwe_secret_key().encrypt_encoded_to(
            plaintext,
            output,
            lwe.cipher_modulus(),
            lwe.cipher_modulus_uniform_distr(),
            lwe.noise_distribution(),
            rng,
        );
    }
}

impl<T, M> EncryptionKey<T, M> for LwePublicKey<T>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn check_compatible(&self, parameters: &TfheParameters<T, M>) -> Result<(), TfheClientError> {
        if self.dimension() != parameters.external_lwe_dimension() {
            return Err(TfheClientError::PublicKeyDimensionMismatch {
                expected: parameters.external_lwe_dimension(),
                actual: self.dimension(),
            });
        }
        if self.cipher_modulus_minus_one() != parameters.external_lwe().cipher_modulus_minus_one() {
            return Err(TfheClientError::PublicKeyModulusMismatch);
        }
        Ok(())
    }

    fn encrypt_encoded<R>(
        &self,
        plaintext: T,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        LwePublicKey::encrypt_encoded(
            self,
            plaintext,
            lwe.cipher_modulus(),
            lwe.noise_distribution(),
            rng,
        )
    }

    fn encrypt_encoded_to<R>(
        &self,
        plaintext: T,
        output: &mut LweCiphertext<T>,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        LwePublicKey::encrypt_encoded_to(
            self,
            plaintext,
            output,
            lwe.cipher_modulus(),
            lwe.noise_distribution(),
            rng,
        );
    }
}
