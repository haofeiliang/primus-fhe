use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_ntru::NlevParameters;
use primus_reduce::RingContext;

use crate::NtruParameterError::{
    CipherModulusMismatch, ClientSecretKeyDistributionMismatch, ClientSecretKeyMustBeBinary,
    InvalidLweDimension, PlainModulusMismatch, PolynomialLengthMismatch,
};
/// Mathematical parameters for NTRU-based TFHE.
///
/// The bootstrapping parameters describe ciphertexts under the accumulator
/// key. The key-switching parameters describe NLev ciphertexts under the
/// client key and therefore the target of the post-bootstrap NTRU key switch.
#[derive(Clone)]
pub struct NtruTfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    external_lwe: LweParameters<T, M>,
    bootstrapping: NlevParameters<T, M>,
    key_switching: NlevParameters<T, M>,
}

impl<T, M> NtruTfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates one NTRU TFHE parameter set.
    ///
    /// # Errors
    ///
    /// Returns an error unless the external LWE key is the binary coefficient
    /// prefix of an NTRU key, fits in `N`, and all three parameter domains
    /// agree on `N`, `t`, and `q` where applicable.
    pub fn try_new(
        external_lwe: LweParameters<T, M>,
        bootstrapping: NlevParameters<T, M>,
        key_switching: NlevParameters<T, M>,
    ) -> Result<Self, NtruParameterError> {
        let external_distr = external_lwe.secret_key_distr();
        let client_ntru_distr = key_switching.ntru().secret_key_distr();
        if !external_distr.is_binary() || !client_ntru_distr.is_binary() {
            return Err(ClientSecretKeyMustBeBinary);
        }
        if external_distr != client_ntru_distr {
            return Err(ClientSecretKeyDistributionMismatch);
        }

        let bootstrapping_ntru = bootstrapping.ntru();
        let key_switching_ntru = key_switching.ntru();
        let poly_length = bootstrapping_ntru.poly_length();
        if !(1..=poly_length).contains(&external_lwe.dimension()) {
            return Err(InvalidLweDimension {
                lwe_dimension: external_lwe.dimension(),
                poly_length,
            });
        }
        if key_switching_ntru.poly_length() != poly_length {
            return Err(PolynomialLengthMismatch);
        }
        if external_lwe.plain_modulus_value() != bootstrapping_ntru.plain_modulus()
            || key_switching_ntru.plain_modulus() != bootstrapping_ntru.plain_modulus()
        {
            return Err(PlainModulusMismatch);
        }
        if external_lwe.cipher_modulus_value() != bootstrapping_ntru.cipher_modulus_value()
            || key_switching_ntru.cipher_modulus_value()
                != bootstrapping_ntru.cipher_modulus_value()
        {
            return Err(CipherModulusMismatch);
        }

        Ok(Self {
            external_lwe,
            bootstrapping,
            key_switching,
        })
    }

    /// Returns the externally visible LWE parameters.
    #[inline]
    pub fn external_lwe(&self) -> &LweParameters<T, M> {
        &self.external_lwe
    }

    /// Returns the accumulator NLev/NGSW parameters.
    #[inline]
    pub fn bootstrapping(&self) -> &NlevParameters<T, M> {
        &self.bootstrapping
    }

    /// Returns the post-bootstrap NTRU key-switching parameters.
    #[inline]
    pub fn key_switching(&self) -> &NlevParameters<T, M> {
        &self.key_switching
    }

    /// Returns the common NTRU polynomial length.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.bootstrapping.poly_length()
    }

    /// Returns the common plaintext modulus.
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.external_lwe.plain_modulus_value()
    }
}

/// An invalid combination of NTRU-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtruParameterError {
    /// The external LWE and client NTRU secret must both be binary.
    #[error("NTRU TFHE requires a binary client secret key")]
    ClientSecretKeyMustBeBinary,
    /// The external LWE and padded NTRU views describe different distributions.
    #[error("the external LWE and client NTRU secret-key distributions must match")]
    ClientSecretKeyDistributionMismatch,
    /// The external LWE key cannot fit in one zero-padded NTRU polynomial.
    #[error("external LWE dimension {lwe_dimension} must belong to 1..={poly_length}")]
    InvalidLweDimension {
        /// Configured external LWE dimension.
        lwe_dimension: usize,
        /// Configured NTRU polynomial length.
        poly_length: usize,
    },
    /// The accumulator and key-switching rings have different lengths.
    #[error("NTRU polynomial lengths do not match")]
    PolynomialLengthMismatch,
    /// The LWE and NTRU plaintext spaces differ.
    #[error("LWE and NTRU plaintext moduli do not match")]
    PlainModulusMismatch,
    /// The LWE and NTRU ciphertext rings differ.
    #[error("LWE and NTRU ciphertext moduli do not match")]
    CipherModulusMismatch,
}
