use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_ntru::{NlevParameters, NtruParameters};
use primus_reduce::RingContext;
use primus_tfhe::rotation::RotationQuantizer;

use crate::TfheParameterError::{
    CipherModulusMismatch, ClientSecretKeyDistributionMismatch, ClientSecretKeyMustBeBinary,
    InvalidLweDimension, PlainModulusMismatch, PolynomialLengthMismatch,
};
/// Mathematical parameters for NTRU-based TFHE.
///
/// The blind-rotation parameters describe ciphertexts under the accumulator
/// key. The key-switching parameters describe NLev ciphertexts under the
/// client key and therefore the target of the post-bootstrap NTRU key switch.
#[derive(Clone)]
pub struct TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    external_lwe: LweParameters<T, M>,
    blind_rotation: NlevParameters<T, M>,
    ntru_key_switching: NlevParameters<T, M>,
    rotation_quantizer: RotationQuantizer<M::Prepared>,
}

impl<T, M> TfheParameters<T, M>
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
    /// agree on `N`, `t`, and `q` where applicable. The rotation domain `2N`
    /// must be representable by `T`.
    pub fn try_new(
        external_lwe: LweParameters<T, M>,
        blind_rotation: NlevParameters<T, M>,
        ntru_key_switching: NlevParameters<T, M>,
    ) -> Result<Self, TfheParameterError> {
        let external_distr = external_lwe.secret_key_distr();
        let client_ntru_distr = ntru_key_switching.ntru().secret_key_distr();
        if !external_distr.is_binary() || !client_ntru_distr.is_binary() {
            return Err(ClientSecretKeyMustBeBinary);
        }
        if external_distr != client_ntru_distr {
            return Err(ClientSecretKeyDistributionMismatch);
        }

        let accumulator_ntru = blind_rotation.ntru();
        let client_ntru = ntru_key_switching.ntru();
        let poly_length = accumulator_ntru.poly_length();
        if !(1..=poly_length).contains(&external_lwe.dimension()) {
            return Err(InvalidLweDimension {
                lwe_dimension: external_lwe.dimension(),
                poly_length,
            });
        }
        if client_ntru.poly_length() != poly_length {
            return Err(PolynomialLengthMismatch);
        }
        if external_lwe.plain_modulus_value() != accumulator_ntru.plain_modulus()
            || client_ntru.plain_modulus() != accumulator_ntru.plain_modulus()
        {
            return Err(PlainModulusMismatch);
        }
        if external_lwe.cipher_modulus_value() != accumulator_ntru.cipher_modulus_value()
            || client_ntru.cipher_modulus_value() != accumulator_ntru.cipher_modulus_value()
        {
            return Err(CipherModulusMismatch);
        }

        if T::try_from(poly_length * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }
        let rotation_quantizer =
            RotationQuantizer::new(external_lwe.cipher_modulus(), poly_length * 2, 1);
        Ok(Self {
            rotation_quantizer,
            external_lwe,
            blind_rotation,
            ntru_key_switching,
        })
    }

    /// Returns the ordinary-PBS quantizer prepared with these parameters.
    #[doc(hidden)]
    #[must_use]
    pub fn rotation_quantizer(&self) -> RotationQuantizer<M::Prepared> {
        self.rotation_quantizer
    }

    /// Returns the externally visible LWE parameters.
    #[must_use]
    #[inline]
    pub fn external_lwe(&self) -> &LweParameters<T, M> {
        &self.external_lwe
    }

    /// Returns the shared parameters of the NLev initializer and NGSW controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation(&self) -> &NlevParameters<T, M> {
        &self.blind_rotation
    }

    /// Returns the accumulator's NTRU encryption parameters.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru(&self) -> &NtruParameters<T, M> {
        self.blind_rotation.ntru()
    }

    /// Returns the dimension of externally visible LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe.dimension()
    }

    /// Returns the input LWE codec used by client encryption and LUT compilation.
    #[must_use]
    #[inline]
    pub fn input_plaintext_codec(&self) -> &RoundedCodec<T, M> {
        self.external_lwe.plaintext_codec()
    }

    /// Returns the post-bootstrap NTRU key-switching parameters.
    #[must_use]
    #[inline]
    pub fn ntru_key_switching(&self) -> &NlevParameters<T, M> {
        &self.ntru_key_switching
    }

    /// Returns the common NTRU polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.blind_rotation.poly_length()
    }

    /// Returns the common plaintext modulus.
    #[must_use]
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.external_lwe.plain_modulus_value()
    }
}

/// An invalid combination of NTRU-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheParameterError {
    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,
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
