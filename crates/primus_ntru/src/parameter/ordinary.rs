//! Ordinary NTRU parameters and message encoding.

use super::{NtruParameterError, NtruParametersInner};
use crate::SecretKeyDistr;
use primus_distr::DiscreteGaussian;
use primus_encoding::ScaledCodec;
use primus_integer::FheUint;
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use std::sync::Arc;

/// Parameters for scalar secret-key NTRU encryption.
///
/// The ciphertext modulus may be an explicit NTT-friendly field or the native
/// wrapping modulus used by the Fourier backend.  In either case plaintexts
/// use the codec scale `Delta = round(q / t)`.
/// The shared inner state owns the checked ring length and sampler tables;
/// cloning ordinary or derived gadget parameters retains that state through `Arc`.
#[derive(Clone)]
pub struct NtruParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    pub(super) inner: Arc<NtruParametersInner<T, M>>,
    plaintext_codec: ScaledCodec<T, M>,
}

impl<T, M> NtruParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates NTRU parameters for `Z_q[X] / (X^N + 1)`.
    ///
    /// `cipher_modulus.explicit_value() == None` selects the native wrapping
    /// modulus `2^T::BITS`, as required by the Fourier backend.
    ///
    /// # Panics
    ///
    /// Panics if the polynomial length, plaintext modulus, ciphertext modulus,
    /// fixed secret weight, probabilities or Gaussian parameters are invalid, including failure of
    /// [`ScaledCodec::new`]'s fixed-scale recovery bound, or if the secret-key
    /// sampler's maximum magnitude is not strictly less than an explicit
    /// ciphertext modulus.
    #[must_use]
    pub fn new(
        poly_length: usize,
        plain_modulus: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            poly_length,
            plain_modulus,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid NTRU parameters")
    }

    /// Checks ring length, fixed-scale encoding, secret support/weight and noise.
    /// Noise standard deviation is in coefficient units at the ciphertext modulus.
    /// Invertibility of a sampled secret and transform availability are checked
    /// by key/table construction, not by this parameter type.
    pub fn try_new(
        poly_length: usize,
        plain_modulus: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, NtruParameterError> {
        let poly_length = PolyLength::try_new(poly_length)
            .map_err(|_| NtruParameterError::InvalidPolynomialLength)?;

        let plaintext_codec = ScaledCodec::try_new(plain_modulus, cipher_modulus)?;
        let inner = NtruParametersInner::try_new(
            poly_length,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )?;
        Self::try_from_parts(Arc::new(inner), plaintext_codec)
    }

    /// Binds shared NTRU sampling state to ordinary message encoding.
    /// No sampler tables are copied or rebuilt. Ring length, secret support/weight,
    /// noise and fixed-scale recovery were checked by the supplied parts.
    ///
    /// # Errors
    /// Returns an error if the codec uses another ciphertext modulus.
    pub fn try_from_parts(
        inner: Arc<NtruParametersInner<T, M>>,
        plaintext_codec: ScaledCodec<T, M>,
    ) -> Result<Self, NtruParameterError> {
        if inner.cipher_modulus() != plaintext_codec.ciphertext_modulus() {
            return Err(NtruParameterError::CodecModulusMismatch);
        }
        Ok(Self {
            inner,
            plaintext_codec,
        })
    }

    /// Binds a Scaled message codec to an existing gadget's ring and samplers.
    /// Shares the immutable sampling state without copying the gadget basis.
    /// Returns an error if the codec uses a different ciphertext modulus.
    pub fn try_from_nlev(
        gadget: &super::NlevParameters<T, M>,
        plaintext_codec: ScaledCodec<T, M>,
    ) -> Result<Self, NtruParameterError> {
        Self::try_from_parts(Arc::clone(&gadget.inner), plaintext_codec)
    }

    /// Returns the ring and sampling state shared with gadget parameters.
    #[must_use]
    #[inline]
    pub fn inner(&self) -> &NtruParametersInner<T, M> {
        &self.inner
    }

    /// Returns the polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.inner.poly_length()
    }

    /// Returns the ciphertext modulus context.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.inner.cipher_modulus()
    }

    /// Returns the representable ciphertext modulus, if one exists.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.inner.cipher_modulus_value()
    }

    /// Returns the plaintext modulus `t`.
    #[must_use]
    #[inline]
    pub fn plain_modulus(&self) -> T {
        self.plaintext_codec.plaintext_modulus()
    }

    /// Returns the plaintext codec implementing the `Delta` embedding.
    #[must_use]
    #[inline]
    pub fn plaintext_codec(&self) -> &ScaledCodec<T, M> {
        &self.plaintext_codec
    }

    /// Returns the coefficient distribution of `f`.
    #[must_use]
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.inner.secret_key_distr()
    }

    /// Returns the error distribution used for fresh ciphertexts.
    #[must_use]
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.inner.noise_distribution()
    }
}
