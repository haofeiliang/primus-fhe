//! Parameters shared by the NTT and Fourier NTRU backends.

use primus_decompose::{ApproxSignedBasisError, primitive::ApproxSignedBasis};
use primus_distr::{DiscreteGaussian, SignedDiscreteGaussian};
use primus_fhe_core::plaintext::PlaintextCodec;
use primus_integer::FheUint;
use primus_lattice::{MAX_POLY_LENGTH, MIN_POLY_LENGTH};
use primus_reduce::RingContext;

use crate::{SecretCoefficient, SecretKeyDistr};

/// Maximum number of coefficient keys sampled while searching for an
/// invertible transform-domain NTRU key.
pub(crate) const KEY_GENERATION_ATTEMPTS: usize = 1 << 10;

/// Parameters for scalar secret-key NTRU encryption.
///
/// The ciphertext modulus may be an explicit NTT-friendly field or the native
/// wrapping modulus used by the Fourier backend.  In either case plaintexts
/// use the codec scale `Delta = round(q / t)`.
#[derive(Clone)]
pub struct NtruParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    poly_length: usize,
    cipher_modulus: M,
    secret_key_distr: SecretKeyDistr,
    secret_key_distribution: Option<SignedDiscreteGaussian<SecretCoefficient<T>>>,
    noise_distribution: DiscreteGaussian<T>,
    plaintext_codec: PlaintextCodec<T>,
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
    /// or Gaussian parameters are invalid.
    pub fn new(
        poly_length: usize,
        plain_modulus: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        assert!(
            (MIN_POLY_LENGTH..=MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two(),
            "NTRU polynomial length must be a supported power of two"
        );

        let plaintext_codec = PlaintextCodec::new(plain_modulus, cipher_modulus.explicit_value());
        let modulus_minus_one = cipher_modulus.minus_one();
        let noise_distribution = DiscreteGaussian::new(noise_standard_deviation, modulus_minus_one)
            .expect("invalid Gaussian NTRU noise distribution");
        let secret_key_distribution = match secret_key_distr {
            SecretKeyDistr::Gaussian(standard_deviation) => Some(
                SignedDiscreteGaussian::new(standard_deviation)
                    .expect("invalid Gaussian NTRU secret-key distribution"),
            ),
            SecretKeyDistr::Binary | SecretKeyDistr::Ternary => None,
        };

        Self {
            poly_length,
            cipher_modulus,
            secret_key_distr,
            secret_key_distribution,
            noise_distribution,
            plaintext_codec,
        }
    }

    /// Returns the polynomial length `N`.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the ciphertext modulus context.
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the representable ciphertext modulus, if one exists.
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.cipher_modulus.explicit_value()
    }

    /// Returns the plaintext modulus `t`.
    #[inline]
    pub fn plain_modulus(&self) -> T {
        self.plaintext_codec.t()
    }

    /// Returns the plaintext codec implementing the `Delta` embedding.
    #[inline]
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
    }

    /// Returns the coefficient distribution of `f`.
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_distr
    }

    /// Returns the signed Gaussian key distribution, when configured.
    #[inline]
    pub(crate) fn secret_key_distribution(
        &self,
    ) -> Option<&SignedDiscreteGaussian<SecretCoefficient<T>>> {
        self.secret_key_distribution.as_ref()
    }

    /// Returns the error distribution used for fresh ciphertexts.
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }
}

/// Parameters for NLev and NGSW ciphertexts in one NTRU modulus domain.
///
/// This type binds the underlying NTRU encryption parameters to the
/// approximate signed decomposition basis used by a gadget operation. Create
/// separate values when key switching, bootstrapping, or another operation
/// uses different decomposition parameters.
#[derive(Clone)]
pub struct NlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    ntru: NtruParameters<T, M>,
    basis: ApproxSignedBasis<T>,
    nlev_len: usize,
}

impl<T, M> NlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates NLev/NGSW parameters from matching NTRU parameters.
    ///
    /// `log_basis` is the base-2 logarithm of the gadget basis.
    /// `reverse_length`, when present, selects the retained decomposition
    /// level count.
    ///
    /// # Panics
    ///
    /// Panics if the decomposition parameters are invalid for the NTRU
    /// ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn with_ntru_params(
        ntru: &NtruParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Self {
        Self::try_with_ntru_params(ntru, log_basis, reverse_length)
            .unwrap_or_else(|error| panic!("failed to construct NLev parameters: {error}"))
    }

    /// Tries to create NLev/NGSW parameters and their decomposition basis in
    /// the modulus domain of `ntru`.
    pub fn try_with_ntru_params(
        ntru: &NtruParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Result<Self, ApproxSignedBasisError> {
        let basis =
            ApproxSignedBasis::try_new(ntru.cipher_modulus_value(), log_basis, reverse_length)?;
        let nlev_len = basis
            .decompose_length()
            .checked_mul(ntru.poly_length())
            .expect("NLev ciphertext length overflow");
        Ok(Self {
            ntru: ntru.clone(),
            basis,
            nlev_len,
        })
    }

    /// Returns the underlying NTRU encryption parameters.
    #[must_use]
    #[inline]
    pub fn ntru(&self) -> &NtruParameters<T, M> {
        &self.ntru
    }

    /// Returns the approximate signed decomposition basis.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the polynomial length `N`.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.ntru.poly_length()
    }

    /// Returns the number of retained decomposition levels.
    #[must_use]
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.basis.decompose_length()
    }

    /// Returns the number of coefficient or NTT values in an NLev/NGSW
    /// ciphertext.
    #[must_use]
    #[inline]
    pub fn nlev_len(&self) -> usize {
        self.nlev_len
    }

    /// Returns the number of complex values in a Fourier NLev/NGSW
    /// ciphertext.
    #[must_use]
    #[inline]
    pub fn fourier_nlev_len(&self) -> usize {
        self.nlev_len >> 1
    }
}
