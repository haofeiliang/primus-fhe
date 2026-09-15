//! Fourier-domain bootstrapping-key storage and generation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters};
use primus_lattice::{GadgetSize, ggsw::FourierGgswIter};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_reduce::RingContext;

/// A Fourier bootstrapping key containing one GGSW encryption per input LWE
/// secret coefficient.
#[derive(Clone)]
pub struct FourierGlweBootstrappingKey<T: TorusFftValue> {
    data: Vec<Complex64>,
    input_dimension: usize,
    input_modulus: Option<T>,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue> FourierGlweBootstrappingKey<T> {
    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the explicit input LWE modulus, or `None` for a native torus.
    #[inline]
    pub fn input_modulus(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the GGSW/GLWE layout bound to this key.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns `None` because the Fourier accumulator uses the native torus.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        None
    }

    /// Returns the decomposition basis bound to this key.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the Fourier-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[Complex64] {
        &self.data
    }

    /// Generates a Fourier bootstrapping key encrypting every binary input
    /// LWE secret coefficient under `output_secret_key`.
    ///
    /// Inherits [`FourierGlweSecretKey::encrypt_ggsw_constant_batch_to`]'s FFT
    /// representation and workspace requirements.
    ///
    /// # Panics
    ///
    /// Panics if input key/parameter distributions are not binary or their
    /// dimensions differ, or if the output key, FFT or workspace layout is
    /// incompatible. A key-length overflow also panics. Checks precede sampling.
    pub fn generate_fourier<LM, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        input_parameters: &LweParameters<T, LM>,
        output_secret_key: &FourierGlweSecretKey,
        parameters: &GlevParameters<T, NativeModulus<T>>,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
        context: &mut FourierGadgetEncryptContext<T>,
    ) -> Self
    where
        LM: RingContext<T>,
        Table: FftTable,
        R: rand::Rng + rand::CryptoRng,
    {
        assert!(input_secret_key.distr().is_binary());
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert!(input_parameters.secret_key_distr().is_binary());

        let input_dimension = input_secret_key.dimension();
        let ggsw_len = parameters.fourier_ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("Fourier bootstrapping-key length overflow");
        let mut data = vec![Complex64::default(); total_len];
        output_secret_key.encrypt_ggsw_constant_batch_to(
            input_secret_key.as_ref(),
            &mut data,
            parameters,
            fft,
            rng,
            context,
        );

        Self {
            data,
            input_dimension,
            input_modulus: input_parameters.cipher_modulus().explicit_value(),
            size: parameters.size(),
            basis: parameters.basis().clone(),
        }
    }

    /// Iterates over the Fourier GGSW encryptions.
    #[inline]
    pub fn iter_fourier_ggsw(&self) -> FourierGgswIter<'_> {
        FourierGgswIter::new(&self.data, self.size.fourier_ggsw_len())
    }
}
