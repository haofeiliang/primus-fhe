//! Fourier-domain bootstrapping-key storage and generation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGadgetEncryptContext, FourierGlweSecretKey, GlevParameters};
use primus_lattice::{
    GadgetSize,
    ggsw::{FourierGgsw, FourierGgswIter},
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::NativeModulus;
use primus_reduce::{PrepareModulusSwitch, RingContext};
use primus_tfhe::rotation::RotationQuantizer;
use primus_tfhe_glwe::SecretKeyDistr;
use zeroize::Zeroizing;

/// A Fourier bootstrapping key containing one control per binary input coefficient
/// or an adjacent `(positive, negative)` pair per ternary coefficient. Each pair
/// independently encrypts `[s=1]` and `[s=-1]` under the same accumulator key.
#[derive(Clone)]
pub struct FourierGlweBootstrappingKey<T: TorusFftValue, LM: PrepareModulusSwitch<ValueT = T>> {
    data: Vec<Complex64>,
    input_dimension: usize,
    input_distribution: SecretKeyDistr,
    input_modulus: LM,
    input_quantizer: RotationQuantizer<LM::Prepared>,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: TorusFftValue, LM: PrepareModulusSwitch<ValueT = T>> FourierGlweBootstrappingKey<T, LM> {
    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the input secret distribution, which fixes the control layout.
    #[must_use]
    #[inline]
    pub fn input_distribution(&self) -> SecretKeyDistr {
        self.input_distribution
    }

    /// Returns the input LWE modulus with its arithmetic type preserved.
    #[inline]
    pub fn input_modulus(&self) -> LM {
        self.input_modulus
    }

    #[inline]
    pub(crate) fn input_quantizer(&self) -> RotationQuantizer<LM::Prepared> {
        self.input_quantizer
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

    /// Generates a Fourier bootstrapping key encrypting binary coefficients or ternary
    /// selector pairs under `output_secret_key`.
    ///
    /// Inherits [`FourierGlweSecretKey::encrypt_ggsw_constant_batch_to`]'s FFT
    /// representation and workspace requirements.
    ///
    /// # Panics
    ///
    /// Panics if input key/parameter distributions are unsupported or unequal,
    /// secret coefficients are outside their declared support, or their
    /// dimensions differ, or if the output key, FFT or workspace layout is
    /// incompatible. Key-length overflow or a rotation domain `2N` not representable
    /// by the input coefficient type also panics. Checks precede sampling.
    pub fn generate_fourier<Table, R>(
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
        let input_distribution = input_secret_key.distr();
        assert!(
            input_distribution.is_binary() || input_distribution.is_ternary(),
            "bootstrapping requires a binary or ternary input LWE secret"
        );
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert_eq!(input_distribution, input_parameters.secret_key_distr());
        let input_dimension = input_secret_key.dimension();
        let control_count = input_dimension
            .checked_mul(if input_distribution.is_binary() { 1 } else { 2 })
            .expect("bootstrapping control count overflow");
        // Only ternary key generation needs a temporary selector array. It is
        // erased on drop; the evaluation key retains only encrypted selectors.
        let mut selectors = Zeroizing::new(Vec::new());
        let plaintexts = if input_distribution.is_binary() {
            assert!(
                input_secret_key.as_ref().iter().all(|&x| x <= T::ONE),
                "binary LWE secret coefficient is outside {{0, 1}}"
            );
            input_secret_key.as_ref()
        } else {
            let minus_one = input_parameters.cipher_modulus().minus_one();
            selectors.resize(control_count, T::ZERO);
            for (&coefficient, pair) in input_secret_key
                .as_ref()
                .iter()
                .zip(selectors.as_chunks_mut::<2>().0.iter_mut())
            {
                assert!(
                    coefficient <= T::ONE || coefficient == minus_one,
                    "ternary LWE secret coefficient is outside {{0, 1, q-1}}"
                );
                pair[0] = if coefficient == T::ONE {
                    T::ONE
                } else {
                    T::ZERO
                };
                pair[1] = if coefficient == minus_one {
                    T::ONE
                } else {
                    T::ZERO
                };
            }
            selectors.as_slice()
        };
        let input_quantizer = RotationQuantizer::new(
            input_parameters.cipher_modulus(),
            parameters.size().glwe_size().poly_length() * 2,
            1,
        );
        let ggsw_len = parameters.fourier_ggsw_len();
        let total_len = control_count
            .checked_mul(ggsw_len)
            .expect("Fourier bootstrapping-key length overflow");
        let mut data = vec![Complex64::default(); total_len];
        output_secret_key
            .encrypt_ggsw_constant_batch_to(plaintexts, &mut data, parameters, fft, rng, context);

        Self {
            data,
            input_dimension,
            input_distribution,
            input_modulus: input_parameters.cipher_modulus(),
            input_quantizer,
            size: parameters.size(),
            basis: parameters.basis().clone(),
        }
    }

    /// Borrows one control per input coordinate, or returns `None` for a ternary key.
    #[must_use]
    pub fn iter_binary_controls(&self) -> Option<FourierGgswIter<'_>> {
        self.input_distribution
            .is_binary()
            .then(|| FourierGgswIter::new(&self.data, self.size.fourier_ggsw_len()))
    }

    /// Borrows `(positive, negative)` controls per input coordinate, or returns
    /// `None` for a binary key. The two encryptions in each pair are independent.
    #[must_use]
    #[expect(
        clippy::type_complexity,
        reason = "expose the positive/negative pair without another public type"
    )]
    pub fn iter_ternary_controls(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = (FourierGgsw<&[Complex64]>, FourierGgsw<&[Complex64]>)>>
    {
        self.input_distribution.is_ternary().then(|| {
            let len = self.size.fourier_ggsw_len();
            self.data.chunks_exact(2 * len).map(move |pair| {
                let (positive, negative) = pair.split_at(len);
                (FourierGgsw::new(positive), FourierGgsw::new(negative))
            })
        })
    }
}
