//! NTT-domain bootstrapping-key storage and generation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlevParameters, NttGadgetEncryptContext, NttGlweSecretKey};
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize,
    ggsw::{NttGgsw, NttGgswIter},
};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_ntt::NttTable;
use primus_reduce::{FieldContext, PrepareModulusSwitch, RingContext};
use primus_tfhe::rotation::RotationQuantizer;
use primus_tfhe_glwe::SecretKeyDistr;
use zeroize::Zeroizing;

/// An NTT bootstrapping key containing one control per binary input coefficient
/// or an adjacent `(positive, negative)` pair per ternary coefficient. Each pair
/// independently encrypts `[s=1]` and `[s=-1]` under the same accumulator key.
#[derive(Clone)]
pub struct NttGlweBootstrappingKey<T: FheUint, LM: PrepareModulusSwitch<ValueT = T>> {
    data: Vec<T>,
    input_dimension: usize,
    input_distribution: SecretKeyDistr,
    input_modulus: LM,
    input_quantizer: RotationQuantizer<LM::Prepared>,
    size: GadgetSize,
    cipher_modulus: T,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint, LM: PrepareModulusSwitch<ValueT = T>> NttGlweBootstrappingKey<T, LM> {
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

    /// Returns the explicit NTT ciphertext modulus.
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        Some(self.cipher_modulus)
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the NTT-domain values stored by this key.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Generates an NTT bootstrapping key encrypting the binary coefficients or ternary
    /// selector pairs of the input LWE secret under `output_secret_key`.
    ///
    /// # Correctness
    ///
    /// The output secret key must use the supplied table's NTT representation.
    ///
    /// # Panics
    ///
    /// Panics on unsupported distributions or invalid secret coefficients, incompatible key/parameter
    /// layouts, NTT length/modulus or gadget workspace, key storage overflow,
    /// or a rotation domain `2N` not representable by the input coefficient type.
    pub fn generate_ntt<M, Table, R>(
        input_secret_key: &LweSecretKey<T>,
        input_parameters: &LweParameters<T, LM>,
        output_secret_key: &NttGlweSecretKey<T>,
        parameters: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        LM: RingContext<T>,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
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
        let ggsw_len = parameters.ggsw_len();
        let total_len = control_count
            .checked_mul(ggsw_len)
            .expect("NTT bootstrapping-key length overflow");
        let mut data = vec![T::ZERO; total_len];
        output_secret_key
            .encrypt_ggsw_constant_batch_to(plaintexts, &mut data, parameters, ntt, rng, context);

        Self {
            data,
            input_dimension,
            input_distribution,
            input_modulus: input_parameters.cipher_modulus(),
            input_quantizer,
            size: parameters.size(),
            cipher_modulus: parameters.cipher_modulus().value(),
            basis: parameters.basis().clone(),
        }
    }

    /// Borrows one control per input coordinate, or returns `None` for a ternary key.
    #[must_use]
    pub fn iter_binary_controls(&self) -> Option<NttGgswIter<'_, T>> {
        self.input_distribution
            .is_binary()
            .then(|| NttGgswIter::new(&self.data, self.size.ggsw_len()))
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
    ) -> Option<impl ExactSizeIterator<Item = (NttGgsw<&[T]>, NttGgsw<&[T]>)>> {
        self.input_distribution.is_ternary().then(|| {
            let len = self.size.ggsw_len();
            self.data.chunks_exact(2 * len).map(move |pair| {
                let (positive, negative) = pair.split_at(len);
                (NttGgsw::new(positive), NttGgsw::new(negative))
            })
        })
    }
}
