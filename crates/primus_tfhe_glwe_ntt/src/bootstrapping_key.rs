//! NTT-domain bootstrapping-key storage and generation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlevParameters, NttGadgetEncryptContext, NttGlweSecretKey};
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, ggsw::NttGgswIter};
use primus_lwe::{LweParameters, LweSecretKey};
use primus_ntt::NttTable;
use primus_reduce::{FieldContext, PrepareModulusSwitch, RingContext};
use primus_tfhe::backend_support::RotationQuantizer;

/// An NTT bootstrapping key containing one GGSW encryption per input LWE
/// secret coefficient.
#[derive(Clone)]
pub struct NttGlweBootstrappingKey<T: FheUint, LM: PrepareModulusSwitch<ValueT = T>> {
    data: Vec<T>,
    input_dimension: usize,
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

    /// Generates an NTT bootstrapping key encrypting every binary input LWE
    /// secret coefficient under `output_secret_key`.
    ///
    /// # Correctness
    ///
    /// The output secret key must use the supplied table's NTT representation.
    ///
    /// # Panics
    ///
    /// Panics on non-binary input key distributions, incompatible key/parameter
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
        assert!(input_secret_key.distr().is_binary());
        assert_eq!(input_secret_key.dimension(), input_parameters.dimension());
        assert!(input_parameters.secret_key_distr().is_binary());
        let input_quantizer = RotationQuantizer::new(
            input_parameters.cipher_modulus(),
            parameters.size().glwe_size().poly_length() * 2,
            1,
        );
        let input_dimension = input_secret_key.dimension();
        let ggsw_len = parameters.ggsw_len();
        let total_len = input_dimension
            .checked_mul(ggsw_len)
            .expect("NTT bootstrapping-key length overflow");
        let mut data = vec![T::ZERO; total_len];
        output_secret_key.encrypt_ggsw_constant_batch_to(
            input_secret_key.as_ref(),
            &mut data,
            parameters,
            ntt,
            rng,
            context,
        );

        Self {
            data,
            input_dimension,
            input_modulus: input_parameters.cipher_modulus(),
            input_quantizer,
            size: parameters.size(),
            cipher_modulus: parameters.cipher_modulus().value(),
            basis: parameters.basis().clone(),
        }
    }

    /// Iterates over the NTT GGSW encryptions.
    #[inline]
    pub fn iter_ntt_ggsw(&self) -> NttGgswIter<'_, T> {
        NttGgswIter::new(&self.data, self.size.ggsw_len())
    }
}
