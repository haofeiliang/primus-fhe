use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

use crate::{LweKeySwitchingParameters, LweParameters, LweSecretKey};

/// An LWE key-switching key from one secret-key vector to another.
///
/// Storage is ordered by input secret coefficient, then decomposition level;
/// every entry is an LWE encryption under the output secret key.
#[derive(Clone)]
pub struct LweKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: usize,
    output_dimension: usize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> LweKeySwitchingKey<T> {
    /// Generates a key switching from `input_secret_key` to
    /// `output_secret_key`.
    pub fn generate<R, M>(
        input_secret_key: &[T],
        output_secret_key: &LweSecretKey<T>,
        output_parameters: &LweParameters<T, M>,
        parameters: &LweKeySwitchingParameters<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        assert_eq!(input_secret_key.len(), parameters.input_dimension());
        assert_eq!(output_secret_key.dimension(), parameters.output_dimension());
        assert_eq!(output_parameters.dimension(), parameters.output_dimension());
        assert_eq!(
            parameters.basis().modulus(),
            output_parameters.cipher_modulus().value(),
            "LWE key switching currently requires matching input and output ciphertext moduli"
        );

        let output_lwe_len = parameters
            .output_dimension()
            .checked_add(1)
            .expect("LWE key-switching output length overflow");
        let entry_count = parameters
            .input_dimension()
            .checked_mul(parameters.decompose_length())
            .expect("LWE key-switching entry count overflow");
        let mut data = Vec::with_capacity(
            entry_count
                .checked_mul(output_lwe_len)
                .expect("LWE key-switching key length overflow"),
        );

        let modulus = output_parameters.cipher_modulus();
        let uniform = output_parameters.cipher_modulus_uniform_distr();
        let gaussian = output_parameters.noise_distribution();
        for &secret in input_secret_key {
            for scalar in parameters.basis().scalar_iter() {
                let mut ciphertext = Lwe::generate_random_zero_sample(
                    output_secret_key.as_ref(),
                    modulus,
                    uniform,
                    gaussian,
                    rng,
                );
                let message = modulus.reduce_mul(secret, scalar);
                modulus.reduce_add_assign(ciphertext.b_mut(), message);
                data.extend_from_slice(&ciphertext.0);
            }
        }

        Self {
            data,
            input_dimension: parameters.input_dimension(),
            output_dimension: parameters.output_dimension(),
            basis: parameters.basis().clone(),
        }
    }

    /// Returns the input LWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the output LWE dimension.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output_dimension
    }

    /// Returns the key-switch decomposition basis.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Key-switches `input` into `output`.
    pub fn key_switch_to<M, A, B>(&self, input: &Lwe<A>, output: &mut Lwe<B>, modulus: M)
    where
        M: RingContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        assert_eq!(input.dimension(), self.input_dimension);
        assert_eq!(output.dimension(), self.output_dimension);
        assert_eq!(self.basis.modulus(), modulus.value());

        output.set_zero();
        *output.b_mut() = modulus.reduce_neg(input.b());

        let output_lwe_len = self.output_dimension + 1;
        let mut entries = self.data.chunks_exact(output_lwe_len);
        for &coefficient in input.a() {
            let (adjusted, mut carry) = self.basis.init_value_carry(coefficient);
            for decomposer in self.basis.decompose_iter() {
                let (digit, next_carry) = decomposer.decompose(adjusted, carry);
                carry = next_carry;
                let key_entry = Lwe(entries.next().expect("invalid key-switching key length"));
                output.add_mul_scalar_assign(&key_entry, digit, modulus);
            }
        }
        debug_assert!(entries.next().is_none());

        output.neg_assign(modulus);
    }

    /// Key-switches `input` into a newly allocated ciphertext.
    pub fn key_switch<M, A>(&self, input: &Lwe<A>, modulus: M) -> Lwe<Vec<T>>
    where
        M: RingContext<T>,
        A: RawData<Elem = T> + Data,
    {
        let mut output = Lwe::zero(self.output_dimension);
        self.key_switch_to(input, &mut output, modulus);
        output
    }
}
