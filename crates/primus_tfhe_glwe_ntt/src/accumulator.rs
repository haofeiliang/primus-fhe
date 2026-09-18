//! Client-side coefficient-ring encryption and decryption under the accumulator secret.

use crate::{ClientKey, TfheContext, TfheKeyError};
use primus_data::{Data, DataMut};
use primus_glwe::{GlweCiphertext, NttGlweSecretKey};
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use zeroize::Zeroizing;

/// Prepared private-key client for the accumulator GLWE domain.
///
/// Owns one transformed accumulator secret and an N-coefficient scratch buffer,
/// both erased on drop. Borrows the context fixing its table, modulus and codec.
/// Ciphertexts use coefficient representation and the accumulator secret, which
/// differs from the external LWE domain used by [`crate::Encryptor`].
/// Construction prepares all buffers; `encrypt_to` and `decrypt_to` do not allocate.
pub struct AccumulatorClient<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    secret: NttGlweSecretKey<T>,
    scratch: Zeroizing<Vec<T>>,
}

impl<'a, T, Table> AccumulatorClient<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Validates the client key and prepares its accumulator representation once.
    ///
    /// # Correctness
    /// Imported accumulator coefficients must have unsigned magnitude below q;
    /// see [`NttGlweSecretKey::from_coeff_secret_key`]. Layout checks do not establish this bound.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        client_key: &ClientKey<T>,
    ) -> Result<Self, TfheKeyError> {
        client_key.check_compatible(context.parameters())?;
        let parameters = context.parameters().accumulator_glwe();
        let secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        Ok(Self {
            context,
            secret,
            scratch: Zeroizing::new(vec![T::ZERO; parameters.poly_length()]),
        })
    }

    /// Allocates a zeroed coefficient ciphertext with the bound accumulator layout.
    #[must_use]
    pub fn allocate_ciphertext(&self) -> GlweCiphertext<Vec<T>> {
        let parameters = self.context.parameters().accumulator_glwe();
        GlweCiphertext::zero(parameters.glwe_len())
    }

    /// Encrypts an unsigned polynomial into a newly allocated coefficient ciphertext.
    /// Inherits [`Self::encrypt_to`]'s message and panic contracts.
    #[must_use]
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        message: &[T],
        rng: &mut R,
    ) -> GlweCiphertext<Vec<T>> {
        let mut output = self.allocate_ciphertext();
        self.encrypt_to(message, &mut output, rng);
        output
    }

    /// Encrypts exactly N unsigned coefficients in `[0, t)` under the accumulator secret.
    /// Uses the accumulator plaintext codec and overwrites the entire coefficient output.
    ///
    /// # Panics
    /// Panics before sampling if message or output length is wrong. A plaintext-range
    /// or RNG/transform panic may consume randomness and partially write output
    /// or scratch. See [`NttGlweSecretKey::encrypt_coeff_to`].
    pub fn encrypt_to<R, S>(&mut self, message: &[T], output: &mut GlweCiphertext<S>, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
        S: DataMut<Elem = T>,
    {
        let parameters = self.context.parameters().accumulator_glwe();
        self.secret.encrypt_coeff_to(
            &Polynomial::new(message),
            output,
            parameters,
            self.context.table(),
            rng,
            &mut self.scratch,
        );
    }

    /// Allocates and decodes all N coefficients. Inherits [`Self::decrypt_to`]'s contracts.
    #[must_use]
    pub fn decrypt<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>) -> Vec<T> {
        let mut output = vec![T::ZERO; self.context.parameters().accumulator_glwe().poly_length()];
        self.decrypt_to(input, &mut output);
        output
    }

    /// Decodes to exactly N unsigned coefficients in `[0, t)`, overwriting `output`.
    ///
    /// # Correctness
    /// Input must use this accumulator secret, modulus and plaintext codec, with
    /// canonical residues and noise within the decoding margin. Ciphertexts carry no
    /// key/encoding metadata.
    ///
    /// # Panics
    /// Panics before output writes if ciphertext or plaintext length is wrong.
    pub fn decrypt_to<S: Data<Elem = T>>(&mut self, input: &GlweCiphertext<S>, output: &mut [T]) {
        let parameters = self.context.parameters().accumulator_glwe();
        self.secret.decrypt_coeff_to(
            input,
            &mut Polynomial::new(output),
            parameters,
            self.context.table(),
            &mut self.scratch,
        );
    }
}
